"""ServerDedupe - duplicate file finder web app (Flask + SQLite)."""

VERSION = "1.7.5"   # shown in the page header
import csv
import hashlib
import io
import itertools
import json
import os
import re
import mimetypes
import threading
import time
from urllib.parse import quote

from flask import Flask, Response, abort, g, jsonify, request, send_file

import actions
import db
import media
import schedule
import emptyfolders
import ignores
import scanner

DATA_ROOT = os.path.realpath(os.environ.get("DATA_ROOT", "/data"))
TRASH_NAME = os.environ.get("TRASH_NAME", ".dedupe_trash")
SMB_HOST = os.environ.get("SMB_HOST", "")        # name shown in Windows network paths; default = host in your browser address
START_SUBDIR = os.environ.get("START_SUBDIR", "")   # folder picker opens here (relative to DATA_ROOT); empty = the root
START_SUBDIR = os.environ.get("START_SUBDIR", "homes")   # folder picker opens here (relative to DATA_ROOT)
_start = os.path.join(DATA_ROOT, START_SUBDIR)
START_PATH = _start if os.path.isdir(_start) else DATA_ROOT
ALLOW_PERM = os.environ.get("ALLOW_PERMANENT_DELETE", "0") == "1"
WORKERS = int(os.environ.get("HASH_WORKERS", "2"))
APP_USER = os.environ.get("APP_USER", "")
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
THUMB_DIR = os.path.join(db.DATA_DIR, "thumbs")
DEFAULT_EXCLUDES = "@eaDir,#recycle,#snapshot,@tmp,@appdata,.git,node_modules"

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
db.init()
os.makedirs(THUMB_DIR, exist_ok=True)

_lock = threading.Lock()
_current = None


_fold = {"running": False, "action": "", "path": "", "phase": "", "files": 0, "bytes": 0, "total_files": 0, "total_bytes": 0,
         "ok": None, "error": "", "warn": "", "state": "", "target": "", "id": 0}


def busy():
    """True while a scan thread is still working (waits briefly for one that is just finishing), or a folder job is running."""
    if _fold["running"]:
        return True
    if _current is not None and _current.is_alive():
        _current.join(2)
        return _current.is_alive()
    return False


# ------------------------------------------------------------ plumbing
def get_db():
    if "db" not in g:
        g.db = db.connect()
    return g.db


@app.teardown_appcontext
def _close(_):
    c = g.pop("db", None)
    if c is not None:
        c.close()


@app.before_request
def _auth():
    if not APP_PASSWORD or request.path == "/healthz":
        return None
    a = request.authorization
    if a and a.username == APP_USER and a.password == APP_PASSWORD:
        return None
    return Response("Login required", 401, {"WWW-Authenticate": 'Basic realm="ServerDedupe"'})


def err(msg, code=400):
    return jsonify(error=msg), code


@app.errorhandler(Exception)
def unexpected(e):
    """Show a readable message (and put the traceback in the container log) instead of a bare 'INTERNAL SERVER ERROR'."""
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return e
    import traceback
    traceback.print_exc()
    return jsonify(error=f"Server error in {request.path}: {type(e).__name__}: {e}"), 500


def under_root(p):
    rp = os.path.realpath(p)
    return rp == DATA_ROOT or rp.startswith(DATA_ROOT + os.sep)


def scan_row(sid):
    r = get_db().execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
    if not r:
        abort(404)
    return r


SCAN_SQL = "SELECT s.*, j.name AS job_name FROM scans s LEFT JOIN jobs j ON j.id=s.job_id"


def scan_json(r):
    d = dict(r)
    d["params"] = json.loads(d["params"] or "{}")
    d["stats"] = json.loads(d["stats"] or "{}")
    return d


# ------------------------------------------------------------ pages / config
@app.get("/")
def index():
    return app.send_static_file("index.html")


@app.get("/healthz")
def healthz():
    return "ok"


@app.get("/api/config")
def config():
    return jsonify(version=VERSION, methods=media.METHODS, ffmpeg=media.have_ffmpeg(), sevenzip=bool(actions.sevenzip_exe()), heic=media.HEIC,
                   tz=schedule.TZ_NAME, server_now=time.time(), data_root=DATA_ROOT, trash_name=TRASH_NAME, allow_permanent_delete=ALLOW_PERM,
                   default_excludes=DEFAULT_EXCLUDES, workers=WORKERS, start_path=START_PATH)


@app.get("/api/browse")
def browse():
    path = request.args.get("path") or START_PATH
    if not under_root(path) or not os.path.isdir(path):
        return err("Folder not available", 404)
    path = os.path.normpath(path)
    dirs = []
    try:
        with os.scandir(path) as it:
            for e in it:
                if e.name[0] in "@#" or e.name == TRASH_NAME:
                    continue
                try:
                    if e.is_dir(follow_symlinks=False):
                        dirs.append(e.name)
                except OSError:
                    pass
    except OSError as ex:
        return err(str(ex), 403)
    parent = os.path.dirname(path) if os.path.realpath(path) != DATA_ROOT else None
    return jsonify(path=path, parent=parent, dirs=sorted(dirs, key=str.lower))


# ------------------------------------------------------------ scans
def build_params(b):
    """Validate scan settings from the browser. Returns (params, None) or (None, error message)."""
    roots = []
    for r in b.get("roots", []):
        p = os.path.normpath(r.get("path", ""))
        if not os.path.isdir(p) or not under_root(p):
            return None, f"Folder not available: {p}"
        roots.append({"path": p, "protected": bool(r.get("protected"))})
    if not roots:
        return None, "Add at least one folder"
    if all(r["protected"] for r in roots):
        return None, "At least one folder must be a normal (non-protected) scan folder"
    family = b.get("family", "regular")
    mode = b.get("mode", "content")
    if family not in media.METHODS or mode not in media.METHODS[family]:
        return None, "Unknown match mode"
    if ((family in ("video", "audio") and mode != "content") or family == "health") and not media.have_ffmpeg():
        return None, "ffmpeg is not installed in the container, so video/audio matching is unavailable"
    return {"roots": roots, "mode": mode, "family": family,
            "dur_tol": max(0.0, min(60.0, float(b.get("dur_tol", 2) or 0))),
            "vthreshold": max(0.0, min(32.0, float(b.get("vthreshold", 10)))),
            "ber": max(5.0, min(45.0, float(b.get("ber", 30)))),
            "include_album": bool(b.get("include_album")),
            "flips": bool(b.get("flips")) and (mode in ("image", "video_similar")),
            "blank_secs": max(5.0, min(600.0, float(b.get("blank_secs", 45) or 45))),
            "deep": bool(b.get("deep")) and family == "health",
            "top_n": max(10, min(5000, int(b.get("top_n", 500) or 500))),
            "health_mode": "full" if b.get("health_mode") == "full" else "quick",
            "junk": bool(b.get("junk", True)), "auto_remove": bool(b.get("auto_remove")) and family == "folders",
            "min_kb": b.get("min_kb", 1), "max_mb": b.get("max_mb") or "",
            "include_ext": b.get("include_ext", ""), "exclude_ext": b.get("exclude_ext", ""),
            "exclude_dirs": b.get("exclude_dirs", DEFAULT_EXCLUDES + (",Drive" if family == "folders" else "")),
            "threshold": max(0, min(16, int(b.get("threshold", 4))))}, None


def launch_scan(params, job_id=None, source="manual", deadline=None):
    """Start a scan thread. Returns (scan_id, None) or (None, reason)."""
    global _current
    with _lock:
        if busy():
            return None, "A scan is already running"
        if _comp["running"]:
            return None, "A compression is running; wait for it to finish"
        conn = db.connect()
        try:
            cur = conn.execute("INSERT INTO scans(started,status,mode,params,phase,job_id,source) VALUES(?,?,?,?,?,?,?)",
                               (time.time(), "queued", params["mode"], json.dumps(params), "starting", job_id, source))
            conn.commit()
            sid = cur.lastrowid
        finally:
            conn.close()
        _current = scanner.Scanner(sid, params, TRASH_NAME, WORKERS, deadline=deadline)
        _current.start()
        return sid, None


@app.post("/api/scans")
def start_scan():
    params, e = build_params(request.get_json(force=True, silent=True) or {})
    if e:
        return err(e)
    sid, e = launch_scan(params)
    return err(e, 409) if e else jsonify(id=sid)


@app.get("/api/status")
def status():
    r = get_db().execute(SCAN_SQL + " WHERE s.status IN ('running','queued') ORDER BY s.id DESC LIMIT 1").fetchone()
    return jsonify(running=scan_json(r) if r else None, now=time.time())


@app.get("/api/scans")
def list_scans():
    rows = get_db().execute(SCAN_SQL + " ORDER BY s.id DESC LIMIT 100").fetchall()
    return jsonify(scans=[scan_json(r) for r in rows])


@app.get("/api/scans/<int:sid>")
def get_scan(sid):
    return jsonify(scan_json(scan_row(sid)))


@app.post("/api/scans/<int:sid>/cancel")
def cancel(sid):
    if _current is not None and _current.scan_id == sid and _current.is_alive():
        _current.cancel.set()
    return jsonify(ok=True)


@app.delete("/api/scans/<int:sid>")
def delete_scan(sid):
    if _current is not None and _current.scan_id == sid and _current.is_alive():
        return err("Cancel the scan first", 409)
    c = get_db()
    for t in ("files", "groups"):
        c.execute(f"DELETE FROM {t} WHERE scan_id=?", (sid,))
    c.execute("DELETE FROM scans WHERE id=?", (sid,))
    c.commit()
    return jsonify(ok=True)


# ------------------------------------------------------------ results
def summary(sid):
    c = get_db()
    g_, f_, w_ = c.execute("""
        WITH a AS (SELECT group_id, count(*) c, sum(size) s, max(size) m FROM files
                   WHERE scan_id=? AND group_id IS NOT NULL AND state='ok' GROUP BY group_id HAVING c>1)
        SELECT count(*), coalesce(sum(c),0), coalesce(sum(s-m),0) FROM a""", (sid,)).fetchone()
    sf, sb = c.execute("SELECT count(*), coalesce(sum(size),0) FROM files WHERE scan_id=? AND selected=1 AND state='ok'",
                       (sid,)).fetchone()
    ag = 0
    if sf:                                   # groups with every copy ticked can only exist when something is ticked
        ag = c.execute("""
            SELECT count(*) FROM (SELECT group_id FROM files WHERE scan_id=? AND group_id IS NOT NULL AND state='ok'
                                  GROUP BY group_id HAVING count(*)>1 AND sum(selected)=count(*))""", (sid,)).fetchone()[0]
    return {"groups": g_, "files": f_, "wasted": w_, "selected_files": sf, "selected_bytes": sb, "all_selected_groups": ag}


@app.post("/api/scans/<int:sid>/recheck")
def scan_recheck(sid):
    """Drop files that no longer exist on disk (deleted outside the app since the scan) from this scan's results."""
    c = get_db()
    gone = []
    for r in c.execute("SELECT id,path FROM files WHERE scan_id=? AND state='ok' AND group_id IS NOT NULL", (sid,)).fetchall():
        if not os.path.lexists(r["path"]):
            gone.append((r["id"],))
    if gone:
        c.executemany("UPDATE files SET state='missing',selected=0 WHERE id=?", gone)
        c.commit()
    return jsonify(removed=len(gone), summary=summary(sid))


@app.get("/api/scans/<int:sid>/summary")
def get_summary(sid):
    scan_row(sid)
    return jsonify(summary(sid))


@app.get("/api/scans/<int:sid>/groups")
def groups(sid):
    scan_row(sid)
    off = max(0, request.args.get("offset", 0, int))
    lim = max(1, min(500, request.args.get("limit", 50, int)))
    q = (request.args.get("q") or "").strip()
    c = get_db()
    sql = ("SELECT g.id,g.label,g.wasted FROM groups g WHERE g.scan_id=? AND "
           "(SELECT count(*) FROM files f WHERE f.scan_id=g.scan_id AND f.group_id=g.id AND f.state='ok')>1")
    args = [sid]
    if request.args.get("all_selected"):      # only groups where EVERY copy is ticked
        sql += (" AND (SELECT count(*) FROM files f WHERE f.scan_id=g.scan_id AND f.group_id=g.id "
                "AND f.state='ok' AND f.selected=0)=0")
    if q:
        sql += (" AND EXISTS (SELECT 1 FROM files f WHERE f.scan_id=g.scan_id AND f.group_id=g.id "
                "AND f.state='ok' AND f.path LIKE ? ESCAPE '\\')")
        args.append("%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    sql += " ORDER BY g.wasted DESC, g.id LIMIT ? OFFSET ?"
    gs = c.execute(sql, (*args, lim, off)).fetchall()
    out = []
    if gs:
        ids = [r["id"] for r in gs]
        ph = ",".join("?" * len(ids))
        files = c.execute(f"SELECT id,group_id,path,size,mtime_ns,protected,selected,ikey,meta FROM files "
                          f"WHERE scan_id=? AND state='ok' AND group_id IN ({ph}) ORDER BY group_id,path",
                          (sid, *ids)).fetchall()
        by = {}
        for f in files:
            by.setdefault(f["group_id"], []).append({
                "id": f["id"], "path": f["path"], "size": f["size"], "mtime": f["mtime_ns"] / 1e9,
                "protected": bool(f["protected"]), "selected": bool(f["selected"]), "ikey": f["ikey"],
                "kind": media.kind_of(f["path"]), "meta": json.loads(f["meta"]) if f["meta"] else {}})
        for r in gs:
            out.append({"id": r["id"], "label": r["label"], "wasted": r["wasted"], "files": by.get(r["id"], [])})
    sc = scan_row(sid)
    try:
        prm = json.loads(sc["params"] or "{}")
    except Exception:
        prm = {}
    match = {"mode": sc["mode"], "threshold": prm.get("threshold"), "vthreshold": prm.get("vthreshold"), "ber": prm.get("ber"), "flips": bool(prm.get("flips"))}
    return jsonify(groups=out, match=match)


def _active_groups(sid):
    """Yield lists of file rows for every group that still has 2+ files."""
    rconn = db.connect()
    try:
        cur = rconn.execute("SELECT id,group_id,path,size,mtime_ns,ikey,protected,meta FROM files "
                            "WHERE scan_id=? AND group_id IS NOT NULL AND state='ok' ORDER BY group_id,path", (sid,))
        for _, grp in itertools.groupby(cur, key=lambda r: r["group_id"]):
            grp = list(grp)
            if len(grp) > 1:
                yield grp
    finally:
        rconn.close()


def _meta(f):
    try:
        return json.loads(f["meta"]) if f["meta"] else {}
    except (ValueError, TypeError):
        return {}


def _px(f):
    m = _meta(f)
    return (m.get("w") or 0) * (m.get("h") or 0)


@app.post("/api/scans/<int:sid>/select")
def auto_select(sid):
    scan_row(sid)
    b = request.get_json(force=True, silent=True) or {}
    rule = b.get("rule", "")
    c = get_db()
    c.execute("UPDATE files SET selected=0 WHERE scan_id=? AND selected=1", (sid,))
    if rule != "clear":
        prefer = [os.path.normpath(p) + os.sep for p in b.get("prefer", []) if p]
        keys = {
            "newest": lambda f: (-f["mtime_ns"], f["path"]),
            "oldest": lambda f: (f["mtime_ns"], f["path"]),
            "shortest_path": lambda f: (len(f["path"]), f["path"]),
            "longest_path": lambda f: (-len(f["path"]), f["path"]),
            "alpha": lambda f: f["path"],
            "shortest_name": lambda f: (len(os.path.basename(f["path"])), f["path"]),
            "largest": lambda f: (-f["size"], f["path"]),
            "smallest": lambda f: (f["size"], f["path"]),
            "resolution": lambda f: (-_px(f), -f["size"], f["path"]),
            "longest": lambda f: (-(_meta(f).get("dur") or 0), -f["size"], f["path"]),
            "bitrate": lambda f: (-(_meta(f).get("br") or 0), -f["size"], f["path"]),
            "taken": lambda f: (_meta(f).get("taken") or "~", f["path"]),
        }
        if rule == "prefer_folder":
            if not prefer:
                return err("Enter a folder to keep")
        elif rule not in keys:
            return err("Unknown rule")
        picks = []
        for grp in _active_groups(sid):
            if any(f["protected"] for f in grp):
                picks += [f["id"] for f in grp if not f["protected"]]
                continue
            if rule == "prefer_folder":
                pool = [f for f in grp if any((f["path"] + "").startswith(p) for p in prefer)] or grp
                keeper = min(pool, key=lambda f: f["path"])
            else:
                keeper = min(grp, key=keys[rule])
            picks += [f["id"] for f in grp if f["id"] != keeper["id"] and f["ikey"] != keeper["ikey"]]
        for i in range(0, len(picks), 500):
            chunk = picks[i:i + 500]
            c.execute(f"UPDATE files SET selected=1 WHERE id IN ({','.join('?' * len(chunk))})", chunk)
    c.commit()
    return jsonify(summary(sid))


@app.post("/api/files/select")
def select_files():
    b = request.get_json(force=True, silent=True) or {}
    ids = [int(i) for i in b.get("ids", [])]
    c = get_db()
    row = c.execute("SELECT scan_id FROM files WHERE id=?", (ids[0],)).fetchone() if ids else None
    if not row:
        return err("No such file")
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        c.execute(f"UPDATE files SET selected=? WHERE protected=0 AND id IN ({','.join('?' * len(chunk))})",
                  (1 if b.get("selected") else 0, *chunk))
    c.commit()
    return jsonify(summary(row["scan_id"]))


def _like(text):
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


@app.post("/api/scans/<int:sid>/select_text")
def select_text(sid):
    """Select (or unselect) files whose path contains some text, across every group in the scan."""
    scan_row(sid)
    b = request.get_json(force=True, silent=True) or {}
    text = (b.get("text") or "").strip()
    if not text:
        return err("Type some text to look for")
    mode = b.get("mode", "select")      # select | unselect | keep_matching
    c = get_db()
    live = ("scan_id=? AND state='ok' AND group_id IN (SELECT group_id FROM files WHERE scan_id=? AND state='ok' "
            "AND group_id IS NOT NULL GROUP BY group_id HAVING count(*)>1)")
    like = _like(text)
    if mode == "dup_elsewhere":
        # files matching the text that have a copy that does NOT match (so a copy always stays outside)
        c.execute(f"UPDATE files SET selected=1 WHERE protected=0 AND {live} AND path LIKE ? ESCAPE '\\' "
                  "AND group_id IN (SELECT group_id FROM files WHERE scan_id=? AND state='ok' AND path NOT LIKE ? ESCAPE '\\')",
                  (sid, sid, like, sid, like))
    elif mode == "keep_matching":
        # in groups where something matches, select the files that do NOT match
        c.execute(f"UPDATE files SET selected=1 WHERE protected=0 AND {live} AND path NOT LIKE ? ESCAPE '\\' "
                  "AND group_id IN (SELECT group_id FROM files WHERE scan_id=? AND state='ok' AND path LIKE ? ESCAPE '\\')",
                  (sid, sid, like, sid, like))
    else:
        c.execute(f"UPDATE files SET selected=? WHERE protected=0 AND {live} AND path LIKE ? ESCAPE '\\'",
                  (0 if mode == "unselect" else 1, sid, sid, like))
    c.commit()
    return jsonify(summary(sid))


@app.post("/api/groups/select")
def select_group():
    """Select or clear every (non-protected) file in the group that file_id belongs to."""
    b = request.get_json(force=True, silent=True) or {}
    c = get_db()
    f = c.execute("SELECT scan_id,group_id FROM files WHERE id=?", (int(b.get("file_id", 0)),)).fetchone()
    if not f:
        return err("No such file")
    c.execute("UPDATE files SET selected=? WHERE scan_id=? AND group_id=? AND state='ok' AND protected=0",
              (1 if b.get("selected", True) else 0, f["scan_id"], f["group_id"]))
    c.commit()
    return jsonify(summary(f["scan_id"]))


@app.post("/api/scans/<int:sid>/groups/remove")
def remove_groups(sid):
    """Housekeeping: drop groups from this result list. Never touches any file on disk."""
    scan_row(sid)
    b = request.get_json(force=True, silent=True) or {}
    c = get_db()
    ids = [int(i) for i in b.get("ids", [])]
    q = (b.get("q") or "").strip()
    if q and not ids:
        ids = [r[0] for r in c.execute(
            "SELECT DISTINCT group_id FROM files WHERE scan_id=? AND state='ok' AND group_id IS NOT NULL "
            "AND path LIKE ? ESCAPE '\\'", (sid, _like(q)))]
    elif not ids:
        return err("No groups given")
    n = 0
    for i in range(0, len(ids), 500):
        ch = ids[i:i + 500]
        ph = ",".join("?" * len(ch))
        c.execute(f"UPDATE files SET group_id=NULL,selected=0 WHERE scan_id=? AND group_id IN ({ph})", (sid, *ch))
        n += c.execute(f"DELETE FROM groups WHERE scan_id=? AND id IN ({ph})", (sid, *ch)).rowcount
    c.commit()
    return jsonify(removed=n, summary=summary(sid))


OPS = ("type", "folder", "tree", "drive", "outside_folder", "outside_tree", "dup_folder", "dup_tree")


@app.post("/api/scans/<int:sid>/mark")
def mark_ops(sid):
    """Power tools (the Mark / Unmark menu), relative to one file the user clicked."""
    scan_row(sid)
    b = request.get_json(force=True, silent=True) or {}
    op = b.get("op")
    c = get_db()
    if op == "invert":
        c.execute("UPDATE files SET selected=1-selected WHERE scan_id=? AND protected=0 AND state='ok' AND group_id IN "
                  "(SELECT group_id FROM files WHERE scan_id=? AND state='ok' AND group_id IS NOT NULL "
                  "GROUP BY group_id HAVING count(*)>1)", (sid, sid))
        c.commit()
        return jsonify(changed=0, summary=summary(sid))
    row = c.execute("SELECT path FROM files WHERE id=? AND scan_id=?", (int(b.get("file_id", 0)), sid)).fetchone()
    if not row:
        return err("No such file")
    folder = os.path.dirname(row["path"])
    want = (b.get("folder") or "").rstrip("/")
    if want and want != folder:           # the user picked a higher folder: it must be an ancestor of the clicked file
        if not row["path"].startswith(want + "/") or not under_root(want):
            return err("That folder does not contain the file you clicked")
        folder = want
    if op in ("protect_tree", "unprotect_tree"):
        like = (folder + "/").replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"   # "<folder>/%"
        prot = 1 if op == "protect_tree" else 0
        cur = c.execute("UPDATE files SET protected=?,selected=CASE WHEN ?=1 THEN 0 ELSE selected END "
                        "WHERE scan_id=? AND path LIKE ? ESCAPE '\\'", (prot, prot, sid, like))
        c.commit()
        return jsonify(changed=cur.rowcount, summary=summary(sid))
    if op not in OPS:
        return err("Unknown operation")
    mark = 1 if b.get("mark", True) else 0
    ACTIVE = ("group_id IN (SELECT group_id FROM files WHERE scan_id=? AND state='ok' AND group_id IS NOT NULL "
              "GROUP BY group_id HAVING count(*)>1)")

    def here(prefix, whole_tree):
        """SQL test 'this file is in the folder (or its tree)': plain prefix compare, so no wildcard surprises."""
        n = len(prefix)
        if whole_tree:
            return "substr(path,1,?)=?", [n, prefix]
        return "(substr(path,1,?)=? AND instr(substr(path,?),'/')=0)", [n, prefix, n + 1]

    tree = op in ("tree", "outside_tree", "dup_tree")
    if op == "type":
        ext = os.path.splitext(row["path"])[1].lower()
        cond, args = (("lower(substr(path,?))=?", [-len(ext), ext]) if ext else ("instr(name,'.')=0", []))
    elif op == "drive":
        share = os.path.relpath(row["path"], DATA_ROOT).split(os.sep)[0]
        cond, args = here(DATA_ROOT.rstrip("/") + "/" + share + "/", True)
    else:
        h, ha = here(folder + "/", tree)
        sub = "SELECT group_id FROM files WHERE scan_id=? AND state='ok' AND group_id IS NOT NULL AND "
        if op in ("folder", "tree"):
            cond, args = h, ha
        elif op in ("dup_folder", "dup_tree"):         # in the place, and a copy exists outside it
            cond, args = f"{h} AND group_id IN ({sub}NOT {h})", [*ha, sid, *ha]
        else:                                          # outside the place, and a copy exists inside it
            cond, args = f"NOT {h} AND group_id IN ({sub}{h})", [*ha, sid, *ha]
    cur = c.execute(f"UPDATE files SET selected=? WHERE scan_id=? AND state='ok' AND protected=0 AND {ACTIVE} AND {cond}",
                    (mark, sid, sid, *args))
    c.commit()
    return jsonify(changed=cur.rowcount, summary=summary(sid))


@app.post("/api/scans/<int:sid>/fix_all_selected")
def fix_all_selected(sid):
    """In every group where all copies are ticked, untick one copy (the one with the shortest path) so a copy stays."""
    scan_row(sid)
    c = get_db()
    allsel = ("SELECT group_id FROM files WHERE scan_id=? AND state='ok' AND group_id IS NOT NULL "
              "GROUP BY group_id HAVING count(*)>1 AND sum(selected)=count(*)")
    cur = c.execute(f"""UPDATE files SET selected=0 WHERE id IN (
        SELECT id FROM (SELECT id, row_number() OVER (PARTITION BY group_id ORDER BY length(path), path) rn
                        FROM files WHERE scan_id=? AND state='ok' AND protected=0 AND group_id IN ({allsel})) WHERE rn=1)""",
                    (sid, sid))
    c.commit()
    return jsonify(fixed=cur.rowcount, summary=summary(sid))


@app.post("/api/groups/keep")
def keep_only():
    b = request.get_json(force=True, silent=True) or {}
    c = get_db()
    keep = c.execute("SELECT * FROM files WHERE id=?", (int(b.get("keep_id", 0)),)).fetchone()
    if not keep:
        return err("No such file")
    c.execute("UPDATE files SET selected=CASE WHEN id=? OR ikey=? OR protected=1 THEN 0 ELSE 1 END "
              "WHERE scan_id=? AND group_id=? AND state='ok'",
              (keep["id"], keep["ikey"], keep["scan_id"], keep["group_id"]))
    c.commit()
    return jsonify(summary(keep["scan_id"]))


@app.post("/api/scans/<int:sid>/act")
def act(sid):
    scan_row(sid)
    b = request.get_json(force=True, silent=True) or {}
    action = b.get("action")
    if action not in ("trash", "hardlink", "move", "delete"):
        return err("Unknown action")
    dest = None
    if action == "move":
        dest = os.path.normpath(b.get("dest", ""))
        if not b.get("dest") or not under_root(dest):
            return err("Pick a destination inside the data folder")
    if busy():
        return err("Wait for the running scan to finish", 409)
    try:
        res = actions.perform(get_db(), sid, action, DATA_ROOT, TRASH_NAME, ALLOW_PERM, dest, bool(b.get("allow_all")))
    except ValueError as e:
        return err(str(e))
    res["summary"] = summary(sid)
    return jsonify(res)


def _like_arg(q):
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _path_filter(col, q):
    """SQL for the path filter box. Plain text = contains. * and ? are wildcards (*.pst). ; or , or | separate alternatives."""
    terms = [t.strip() for t in re.split(r"[;,|]", q) if t.strip()]
    if not terms:
        return "", []
    parts, args = [], []
    for t in terms:
        esc = t.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        if "*" in t or "?" in t:
            pat = esc.replace("*", "%").replace("?", "_")
        else:
            pat = "%" + esc + "%"
        parts.append(f"{col} LIKE ? ESCAPE '\\'")
        args.append(pat)
    return " AND (" + " OR ".join(parts) + ")", args


def _health_filters(q, kind, ext, pre="", under="", sub=True):
    sql, args = _path_filter(pre + "path", q or "")
    if under:
        pfx = under.rstrip("/") + "/"
        sql += f" AND substr({pre}path,1,?)=?"
        args += [len(pfx), pfx]
        if not sub:
            sql += f" AND instr(substr({pre}path,?),'/')=0"
            args.append(len(pfx) + 1)
    if kind:
        sql += f" AND {pre}kind=?"
        args.append(kind)
    if ext:
        sql += f" AND lower({pre}path) LIKE ? ESCAPE '\\'"
        args.append("%." + ext.lower().lstrip(".").replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_"))
    return sql, args


def empties_summary(sid):
    r = get_db().execute("SELECT count(*) n, coalesce(sum(state='ok'),0) ok, coalesce(sum(state='removed'),0) removed, "
                         "coalesce(sum(selected=1 AND state='ok'),0) sel FROM empties WHERE scan_id=?", (sid,)).fetchone()
    return {"total": r["n"], "listed": r["ok"], "removed": r["removed"], "selected": r["sel"]}


@app.get("/api/scans/<int:sid>/empties")
def list_empties(sid):
    scan_row(sid)
    off = max(0, request.args.get("offset", 0, int))
    lim = max(1, min(500, request.args.get("limit", 200, int)))
    q = (request.args.get("q") or "").strip()
    sql, args = "SELECT id,path,junk,selected,state FROM empties WHERE scan_id=? AND state='ok'", [sid]
    if q:
        sql += " AND path LIKE ? ESCAPE '\\'"
        args.append(_like_arg(q))
    rows = get_db().execute(sql + " ORDER BY path LIMIT ? OFFSET ?", (*args, lim, off)).fetchall()
    return jsonify(folders=[{"id": r["id"], "path": r["path"], "junk": bool(r["junk"]), "selected": bool(r["selected"])} for r in rows],
                   summary=empties_summary(sid))


@app.post("/api/scans/<int:sid>/empties/select")
def select_empties(sid):
    scan_row(sid)
    b = request.get_json(force=True, silent=True) or {}
    sel = 1 if b.get("selected", True) else 0
    c = get_db()
    changed = 0
    if b.get("ids"):
        ids = [int(i) for i in b["ids"]]
        for i in range(0, len(ids), 500):
            ch = ids[i:i + 500]
            c.execute(f"UPDATE empties SET selected=? WHERE scan_id=? AND state='ok' AND id IN ({','.join('?' * len(ch))})", (sel, sid, *ch))
    else:                                    # everything, or everything matching the filter text
        q = (b.get("q") or "").strip()
        sql, args = "UPDATE empties SET selected=? WHERE scan_id=? AND state='ok'", [sel, sid]
        if q:
            sql += " AND path LIKE ? ESCAPE '\\'"
            args.append(_like_arg(q))
        c.execute(sql, args)
    c.commit()
    return jsonify(summary=empties_summary(sid))


@app.post("/api/scans/<int:sid>/empties/remove")
def remove_empties(sid):
    sc = scan_row(sid)
    if busy():
        return err("Wait for the running scan to finish", 409)
    res = emptyfolders.remove(get_db(), sid, json.loads(sc["params"]), only_selected=True)
    res["summary"] = empties_summary(sid)
    return jsonify(res)


# ------------------------------------------------------------ health check results
def health_summary(sid):
    r = get_db().execute(
        "SELECT count(*) n, coalesce(sum(state='ok'),0) ok, coalesce(sum(state IN ('trashed','moved','compressed','deleted')),0) gone, "
        "coalesce(sum(selected=1 AND state='ok'),0) sel, coalesce(sum(CASE WHEN selected=1 AND state='ok' THEN size END),0) selbytes, "
        "coalesce(sum(CASE WHEN state='ok' THEN size END),0) bytes FROM health WHERE scan_id=?", (sid,)).fetchone()
    kinds = {k["kind"]: k["n"] for k in get_db().execute(
        "SELECT kind, count(*) n FROM health WHERE scan_id=? AND state='ok' GROUP BY kind", (sid,))}
    exts = {}
    for row in get_db().execute("SELECT path,size FROM health WHERE scan_id=? AND state='ok'", (sid,)):
        nm = row["path"].rsplit("/", 1)[-1]
        e = nm.rsplit(".", 1)[-1].lower() if "." in nm.strip(".") else ""
        v = exts.setdefault(e, [0, 0])
        v[0] += 1
        v[1] += row["size"]
    return {"total": r["n"], "listed": r["ok"], "handled": r["gone"], "selected": r["sel"],
            "selected_bytes": r["selbytes"], "bytes": r["bytes"], "kinds": kinds, "exts": exts}


@app.get("/api/scans/<int:sid>/health")
def list_health(sid):
    scan_row(sid)
    off = max(0, request.args.get("offset", 0, int))
    lim = max(1, min(300, request.args.get("limit", 100, int)))
    q = (request.args.get("q") or "").strip()
    kind = (request.args.get("kind") or "").strip()
    ext = (request.args.get("ext") or "").strip()
    sql = ("SELECT h.id,h.file_id,h.path,h.size,h.mtime_ns,h.kind,h.sev,h.reason,h.detail,h.selected,COALESCE(f.protected,0) prot "
           "FROM health h LEFT JOIN files f ON f.id=h.file_id WHERE h.scan_id=? AND h.state='ok'")
    args = [sid]
    fs, fa = _health_filters(q, kind, ext, "h.")
    sql += fs
    args += fa
    rows = get_db().execute(sql + " ORDER BY h.sev DESC, h.size DESC, h.path LIMIT ? OFFSET ?", (*args, lim, off)).fetchall()
    out = []
    for r in rows:
        try:
            det = json.loads(r["detail"] or "{}")
        except ValueError:
            det = {}
        out.append({"id": r["id"], "fid": r["file_id"], "path": r["path"], "size": r["size"], "mtime": r["mtime_ns"] / 1e9,
                    "kind": r["kind"], "sev": r["sev"], "reason": r["reason"], "detail": det,
                    "selected": bool(r["selected"]), "protected": bool(r["prot"])})
    return jsonify(files=out, summary=health_summary(sid))


@app.post("/api/scans/<int:sid>/health/select")
def select_health(sid):
    scan_row(sid)
    b = request.get_json(force=True, silent=True) or {}
    sel = 1 if b.get("selected", True) else 0
    c = get_db()
    free = "(file_id IS NULL OR file_id NOT IN (SELECT id FROM files WHERE scan_id=? AND protected=1))"
    changed = 0
    if b.get("ids"):
        ids = [int(i) for i in b["ids"]]
        for i in range(0, len(ids), 500):
            ch = ids[i:i + 500]
            changed += c.execute(f"UPDATE health SET selected=? WHERE scan_id=? AND state='ok' AND {free} AND id IN ({','.join('?' * len(ch))})",
                                 (sel, sid, sid, *ch)).rowcount
    else:
        sql, args = f"UPDATE health SET selected=? WHERE scan_id=? AND state='ok' AND {free}", [sel, sid, sid]
        fs, fa = _health_filters((b.get("q") or "").strip(), (b.get("kind") or "").strip(), (b.get("ext") or "").strip(),
                                 under=(b.get("under") or "").strip(), sub=bool(b.get("sub", True)))
        sql += fs
        args += fa
        changed = c.execute(sql, args).rowcount
    c.commit()
    return jsonify(summary=health_summary(sid), changed=changed)


@app.post("/api/scans/<int:sid>/health/act")
def act_health(sid):
    scan_row(sid)
    b = request.get_json(force=True, silent=True) or {}
    action = b.get("action")
    if action not in ("trash", "move", "delete"):
        return err("Unknown action")
    dest = None
    if action == "move":
        dest = os.path.normpath(b.get("dest", ""))
        if not b.get("dest") or not under_root(dest):
            return err("Pick a destination inside the data folder")
    if busy() or _comp["running"]:
        return err("Wait for the running scan or compression to finish", 409)
    try:
        res = actions.perform_health(get_db(), sid, action, DATA_ROOT, TRASH_NAME, dest)
    except ValueError as e:
        return err(str(e))
    res["summary"] = health_summary(sid)
    return jsonify(res)


_comp = {"running": False, "sid": None, "total": 0, "done": 0, "saved": 0, "failed": 0, "errors": [], "current": "", "cancel": False, "fmt": "", "total_bytes": 0, "done_bytes": 0, "cur_size": 0, "cur_phase": "", "cur_pct": None, "started": 0}


def compress_running():
    return _comp["running"]


@app.post("/api/scans/<int:sid>/health/compress")
def compress_start(sid):
    """Compress the ticked files of a large-files scan to 7z or zip in the background (originals go to quarantine unless keep)."""
    if scan_row(sid)["mode"] != "large_files":
        return err("Compressing is only available on a Large files scan")
    b = request.get_json(force=True, silent=True) or {}
    fmt = "zip" if b.get("format") == "zip" else "7z"
    level = "fast" if b.get("level") == "fast" else "normal"
    if fmt == "7z" and not actions.sevenzip_exe():
        return err("7z is not installed in this container yet. Rebuild the image (see the README), or choose zip.", 400)
    if busy():
        return err("Wait for the running scan to finish", 409)
    with _lock:
        if _comp["running"]:
            return err("A compression is already running", 409)
        n = get_db().execute("SELECT count(*) FROM health h LEFT JOIN files f ON f.id=h.file_id WHERE h.scan_id=? AND h.selected=1 "
                             "AND h.state='ok' AND COALESCE(f.protected,0)=0", (sid,)).fetchone()[0]
        if not n:
            return err("Nothing selected")
        _comp.update(running=True, sid=sid, total=n, done=0, saved=0, failed=0, errors=[], current="", cancel=False, fmt=fmt, total_bytes=0, done_bytes=0,
                     cur_size=0, cur_phase="starting", cur_pct=None, started=time.time())

    def work():
        conn = db.connect()
        try:
            actions.perform_compress(conn, sid, fmt, level, bool(b.get("keep")), DATA_ROOT, TRASH_NAME, _comp, lambda: _comp["cancel"])
        except Exception as e:  # noqa: BLE001
            _comp["errors"].append(f"{type(e).__name__}: {e}")
        finally:
            conn.close()
            _comp["running"] = False

    threading.Thread(target=work, daemon=True).start()
    return jsonify(ok=True, total=n)


_tool = {"running": False, "ok": None, "log": ""}


@app.post("/api/tools/7z/install")
def install_7z():
    """Install the 7z program inside this container (needs internet; used when the image was built without it)."""
    if actions.sevenzip_exe():
        return jsonify(ok=True, already=True)
    with _lock:
        if _tool["running"]:
            return err("An install is already running", 409)
        _tool.update(running=True, ok=None, log="")

    def work():
        import subprocess
        env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
        cmd = ("apt-get update -qq && (apt-get install -y --no-install-recommends p7zip-full || apt-get install -y --no-install-recommends 7zip)")
        try:
            p = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True, env=env, timeout=900)
            _tool["log"] = ((p.stdout or "") + (p.stderr or ""))[-1500:]
            _tool["ok"] = bool(actions.sevenzip_exe())
        except Exception as e:  # noqa: BLE001
            _tool["log"] = f"{type(e).__name__}: {e}"
            _tool["ok"] = False
        finally:
            _tool["running"] = False

    threading.Thread(target=work, daemon=True).start()
    return jsonify(ok=True, started=True)


@app.get("/api/tools/7z/status")
def install_7z_status():
    return jsonify(running=_tool["running"], ok=_tool["ok"], log=_tool["log"], installed=bool(actions.sevenzip_exe()))


@app.get("/api/compress/status")
def compress_status():
    out = dict(_comp)
    out["errors"] = _comp["errors"][:50]
    out["now"] = time.time()
    sid = _comp.get("sid")
    out["summary"] = health_summary(sid) if sid else None
    return jsonify(out)


@app.post("/api/compress/cancel")
def compress_cancel():
    _comp["cancel"] = True
    return jsonify(ok=True)


@app.get("/api/health/<int:hid>/frame")
def health_frame(hid):
    """A picture from the flagged video at t seconds (used to show what is wrong). 404 when no picture can be read there."""
    r = get_db().execute("SELECT path,size,mtime_ns FROM health WHERE id=?", (hid,)).fetchone()
    if not r or not under_root(r["path"]):
        abort(404)
    t = max(0.0, request.args.get("t", 0, float))
    key = hashlib.sha1(f"{r['path']}|{r['size']}|{r['mtime_ns']}|{t:.1f}|hf".encode()).hexdigest()
    out = os.path.join(THUMB_DIR, key + ".jpg")
    if not os.path.exists(out):
        import subprocess
        try:
            p = subprocess.run([media.FFMPEG, "-v", "error", "-ss", f"{t:.2f}", "-i", r["path"], "-frames:v", "1", "-an",
                                "-vf", "scale='min(640,iw)':-2", "-q:v", "5", "-y", out], capture_output=True, timeout=60)
        except Exception:  # noqa: BLE001
            abort(404)
        if p.returncode != 0 or not os.path.exists(out):
            abort(404)
    return send_file(out, mimetype="image/jpeg", max_age=86400)


@app.get("/api/health/<int:hid>/copies")
def health_copies(hid):
    """Other copies of this video found by the most recent duplicate scan, and whether each one looks healthy."""
    c = get_db()
    r = c.execute("SELECT scan_id,path FROM health WHERE id=?", (hid,)).fetchone()
    if not r:
        abort(404)
    hit = c.execute("SELECT f.scan_id sid, f.group_id gid FROM files f JOIN scans s ON s.id=f.scan_id "
                    "WHERE f.path=? AND f.group_id IS NOT NULL AND f.scan_id!=? AND s.status='done' AND s.mode!='video_health' "
                    "ORDER BY f.scan_id DESC LIMIT 1", (r["path"], r["scan_id"])).fetchone()
    if not hit:
        return jsonify(found=False, copies=[])
    others = c.execute("SELECT path,size FROM files WHERE scan_id=? AND group_id=? AND path!=? AND state IN ('ok','trashed','moved')",
                       (hit["sid"], hit["gid"], r["path"])).fetchall()
    out = []
    for o in others:
        flagged = c.execute("SELECT reason FROM health WHERE scan_id=? AND path=? AND state='ok'", (r["scan_id"], o["path"])).fetchone()
        scanned = c.execute("SELECT 1 FROM files WHERE scan_id=? AND path=?", (r["scan_id"], o["path"])).fetchone()
        exists = os.path.isfile(o["path"])
        status = "gone" if not exists else "damaged" if flagged else "healthy" if scanned else "unchecked"
        out.append({"path": o["path"], "size": o["size"], "status": status, "reason": flagged["reason"] if flagged else ""})
    return jsonify(found=True, scan=hit["sid"], copies=out)


# ------------------------------------------------------------ permanent ignore list
@app.get("/api/ignores")
def list_ignores():
    return jsonify(items=ignores.listing(get_db()))


@app.post("/api/ignores")
def add_ignore():
    b = request.get_json(force=True, silent=True) or {}
    path = os.path.normpath(b.get("path", ""))
    scope = b.get("scope", "all")
    if scope not in ("empty", "scan", "all"):
        return err("Unknown scope")
    if not b.get("path") or not under_root(path):
        return err("Pick a folder inside the data folder")
    c = get_db()
    ignores.add_folder(c, path, scope, b.get("note", ""))
    c.commit()
    return jsonify(items=ignores.listing(c))


@app.post("/api/ignores/<int:iid>/delete")
def delete_ignore(iid):
    c = get_db()
    c.execute("DELETE FROM ignores WHERE id=?", (iid,))
    c.commit()
    return jsonify(items=ignores.listing(c))


@app.post("/api/scans/<int:sid>/groups/ignore")
def ignore_groups(sid):
    """Never show these duplicate groups again (any later scan), and drop them from this result list."""
    scan_row(sid)
    b = request.get_json(force=True, silent=True) or {}
    ids = [int(i) for i in b.get("ids", [])]
    if not ids:
        return err("No groups given")
    c = get_db()
    n = 0
    for gid in ids:
        paths = [r[0] for r in c.execute("SELECT path FROM files WHERE scan_id=? AND group_id=?", (sid, gid))]
        if len(paths) > 1:
            ignores.add_group(c, paths)
            n += 1
    for i in range(0, len(ids), 500):
        ch = ids[i:i + 500]
        ph = ",".join("?" * len(ch))
        c.execute(f"UPDATE files SET group_id=NULL,selected=0 WHERE scan_id=? AND group_id IN ({ph})", (sid, *ch))
        c.execute(f"DELETE FROM groups WHERE scan_id=? AND id IN ({ph})", (sid, *ch))
    c.commit()
    return jsonify(ignored=n, summary=summary(sid))


@app.post("/api/scans/<int:sid>/ignore_folder")
def ignore_folder(sid):
    """Add a folder (the clicked file's folder, or one above it) to the ignore list for duplicate and health scans,
    and hide the files under it in this result list."""
    sc = scan_row(sid)
    b = request.get_json(force=True, silent=True) or {}
    c = get_db()
    row = c.execute("SELECT path FROM files WHERE id=? AND scan_id=?", (int(b.get("file_id", 0)), sid)).fetchone()
    if not row:
        return err("No such file")
    folder = os.path.dirname(row["path"])
    want = (b.get("folder") or "").rstrip("/")
    if want and want != folder:
        if not row["path"].startswith(want + "/") or not under_root(want):
            return err("That folder does not contain the file you clicked")
        folder = want
    ignores.add_folder(c, folder, "scan")
    n = len(folder) + 1
    changed = c.execute("UPDATE files SET state='ignored',selected=0 WHERE scan_id=? AND state='ok' AND substr(path,1,?)=?",
                        (sid, n, folder + "/")).rowcount
    c.execute("UPDATE health SET state='ignored',selected=0 WHERE scan_id=? AND state='ok' AND substr(path,1,?)=?", (sid, n, folder + "/"))
    c.commit()
    fam = json.loads(sc["params"] or "{}").get("family")
    return jsonify(folder=folder, changed=changed, summary=health_summary(sid) if fam == "health" else summary(sid))


@app.post("/api/scans/<int:sid>/empties/ignore")
def ignore_empties(sid):
    """Keep these folders: never list or remove them again. The folders above them are no longer empty, and anything inside is left alone."""
    scan_row(sid)
    b = request.get_json(force=True, silent=True) or {}
    ids = [int(i) for i in b.get("ids", [])]
    if not ids:
        return err("No folders given")
    c = get_db()
    done = 0
    for eid in ids:
        r = c.execute("SELECT path FROM empties WHERE id=? AND scan_id=?", (eid, sid)).fetchone()
        if not r or not under_root(r["path"]):
            continue
        p = r["path"]
        ignores.add_folder(c, p, "empty")
        c.execute("UPDATE empties SET state='ignored',selected=0 WHERE scan_id=? AND state='ok' AND "
                  "(path=? OR substr(path,1,?)=? OR substr(?,1,length(path)+1)=path||'/')", (sid, p, len(p) + 1, p + "/", p))
        done += 1
    c.commit()
    return jsonify(ignored=done, summary=empties_summary(sid))


@app.get("/api/scans/<int:sid>/export.csv")
def export_csv(sid):
    scan_row(sid)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["group", "path", "size_bytes", "modified", "protected", "selected"])
    for grp in _active_groups(sid):
        for f in grp:
            w.writerow([f["group_id"], f["path"], f["size"],
                        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(f["mtime_ns"] / 1e9)),
                        f["protected"], ""])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=duplicates_scan{sid}.csv"})


# ------------------------------------------------------------ previews
def file_path_by_id(fid):
    r = get_db().execute("SELECT path,size,mtime_ns FROM files WHERE id=?", (fid,)).fetchone()
    if not r or not under_root(r["path"]) or not os.path.isfile(r["path"]):
        abort(404)
    return r


SAFE_INLINE = {"image/jpeg", "image/png", "image/gif", "image/webp", "image/bmp", "application/pdf", "text/plain"}


def _mime(path):
    return mimetypes.guess_type(path)[0] or "application/octet-stream"


def _viewable(mime):
    return mime in SAFE_INLINE or mime.startswith(("video/", "audio/"))


@app.get("/api/raw/<int:fid>")
def raw(fid):
    """Serve a scanned file. Only types a browser can safely show are opened inline; everything else downloads."""
    r = file_path_by_id(fid)
    mime = _mime(r["path"])
    inline = _viewable(mime) and not request.args.get("dl")
    resp = send_file(r["path"], mimetype=mime, as_attachment=not inline, download_name=os.path.basename(r["path"]),
                     conditional=True)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.get("/api/fileinfo/<int:fid>")
def fileinfo(fid):
    r = file_path_by_id(fid)
    rel = os.path.relpath(r["path"], DATA_ROOT).replace(os.sep, "/")
    host = SMB_HOST or request.host.split(":")[0]
    parts = rel.split("/")
    folder = "/" + "/".join(parts[:-1])
    dsm = f"{request.scheme}://{request.host.split(':')[0]}:{DSM_PORT}/?launchApp=SYNO.SDS.App.FileStation3.Instance&launchParam=" + \
          quote("openfile=" + quote(folder + "/", safe=""), safe="")
    st = os.stat(r["path"])
    return jsonify(name=parts[-1], path=r["path"], size=st.st_size, mtime=st.st_mtime,
                   viewable=_viewable(_mime(r["path"])), unc="\\\\" + host + "\\" + "\\".join(parts),
                   unc_folder="\\\\" + host + "\\" + "\\".join(parts[:-1]), dsm_url=dsm, nas_path="/volume1/" + rel)


@app.get("/api/emptyinfo/<int:eid>")
def emptyinfo(eid):
    """Details for one listed empty folder, including what is really inside it right now, so it can be checked."""
    r = get_db().execute("SELECT path FROM empties WHERE id=?", (eid,)).fetchone()
    if not r or not under_root(r["path"]):
        abort(404)
    path = r["path"]
    rel = os.path.relpath(path, DATA_ROOT).replace(os.sep, "/")
    parts = rel.split("/")
    host = SMB_HOST or request.host.split(":")[0]
    dsm = f"{request.scheme}://{request.host.split(':')[0]}:{DSM_PORT}/?launchApp=SYNO.SDS.App.FileStation3.Instance&launchParam=" + \
          quote("openfile=" + quote("/" + rel + "/", safe=""), safe="")
    entries, more, exists = [], False, os.path.isdir(path)
    if exists:
        try:
            with os.scandir(path) as it:
                for e in it:
                    if len(entries) >= 200:
                        more = True
                        break
                    try:
                        kind = "link" if e.is_symlink() else "folder" if e.is_dir(follow_symlinks=False) else "file"
                        entries.append({"name": e.name, "kind": kind, "size": e.stat(follow_symlinks=False).st_size if kind == "file" else None})
                    except OSError:
                        entries.append({"name": e.name, "kind": "unreadable", "size": None})
        except OSError as ex:
            entries.append({"name": f"(cannot read this folder: {ex})", "kind": "unreadable", "size": None})
    return jsonify(path=path, name=parts[-1], exists=exists, entries=sorted(entries, key=lambda x: x["name"].lower()), more=more,
                   unc="\\\\" + host + "\\" + "\\".join(parts), dsm_url=dsm, nas_path="/volume1/" + rel)


@app.post("/api/files/<int:fid>/move")
def move_file(fid):
    """Move one file, from the file-details window, to a folder the user picked."""
    b = request.get_json(force=True, silent=True) or {}
    dest = os.path.normpath(b.get("dest", ""))
    if not b.get("dest") or not under_root(dest):
        return err("Pick a destination inside the data folder")
    r = get_db().execute("SELECT path FROM files WHERE id=?", (fid,)).fetchone()
    if not r or not under_root(r["path"]):
        return err("No such file")
    try:
        target = actions.move_one(get_db(), fid, dest, TRASH_NAME)
    except (ValueError, OSError) as e:
        return err(str(e))
    return jsonify(target=target)


# ------------------------------------------------------------ folder browser (look inside folders, act on a whole folder)
def _safe_dir(path, need_depth=0):
    """Real folder inside the data root. need_depth=2 means it must be below a shared folder (never a share itself)."""
    if not path or not under_root(path):
        return None, "That folder is outside the data folder"
    rp = os.path.realpath(path)
    if not os.path.isdir(rp):
        return None, "That folder no longer exists"
    rel = os.path.relpath(rp, DATA_ROOT)
    parts = [] if rel == "." else rel.split(os.sep)
    if TRASH_NAME in parts:
        return None, "That is the quarantine area"
    if need_depth and len(parts) < need_depth:
        return None, "For safety, whole shared folders can't be removed from here. Open it and pick a folder inside it."
    return rp, None


@app.get("/api/ls")
def ls_folder():
    """Sub-folders and files of one folder, for the folder browser."""
    rp, e = _safe_dir(request.args.get("path") or START_PATH)
    if e:
        return err(e, 404)
    dirs, files, more = [], [], False
    try:
        with os.scandir(rp) as it:
            for ent in it:
                if ent.name == TRASH_NAME or ent.name[0] == "#" or ent.name == "@eaDir":
                    continue
                try:
                    if ent.is_dir(follow_symlinks=False):
                        dirs.append({"name": ent.name})
                    elif ent.is_file(follow_symlinks=False):
                        st = ent.stat(follow_symlinks=False)
                        files.append({"name": ent.name, "size": st.st_size, "mtime": st.st_mtime,
                                      "mime": _mime(ent.name), "viewable": _viewable(_mime(ent.name))})
                except OSError:
                    pass
                if len(dirs) + len(files) > 5000:
                    more = True
                    break
    except OSError as ex:
        return err(str(ex), 403)
    dirs.sort(key=lambda d: d["name"].lower())
    files.sort(key=lambda f: f["name"].lower())
    parent = os.path.dirname(rp) if rp != DATA_ROOT else None
    rel = os.path.relpath(rp, DATA_ROOT)
    return jsonify(path=rp, parent=parent, dirs=dirs, files=files, more=more,
                   can_act=(rel != "." and len(rel.split(os.sep)) >= 2))


def _folder_stats(rp, limit_s=90):
    t0 = time.time()
    n = b = d = 0
    cut = False
    for root, dirs, files in os.walk(rp):
        d += len(dirs)
        for f in files:
            try:
                st = os.lstat(os.path.join(root, f))
                b += st.st_size
                n += 1
            except OSError:
                pass
        if time.time() - t0 > limit_s:
            cut = True
            break
    return n, b, d, cut


@app.get("/api/foldersize")
def folder_size():
    rp, e = _safe_dir(request.args.get("path"))
    if e:
        return err(e, 404)
    n, b, d, cut = _folder_stats(rp)
    return jsonify(files=n, bytes=b, folders=d, partial=cut)


@app.get("/api/rawpath")
def raw_path():
    """Open any file in the browser folder view (video, picture, audio, PDF play inline; other types download)."""
    path = request.args.get("path", "")
    if not under_root(path) or not os.path.isfile(path) or TRASH_NAME in path.split(os.sep):
        abort(404)
    mime = _mime(path)
    inline = _viewable(mime) and not request.args.get("dl")
    resp = send_file(path, mimetype=mime, as_attachment=not inline, download_name=os.path.basename(path), conditional=True)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.get("/api/thumbpath")
def thumb_path():
    """Still frame / small picture for a file picked in the folder view (used when the browser can't play the format)."""
    path = request.args.get("path", "")
    if not under_root(path) or not os.path.isfile(path):
        abort(404)
    px = max(64, min(1920, request.args.get("s", 900, int)))
    st = os.stat(path)
    key = hashlib.sha1(f"{path}|{st.st_size}|{st.st_mtime_ns}|{px}|p".encode()).hexdigest()
    out = os.path.join(THUMB_DIR, key + ".jpg")
    if not os.path.exists(out):
        kind = media.kind_of(path)
        try:
            if kind == "video":
                import subprocess
                p = subprocess.run([media.FFMPEG, "-v", "error", "-ss", "3", "-i", path, "-frames:v", "1", "-an",
                                    "-vf", f"scale='min({px},iw)':-2", "-q:v", "5", "-y", out], capture_output=True, timeout=60)
                if p.returncode != 0 or not os.path.exists(out):
                    subprocess.run([media.FFMPEG, "-v", "error", "-i", path, "-frames:v", "1", "-an",
                                    "-vf", f"scale='min({px},iw)':-2", "-q:v", "5", "-y", out], capture_output=True, timeout=60)
                if not os.path.exists(out):
                    abort(404)
            elif kind == "img":
                from PIL import Image, ImageOps
                Image.MAX_IMAGE_PIXELS = None
                with Image.open(path) as im:
                    im = ImageOps.exif_transpose(im)
                    im.thumbnail((px, px))
                    im.convert("RGB").save(out, "JPEG", quality=80)
            else:
                abort(404)
        except Exception:  # noqa: BLE001
            abort(404)
    return send_file(out, mimetype="image/jpeg", max_age=86400)


@app.post("/api/folder/act")
def folder_act():
    """Quarantine, move or permanently delete a whole folder. Runs in the background; the page polls /api/folder/status."""
    b = request.get_json(force=True, silent=True) or {}
    action = b.get("action")
    if action not in ("trash", "move", "delete"):
        return err("Unknown action")
    rp, e = _safe_dir(b.get("path"), need_depth=2)
    if e:
        return err(e)
    if os.path.islink(b.get("path") or "") or os.path.islink(rp):
        return err("That is a shortcut (link), not a real folder")
    dest = None
    if action == "move":
        dp, e2 = _safe_dir(os.path.normpath(b.get("dest") or ""))
        if e2:
            return err("Pick a destination inside the data folder")
        if dp == rp or dp.startswith(rp + os.sep):
            return err("Can't move a folder into itself")
        if os.path.dirname(rp) == dp:
            return err("The folder is already there")
        dest = dp
    with _lock:
        if _fold["running"] or (_current is not None and _current.is_alive()) or _comp["running"]:
            return err("A scan, compression or another folder job is running. Wait for it to finish (or cancel it) first.", 409)
        _fold.update(running=True, action=action, path=rp, phase="starting", files=0, bytes=0, total_files=0, total_bytes=0,
                     ok=None, error="", warn="", state="", target="", id=_fold["id"] + 1)
    threading.Thread(target=_folder_work, args=(rp, action, dest), daemon=True).start()
    return jsonify(started=True, id=_fold["id"])


def _folder_work(rp, action, dest):
    import shutil
    import uuid
    st = _fold
    try:
        if action == "move":
            target = actions._unique(os.path.join(dest, os.path.basename(rp)))
            st["phase"] = "moving"
            shutil.move(rp, target)
            st.update(state="moved", target=target)
        elif action == "trash":
            st["phase"] = "counting"
            n, size, d, cut = _folder_stats(rp, 30)
            st.update(total_files=n, total_bytes=size, phase="moving")
            stamp = time.strftime("%Y%m%d-%H%M%S")
            tdir = os.path.join(actions.trash_dir_for(rp, DATA_ROOT, TRASH_NAME), stamp)
            os.makedirs(tdir, exist_ok=True)
            tpath = os.path.join(tdir, f"{uuid.uuid4().hex[:8]}_{os.path.basename(rp)}")
            shutil.move(rp, tpath)
            with open(os.path.join(tdir, "manifest.tsv"), "a", encoding="utf-8") as mf:
                mf.write(f"{os.path.basename(tpath)}\t{rp}\n")
            st.update(state="trashed", target=tpath, files=n, bytes=size)
            _db_retry(lambda c: c.execute("INSERT INTO trash(orig_path,trash_path,size,ts) VALUES(?,?,?,?)", (rp, tpath, size, time.time())), st)
        else:
            st["phase"] = "counting"
            n, size, d, cut = _folder_stats(rp, 60)
            st.update(total_files=n, total_bytes=size, phase="deleting")
            bad = 0
            for root, dirs, files in os.walk(rp, topdown=False):
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        sz = os.lstat(fp).st_size
                        os.remove(fp)
                        st["files"] += 1
                        st["bytes"] += sz
                    except OSError:
                        bad += 1
                for dn in dirs:
                    try:
                        os.rmdir(os.path.join(root, dn))
                    except OSError:
                        pass
            try:
                os.rmdir(rp)
            except OSError:
                pass
            if os.path.exists(rp):
                raise OSError(f"{bad} item(s) could not be deleted (in use or no permission); the rest of the folder was removed")
            st["state"] = "deleted"
        pre = rp + os.sep
        state = st["state"]

        def upd(c):
            c.execute("UPDATE health SET state=?,selected=0 WHERE state='ok' AND file_id IN "
                      "(SELECT id FROM files WHERE substr(path,1,?)=?)", (state, len(pre), pre))
            c.execute("UPDATE files SET state=?,selected=0 WHERE state='ok' AND substr(path,1,?)=?", (state, len(pre), pre))
            actions._log(c, None, "folder-" + action, rp, st["target"], True)
        _db_retry(upd, st)
        st["ok"] = True
    except Exception as ex:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        st["ok"] = False
        st["error"] = f"{type(ex).__name__}: {ex}"
        if action == "delete" and not os.path.exists(rp):
            st["ok"] = True
    finally:
        st["running"] = False


def _db_retry(fn, st):
    """Run a database write on its own connection, retrying if the database is busy. The files are already changed on disk,
    so a failure here only means the old scan results are not updated (shown as a note)."""
    for i in range(6):
        conn = db.connect()
        try:
            fn(conn)
            conn.commit()
            st["warn"] = ""
            return True
        except Exception as ex:  # noqa: BLE001
            st["warn"] = f"Folder done, but the saved results could not be updated ({type(ex).__name__}); re-run the scan to refresh them."
            time.sleep(2 + i)
        finally:
            conn.close()
    return False


@app.get("/api/folder/status")
def folder_status():
    return jsonify(dict(_fold))


@app.get("/api/thumb/<int:fid>")
def thumb(fid):
    r = file_path_by_id(fid)
    px = max(64, min(1920, request.args.get("s", 240, int)))
    key = hashlib.sha1(f"{r['path']}|{r['size']}|{r['mtime_ns']}|{px}".encode()).hexdigest()
    out = os.path.join(THUMB_DIR, key + ".jpg")
    if not os.path.exists(out):
        kind = media.kind_of(r["path"])
        try:
            if kind == "video":
                import subprocess
                meta = db_meta(fid)
                t = (meta.get("dur") or 0) * 0.2
                p = subprocess.run([media.FFMPEG, "-v", "error", "-ss", f"{t:.2f}", "-i", r["path"], "-frames:v", "1", "-an",
                                    "-vf", f"scale='min({px},iw)':-2", "-q:v", "5", "-y", out], capture_output=True, timeout=60)
                if p.returncode != 0 or not os.path.exists(out):
                    abort(404)
            elif kind == "img":
                from PIL import Image, ImageOps
                Image.MAX_IMAGE_PIXELS = None
                with Image.open(r["path"]) as im:
                    if im.format == "JPEG":
                        im.draft("RGB", (px * 2, px * 2))
                    im = ImageOps.exif_transpose(im)
                    im.thumbnail((px, px))
                    im.convert("RGB").save(out, "JPEG", quality=75 if px <= 480 else 85)
            else:
                abort(404)
        except Exception:  # noqa: BLE001
            abort(404)
    return send_file(out, mimetype="image/jpeg", max_age=86400)


def db_meta(fid):
    r = get_db().execute("SELECT meta FROM files WHERE id=?", (fid,)).fetchone()
    try:
        return json.loads(r["meta"]) if r and r["meta"] else {}
    except ValueError:
        return {}


# ------------------------------------------------------------ quarantine
@app.get("/api/trash")
def trash_list():
    rows = get_db().execute("SELECT * FROM trash WHERE restored=0 AND purged=0 ORDER BY ts DESC LIMIT 2000").fetchall()
    tot = get_db().execute("SELECT count(*), coalesce(sum(size),0) FROM trash WHERE restored=0 AND purged=0").fetchone()
    return jsonify(items=[dict(r) for r in rows], count=tot[0], bytes=tot[1])


@app.post("/api/trash/restore")
def trash_restore():
    ids = (request.get_json(force=True, silent=True) or {}).get("ids", [])
    return jsonify(actions.restore(get_db(), [int(i) for i in ids]))


@app.post("/api/trash/purge")
def trash_purge():
    b = request.get_json(force=True, silent=True) or {}
    c = get_db()
    if b.get("all"):
        ids = [r[0] for r in c.execute("SELECT id FROM trash WHERE restored=0 AND purged=0")]
    else:
        ids = [int(i) for i in b.get("ids", [])]
    return jsonify(actions.purge(c, ids))


# ------------------------------------------------------------ scheduled jobs
def delete_scan_rows(conn, sid):
    for t in ("files", "groups", "empties", "health"):
        conn.execute(f"DELETE FROM {t} WHERE scan_id=?", (sid,))
    conn.execute("DELETE FROM scans WHERE id=?", (sid,))


def job_json(c, j):
    d = dict(j)
    d["params"] = json.loads(d["params"] or "{}")
    d["schedule"] = json.loads(d["schedule"] or "{}")
    last = c.execute("SELECT id,status,finished,message,stats FROM scans WHERE job_id=? ORDER BY id DESC LIMIT 1", (j["id"],)).fetchone()
    if last:
        d["last"] = {"id": last["id"], "status": last["status"], "finished": last["finished"], "message": last["message"],
                     "stats": json.loads(last["stats"] or "{}")}
    d["runs"] = c.execute("SELECT count(*) FROM scans WHERE job_id=?", (j["id"],)).fetchone()[0]
    return d


def read_job_body(b):
    """Validate the job form. Returns (fields dict, None) or (None, error)."""
    params, e = build_params(b.get("params") or {})
    if e:
        return None, e
    name = (b.get("name") or "").strip()
    if not name:
        return None, "Give the job a name"
    try:
        sched = schedule.clean(b.get("schedule") or {})
    except (ValueError, TypeError) as ex:
        return None, str(ex)
    keep = max(1, min(50, int(b.get("keep_runs", 3) or 3)))
    return {"name": name[:80], "params": params, "schedule": sched, "keep_runs": keep, "enabled": 1 if b.get("enabled", True) else 0}, None


@app.get("/api/jobs")
def jobs_list():
    c = get_db()
    return jsonify(jobs=[job_json(c, j) for j in c.execute("SELECT * FROM jobs ORDER BY name COLLATE NOCASE")], now=time.time())


@app.post("/api/jobs")
def jobs_create():
    f, e = read_job_body(request.get_json(force=True, silent=True) or {})
    if e:
        return err(e)
    c = get_db()
    nxt = schedule.next_run_time(f["schedule"], time.time()) if f["enabled"] else None
    cur = c.execute("INSERT INTO jobs(name,enabled,params,schedule,keep_runs,next_run,created) VALUES(?,?,?,?,?,?,?)",
                    (f["name"], f["enabled"], json.dumps(f["params"]), json.dumps(f["schedule"]), f["keep_runs"], nxt, time.time()))
    c.commit()
    return jsonify(id=cur.lastrowid)


@app.put("/api/jobs/<int:jid>")
def jobs_update(jid):
    c = get_db()
    if not c.execute("SELECT 1 FROM jobs WHERE id=?", (jid,)).fetchone():
        abort(404)
    b = request.get_json(force=True, silent=True) or {}
    if set(b) == {"enabled"}:                                   # quick pause / resume switch
        old = c.execute("SELECT schedule FROM jobs WHERE id=?", (jid,)).fetchone()
        nxt = schedule.next_run_time(json.loads(old["schedule"]), time.time()) if b["enabled"] else None
        c.execute("UPDATE jobs SET enabled=?,next_run=? WHERE id=?", (1 if b["enabled"] else 0, nxt, jid))
        c.commit()
        return jsonify(ok=True)
    f, e = read_job_body(b)
    if e:
        return err(e)
    nxt = schedule.next_run_time(f["schedule"], time.time()) if f["enabled"] else None
    c.execute("UPDATE jobs SET name=?,enabled=?,params=?,schedule=?,keep_runs=?,next_run=? WHERE id=?",
              (f["name"], f["enabled"], json.dumps(f["params"]), json.dumps(f["schedule"]), f["keep_runs"], nxt, jid))
    c.commit()
    return jsonify(ok=True)


@app.delete("/api/jobs/<int:jid>")
def jobs_delete(jid):
    c = get_db()
    if request.args.get("results") == "only":          # clear the saved results but keep the job
        if _current is not None and _current.is_alive() and (c.execute("SELECT job_id FROM scans WHERE id=?", (_current.scan_id,)).fetchone() or [None])[0] == jid:
            return err("This job is running right now. Cancel it first.", 409)
        n = 0
        for r in c.execute("SELECT id FROM scans WHERE job_id=?", (jid,)).fetchall():
            delete_scan_rows(c, r["id"]); n += 1
        c.commit()
        return jsonify(ok=True, cleared=n)
    if request.args.get("results") == "1":
        if _current is not None and _current.is_alive() and (c.execute("SELECT job_id FROM scans WHERE id=?", (_current.scan_id,)).fetchone() or [None])[0] == jid:
            return err("This job is running right now. Cancel it first.", 409)
        for r in c.execute("SELECT id FROM scans WHERE job_id=?", (jid,)).fetchall():
            delete_scan_rows(c, r["id"])
    else:
        c.execute("UPDATE scans SET job_id=NULL WHERE job_id=?", (jid,))
    c.execute("DELETE FROM jobs WHERE id=?", (jid,))
    c.commit()
    return jsonify(ok=True)


@app.post("/api/jobs/<int:jid>/run")
def jobs_run(jid):
    c = get_db()
    j = c.execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
    if not j:
        abort(404)
    params = json.loads(j["params"])
    sid, e = launch_scan(params, jid, "manual")
    if e:
        return err(e, 409)
    c.execute("UPDATE jobs SET last_run=?,last_scan_id=? WHERE id=?", (time.time(), sid, jid))
    c.commit()
    return jsonify(id=sid)


@app.get("/api/cache")
def cache_info():
    c = get_db()
    n, old = c.execute("SELECT count(*), min(seen) FROM cache").fetchone()
    return jsonify(entries=n, oldest=old, days=scanner.CACHE_DAYS)


@app.post("/api/cache/clean")
def cache_clean():
    """Forget cached fingerprints of files not seen by a scan for N days (never touches your files)."""
    if busy():
        return err("Wait for the running scan to finish", 409)
    days = max(0, min(3650, int((request.get_json(force=True, silent=True) or {}).get("days", scanner.CACHE_DAYS))))
    n = db.prune_cache(get_db(), days)
    return jsonify(removed=n, entries=get_db().execute("SELECT count(*) FROM cache").fetchone()[0])


@app.post("/api/scans/cleanup")
def scans_cleanup():
    """Delete finished scan results older than N days (never touches your files)."""
    days = max(0, min(3650, int((request.get_json(force=True, silent=True) or {}).get("older_than_days", 7))))
    cutoff = time.time() - days * 86400
    c = get_db()
    ids = [r["id"] for r in c.execute("SELECT id FROM scans WHERE status NOT IN ('running','queued') AND started < ?", (cutoff,))]
    for sid in ids:
        delete_scan_rows(c, sid)
    c.commit()
    if ids:
        try:
            c.isolation_level = None
            c.execute("VACUUM")
        except Exception:  # noqa: BLE001
            pass
    return jsonify(deleted=len(ids))


def prune_runs(c):
    """Keep only each job's newest N finished runs."""
    for j in c.execute("SELECT id,keep_runs FROM jobs").fetchall():
        old = c.execute("SELECT id FROM scans WHERE job_id=? AND status NOT IN ('running','queued') ORDER BY id DESC LIMIT -1 OFFSET ?",
                        (j["id"], j["keep_runs"] or 3)).fetchall()
        for r in old:
            delete_scan_rows(c, r["id"])
    c.commit()


def scheduler_tick():
    now = time.time()
    c = db.connect()
    try:
        due = c.execute("SELECT * FROM jobs WHERE enabled=1 AND next_run IS NOT NULL AND next_run<=? ORDER BY next_run", (now,)).fetchall()
        for j in due:
            sched = json.loads(j["schedule"])
            if now > j["next_run"] + schedule.GRACE:            # missed (server off / busy): wait for the next slot
                nxt = schedule.next_run_time(sched, now)
                c.execute("UPDATE jobs SET next_run=?,enabled=? WHERE id=?", (nxt, 1 if nxt else 0, j["id"]))
                continue
            if busy():
                break                                           # try again next tick
            params = json.loads(j["params"])
            missing = [r["path"] for r in params["roots"] if not os.path.isdir(r["path"])]
            if missing:                                         # leave a visible failed run instead of silently skipping
                cur = c.execute("INSERT INTO scans(started,finished,status,mode,params,phase,message,job_id,source) VALUES(?,?,?,?,?,?,?,?,?)",
                                (now, now, "error", params["mode"], j["params"], "finished", "Folder not found: " + ", ".join(missing), j["id"], "schedule"))
                sid = cur.lastrowid
            else:
                sid, e = launch_scan(params, j["id"], "schedule", schedule.deadline_for(sched, now))
                if e:
                    break
            nxt = schedule.next_run_time(sched, now)
            c.execute("UPDATE jobs SET last_run=?,last_scan_id=?,next_run=?,enabled=? WHERE id=?", (now, sid, nxt, 1 if nxt else 0, j["id"]))
        c.commit()
        if not busy():
            prune_runs(c)
    finally:
        c.close()


def scheduler_loop():
    while True:
        try:
            scheduler_tick()
        except Exception as ex:  # noqa: BLE001
            print("scheduler error:", ex, flush=True)
        time.sleep(20)


threading.Thread(target=scheduler_loop, daemon=True, name="scheduler").start()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5070")), threaded=True)
