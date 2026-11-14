"""File actions: quarantine, hardlink, move, delete, restore. Every action re-verifies the file on disk first."""
import itertools
import json
import os
import shutil
import time
import uuid

import db


def trash_dir_for(path, data_root, trash_name):
    """Quarantine lives inside the same shared folder as the file, so the move is an instant rename."""
    rel = os.path.relpath(path, data_root)
    first = rel.split(os.sep)[0]
    if first in ("..", "."):
        return os.path.join(data_root, trash_name)
    return os.path.join(data_root, first, trash_name)


def _lstat_ok(row_path, size, mtime_ns):
    try:
        st = os.lstat(row_path)
    except FileNotFoundError:
        return "missing", None
    except OSError as e:
        return str(e), None
    if not os.path.isfile(row_path) or os.path.islink(row_path):
        return "not a regular file any more", None
    if st.st_size != size or db.clamp_ns(st.st_mtime_ns) != mtime_ns:
        return "changed since scan", None
    return None, st


def _log(conn, scan_id, action, path, detail, ok):
    conn.execute("INSERT INTO action_log(ts,scan_id,action,path,detail,ok) VALUES(?,?,?,?,?,?)",
                 (time.time(), scan_id, action, path, detail, 1 if ok else 0))


def _unique(dest):
    if not os.path.exists(dest):
        return dest
    base, ext = os.path.splitext(dest)
    i = 1
    while os.path.exists(f"{base} ({i}){ext}"):
        i += 1
    return f"{base} ({i}){ext}"


def perform(conn, scan_id, action, data_root, trash_name, allow_perm=False, dest=None, allow_all=False):
    if action == "delete" and not allow_perm:
        raise ValueError("Permanent delete is disabled (set ALLOW_PERMANENT_DELETE=1)")
    if action == "move" and not dest:
        raise ValueError("No destination folder")
    res = {"done": 0, "bytes": 0, "skipped": 0, "errors": []}
    stamp = time.strftime("%Y%m%d-%H%M%S")

    def fail(path, why):
        res["skipped"] += 1
        if len(res["errors"]) < 100:
            res["errors"].append(f"{path}: {why}")

    sel = conn.execute(
        "SELECT id,group_id,path,size,mtime_ns,ikey FROM files "
        "WHERE scan_id=? AND selected=1 AND state='ok' AND protected=0 AND group_id IS NOT NULL "
        "ORDER BY group_id,id", (scan_id,)).fetchall()
    for gid, items in itertools.groupby(sel, key=lambda r: r["group_id"]):
        items = list(items)
        sel_ids = {r["id"] for r in items}
        members = conn.execute(
            "SELECT id,path,size,mtime_ns,ikey FROM files WHERE scan_id=? AND group_id=? AND state='ok'",
            (scan_id, gid)).fetchall()
        keepers = []
        for m in members:
            if m["id"] in sel_ids:
                continue
            why, st = _lstat_ok(m["path"], m["size"], m["mtime_ns"])
            if not why:
                keepers.append((m, st))
        if not keepers and allow_all and action in ("trash", "move", "delete"):
            pass  # user explicitly confirmed removing every copy in this group
        elif not keepers:
            for r in items:
                fail(r["path"], "skipped: would remove every remaining copy in the group")
            continue
        for r in items:
            path = r["path"]
            why, st = _lstat_ok(path, r["size"], r["mtime_ns"])
            if why:
                if why == "missing":
                    conn.execute("UPDATE files SET state='missing',selected=0 WHERE id=?", (r["id"],))
                fail(path, why)
                continue
            try:
                new_state, detail = None, ""
                if action == "trash":
                    tdir = os.path.join(trash_dir_for(path, data_root, trash_name), stamp)
                    os.makedirs(tdir, exist_ok=True)
                    tpath = os.path.join(tdir, f"{uuid.uuid4().hex[:8]}_{os.path.basename(path)}")
                    shutil.move(path, tpath)
                    with open(os.path.join(tdir, "manifest.tsv"), "a", encoding="utf-8") as mf:
                        mf.write(f"{os.path.basename(tpath)}\t{path}\n")
                    conn.execute("INSERT INTO trash(orig_path,trash_path,size,ts) VALUES(?,?,?,?)",
                                 (path, tpath, r["size"], time.time()))
                    new_state, detail = "trashed", tpath
                elif action == "delete":
                    os.remove(path)
                    new_state = "deleted"
                elif action == "hardlink":
                    keeper = None
                    for m, kst in keepers:
                        if m["ikey"] == r["ikey"]:
                            keeper = "same"
                            break
                        if kst.st_dev == st.st_dev and keeper is None:
                            keeper = m["path"]
                    if keeper == "same":
                        new_state = "linked"
                    elif keeper is None:
                        fail(path, "no kept copy on the same volume/shared folder to link to")
                        continue
                    else:
                        tmp = f"{path}.dedupe_{uuid.uuid4().hex[:6]}"
                        os.link(keeper, tmp)
                        os.replace(tmp, path)
                        new_state, detail = "linked", keeper
                elif action == "move":
                    os.makedirs(dest, exist_ok=True)
                    target = _unique(os.path.join(dest, os.path.basename(path)))
                    shutil.move(path, target)
                    new_state, detail = "moved", target
                else:
                    raise ValueError("unknown action")
                conn.execute("UPDATE files SET state=?,selected=0 WHERE id=?", (new_state, r["id"]))
                _log(conn, scan_id, action, path, detail, True)
                res["done"] += 1
                res["bytes"] += r["size"]
            except Exception as e:  # noqa: BLE001
                _log(conn, scan_id, action, path, str(e), False)
                fail(path, str(e))
        conn.commit()
    conn.commit()
    return res


def perform_health(conn, scan_id, action, data_root, trash_name, dest=None):
    """Quarantine or move the ticked files of a health-check scan (no duplicate groups, so no 'keep one' rule applies)."""
    if action not in ("trash", "move", "delete"):
        raise ValueError("Unknown action")
    if action == "move" and not dest:
        raise ValueError("No destination folder")
    res = {"done": 0, "bytes": 0, "skipped": 0, "errors": []}
    stamp = time.strftime("%Y%m%d-%H%M%S")
    rows = conn.execute(
        "SELECT h.id hid, h.file_id fid, h.path, h.size, h.mtime_ns FROM health h LEFT JOIN files f ON f.id=h.file_id "
        "WHERE h.scan_id=? AND h.selected=1 AND h.state='ok' AND COALESCE(f.protected,0)=0 ORDER BY h.id", (scan_id,)).fetchall()
    for r in rows:
        path = r["path"]
        why, st = _lstat_ok(path, r["size"], r["mtime_ns"])
        if why:
            if why == "missing":
                conn.execute("UPDATE health SET state='missing',selected=0 WHERE id=?", (r["hid"],))
            res["skipped"] += 1
            if len(res["errors"]) < 100:
                res["errors"].append(f"{path}: {why}")
            continue
        try:
            if action == "trash":
                tdir = os.path.join(trash_dir_for(path, data_root, trash_name), stamp)
                os.makedirs(tdir, exist_ok=True)
                tpath = os.path.join(tdir, f"{uuid.uuid4().hex[:8]}_{os.path.basename(path)}")
                shutil.move(path, tpath)
                with open(os.path.join(tdir, "manifest.tsv"), "a", encoding="utf-8") as mf:
                    mf.write(f"{os.path.basename(tpath)}\t{path}\n")
                conn.execute("INSERT INTO trash(orig_path,trash_path,size,ts) VALUES(?,?,?,?)", (path, tpath, r["size"], time.time()))
                new_state, detail = "trashed", tpath
            elif action == "delete":
                os.remove(path)
                new_state, detail = "deleted", ""
            else:
                os.makedirs(dest, exist_ok=True)
                target = _unique(os.path.join(dest, os.path.basename(path)))
                shutil.move(path, target)
                new_state, detail = "moved", target
            conn.execute("UPDATE health SET state=?,selected=0 WHERE id=?", (new_state, r["hid"]))
            if r["fid"]:
                conn.execute("UPDATE files SET state=?,selected=0 WHERE id=?", (new_state, r["fid"]))
            _log(conn, scan_id, action, path, detail, True)
            res["done"] += 1
            res["bytes"] += r["size"]
        except Exception as e:  # noqa: BLE001
            _log(conn, scan_id, action, path, str(e), False)
            res["skipped"] += 1
            if len(res["errors"]) < 100:
                res["errors"].append(f"{path}: {e}")
        conn.commit()
    conn.commit()
    return res


def move_one(conn, fid, dest, trash_name):
    """Move one listed file to another folder (the user picked both). Returns the new path."""
    r = conn.execute("SELECT id,scan_id,path,size FROM files WHERE id=?", (fid,)).fetchone()
    if not r:
        raise ValueError("No such file")
    path = r["path"]
    if not os.path.isfile(path) or os.path.islink(path):
        raise ValueError("That file is no longer there (moved, deleted or changed since the scan)")
    if trash_name in dest.split(os.sep):
        raise ValueError("Pick a normal folder, not the quarantine")
    if os.path.normpath(os.path.dirname(path)) == os.path.normpath(dest):
        raise ValueError("The file is already in that folder")
    os.makedirs(dest, exist_ok=True)
    target = _unique(os.path.join(dest, os.path.basename(path)))
    shutil.move(path, target)
    conn.execute("UPDATE files SET state='moved',selected=0 WHERE id=?", (fid,))
    conn.execute("UPDATE health SET state='moved',selected=0 WHERE file_id=?", (fid,))
    _log(conn, r["scan_id"], "move", path, target, True)
    conn.commit()
    return target


def restore(conn, ids):
    res = {"done": 0, "errors": []}
    for i in ids:
        r = conn.execute("SELECT * FROM trash WHERE id=? AND restored=0 AND purged=0", (i,)).fetchone()
        if not r:
            continue
        try:
            if not os.path.exists(r["trash_path"]):
                raise FileNotFoundError("file is no longer in the quarantine folder")
            if os.path.exists(r["orig_path"]):
                raise FileExistsError("a file already exists at the original location")
            os.makedirs(os.path.dirname(r["orig_path"]), exist_ok=True)
            shutil.move(r["trash_path"], r["orig_path"])
            conn.execute("UPDATE trash SET restored=1 WHERE id=?", (i,))
            _log(conn, None, "restore", r["orig_path"], "", True)
            res["done"] += 1
        except Exception as e:  # noqa: BLE001
            res["errors"].append(f"{r['orig_path']}: {e}")
    conn.commit()
    return res


def purge(conn, ids):
    res = {"done": 0, "bytes": 0, "errors": []}
    for i in ids:
        r = conn.execute("SELECT * FROM trash WHERE id=? AND restored=0 AND purged=0", (i,)).fetchone()
        if not r:
            continue
        try:
            if os.path.isdir(r["trash_path"]) and not os.path.islink(r["trash_path"]):
                shutil.rmtree(r["trash_path"])
            elif os.path.exists(r["trash_path"]):
                os.remove(r["trash_path"])
            conn.execute("UPDATE trash SET purged=1 WHERE id=?", (i,))
            _log(conn, None, "purge", r["orig_path"], r["trash_path"], True)
            res["done"] += 1
            res["bytes"] += r["size"]
            d = os.path.dirname(r["trash_path"])
            if os.path.isdir(d) and os.listdir(d) == ["manifest.tsv"]:
                os.remove(os.path.join(d, "manifest.tsv"))
                os.rmdir(d)
        except Exception as e:  # noqa: BLE001
            res["errors"].append(f"{r['trash_path']}: {e}")
    conn.commit()
    return res


# ---------------------------------------------------------------- compress (7z / zip)
def sevenzip_exe():
    for n in ("7z", "7zz", "7za"):
        p = shutil.which(n)
        if p:
            return p
    return None


def _run_archiver(cmd, cwd, cancel, on_pct=None):
    """Run a command at low priority; poll so a Cancel can stop it. on_pct(0-100) is called as the archiver reports progress.
    Returns (returncode, last output line)."""
    import re
    import subprocess
    import threading
    proc = subprocess.Popen(["nice", "-n", "19"] + cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    buf = []

    def reader():
        tail = b""
        while True:
            chunk = os.read(proc.stdout.fileno(), 4096)
            if not chunk:
                break
            buf.append(chunk)
            tail = (tail + chunk)[-64:]
            m = re.findall(rb"(\d{1,3})%", tail)
            if m and on_pct:
                try:
                    on_pct(min(100, int(m[-1])))
                except Exception:  # noqa: BLE001
                    pass

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    while proc.poll() is None:
        if cancel():
            proc.kill()
            proc.wait()
            raise InterruptedError("cancelled")
        time.sleep(0.5)
    t.join(2)
    out = b"".join(buf).decode("utf-8", "replace").replace("\r", "\n")
    lines = [l.strip() for l in out.splitlines() if l.strip() and "%" not in l[:8]]
    return proc.returncode, (lines[-1] if lines else "")


def compress_file(path, size, fmt, level, cancel, progress=None):
    """Make <file>.7z or <file>.zip next to the file, test it, and return (archive_path, archive_size).
    Raises ValueError (with a plain reason) when nothing useful was made; the original is never touched here."""
    d, name = os.path.split(path)
    exe = sevenzip_exe()
    if fmt == "7z" and not exe:
        raise ValueError("7z is not installed in this container (rebuild the image to add it)")
    free = shutil.disk_usage(d).free
    if free < size * 1.05 + 50 * 1048576:
        raise ValueError("not enough free space beside the file to build the archive")
    arch = _unique(os.path.join(d, name + (".7z" if fmt == "7z" else ".zip")))
    tmp = arch + ".part"
    mx = "1" if level == "fast" else "5"
    try:
        if exe:
            kind = "7z" if fmt == "7z" else "zip"
            if progress:
                progress("compressing", None)
            rc, last = _run_archiver([exe, "a", "-t" + kind, "-mx=" + mx, "-mmt=2", "-y", "-bsp1", "-bso0", tmp, "./" + name], d, cancel,
                                     (lambda pc: progress("compressing", pc)) if progress else None)
            if rc != 0:
                raise ValueError("the archiver failed: " + (last or f"exit {rc}"))
            if progress:
                progress("testing", 0)
            rc, last = _run_archiver([exe, "t", "-t" + kind, "-bsp1", "-bso0", tmp], d, cancel,
                                     (lambda pc: progress("testing", pc)) if progress else None)
            if rc != 0:
                raise ValueError("the finished archive did not pass its test: " + (last or f"exit {rc}"))
        else:                                                   # zip without 7z installed: plain Python
            import zipfile
            if progress:
                progress("compressing", None)
            with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, compresslevel=1 if level == "fast" else 6, allowZip64=True) as z:
                z.write(path, name)
            with zipfile.ZipFile(tmp) as z:
                if z.testzip() is not None:
                    raise ValueError("the finished archive did not pass its test")
        asize = os.path.getsize(tmp)
        if asize >= size * 0.98:
            raise ValueError("no space would be saved (the file is already compressed)")
        os.replace(tmp, arch)
        try:
            st = os.stat(path)
            os.utime(arch, ns=(st.st_atime_ns, st.st_mtime_ns))
        except OSError:
            pass
        return arch, asize
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def perform_compress(conn, scan_id, fmt, level, keep, data_root, trash_name, status, cancel):
    """Compress every ticked file of a large-files scan, one at a time. status is a dict the web page polls."""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    rows = conn.execute(
        "SELECT h.id hid, h.file_id fid, h.path, h.size, h.mtime_ns FROM health h LEFT JOIN files f ON f.id=h.file_id "
        "WHERE h.scan_id=? AND h.selected=1 AND h.state='ok' AND COALESCE(f.protected,0)=0 ORDER BY h.size DESC", (scan_id,)).fetchall()
    status.update(total=len(rows), done=0, saved=0, failed=0, errors=[], current="", total_bytes=sum(r["size"] for r in rows),
                  done_bytes=0, cur_size=0, cur_phase="", cur_pct=None, started=time.time())
    for r in rows:
        if cancel():
            break
        path = r["path"]
        status["current"] = os.path.basename(path)
        status.update(cur_size=r["size"], cur_phase="starting", cur_pct=None)

        def progress(phase, pct):
            status["cur_phase"], status["cur_pct"] = phase, pct
        why, st = _lstat_ok(path, r["size"], r["mtime_ns"])
        if why:
            if why == "missing":
                conn.execute("UPDATE health SET state='missing',selected=0 WHERE id=?", (r["hid"],))
                conn.commit()
            status["failed"] += 1
            status["errors"].append(f"{path}: {why}")
            continue
        try:
            arch, asize = compress_file(path, r["size"], fmt, level, cancel, progress)
            status["cur_phase"], status["cur_pct"] = "finishing", 100
            detail = arch
            if not keep:
                tdir = os.path.join(trash_dir_for(path, data_root, trash_name), stamp)
                os.makedirs(tdir, exist_ok=True)
                tpath = os.path.join(tdir, f"{uuid.uuid4().hex[:8]}_{os.path.basename(path)}")
                shutil.move(path, tpath)
                with open(os.path.join(tdir, "manifest.tsv"), "a", encoding="utf-8") as mf:
                    mf.write(f"{os.path.basename(tpath)}\t{path}\n")
                conn.execute("INSERT INTO trash(orig_path,trash_path,size,ts) VALUES(?,?,?,?)", (path, tpath, r["size"], time.time()))
                if r["fid"]:
                    conn.execute("UPDATE files SET state='trashed',selected=0 WHERE id=?", (r["fid"],))
            conn.execute("UPDATE health SET state='compressed',selected=0,detail=? WHERE id=?",
                         (json.dumps({"archive": arch, "archive_size": asize, "kept_original": bool(keep)}), r["hid"]))
            _log(conn, scan_id, "compress", path, detail, True)
            status["done"] += 1
            status["saved"] += max(0, r["size"] - asize) if not keep else 0
        except InterruptedError:
            break
        except Exception as e:  # noqa: BLE001
            _log(conn, scan_id, "compress", path, str(e), False)
            status["failed"] += 1
            if len(status["errors"]) < 100:
                status["errors"].append(f"{path}: {e}")
        status["done_bytes"] += r["size"]
        status.update(cur_size=0, cur_phase="", cur_pct=None)
        conn.commit()
    conn.commit()
    status["current"] = ""

