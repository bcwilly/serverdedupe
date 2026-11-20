"""Scan engine: walk -> (size / partial hash / full hash | name | perceptual hash) -> groups."""
import fnmatch
import hashlib
import itertools
import json
import os
import re
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

import db
import emptyfolders
import ignores
import media

PART = 64 * 1024          # bytes hashed from head and tail for the quick pass
CHUNK = 1024 * 1024
IMG_EXT = media.IMG_EXT
MEDIA_MODES = ("video_duration", "video_similar", "audio_tags", "audio_tags_dur", "audio_fp")


class Cancelled(Exception):
    pass


def lower_priority():
    """Run at low CPU priority so DSM and other apps stay responsive (child ffmpeg processes inherit it)."""
    try:
        os.setpriority(os.PRIO_PROCESS, threading.get_native_id(), 10)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------- hashing
def sha_full(path, cancel):
    h = hashlib.sha256()
    with open(path, "rb", buffering=0) as f:
        while True:
            if cancel.is_set():
                raise Cancelled()
            b = f.read(CHUNK)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def sha_partial(path, size):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read(PART))
        f.seek(size - PART)
        h.update(f.read(PART))
    return h.hexdigest()


def _dh(img):
    """64-bit difference hash (16 hex chars) of a greyscale image, or None if it is blank."""
    from PIL import Image
    px = img.resize((9, 8), Image.Resampling.BILINEAR, reducing_gap=2.0).tobytes()
    if max(px) == min(px):
        return None
    v = 0
    for r in range(8):
        for c in range(8):
            v = (v << 1) | (1 if px[r * 9 + c] > px[r * 9 + c + 1] else 0)
    return "%016x" % v


def dhash(path):
    """("original:mirrored:rot90:rot270" hashes, or None for blank images ; metadata dict).
    The extra three let a scan match mirrored / sideways copies when that option is ticked."""
    from PIL import Image
    Image.MAX_IMAGE_PIXELS = None
    with Image.open(path) as im:
        meta = {"w": im.width, "h": im.height}
        try:
            taken = im.getexif().get_ifd(0x8769).get(36867)
            if taken:
                meta["taken"] = str(taken)
        except Exception:  # noqa: BLE001
            pass
        if im.format == "JPEG":
            im.draft("L", (256, 256))
        grey = im.convert("L")
    first = _dh(grey)
    if first is None:
        return None, meta
    T = Image.Transpose
    extra = [_dh(grey.transpose(t)) or first for t in (T.FLIP_LEFT_RIGHT, T.ROTATE_90, T.ROTATE_270)]
    return ":".join([first] + extra), meta


CACHE_DAYS = max(1, int(os.environ.get("CACHE_DAYS", "30")))   # forget cached fingerprints of files unseen this long

# ---------------------------------------------------------------- groups
class GroupWriter:
    ignore_by_path, ignored = {}, 0          # the permanent "never show this group" list, loaded by the running scan

    @classmethod
    def setup(cls, sets):
        cls.ignore_by_path, cls.ignored = {}, 0
        for st in sets:
            for path in st:
                cls.ignore_by_path.setdefault(path, []).append(st)

    def __init__(self, conn, scan_id):
        self.conn, self.sid, self.next = conn, scan_id, 1
        self.groups, self.updates = [], []

    def add(self, label, members):
        """members: list of (id, size, ikey, protected)."""
        if all(m[3] for m in members):
            return                       # reference-only group: nothing to clean
        if GroupWriter.ignore_by_path:
            ids = [m[0] for m in members]
            paths = set()
            for i in range(0, len(ids), 500):
                ch = ids[i:i + 500]
                paths.update(r[0] for r in self.conn.execute(f"SELECT path FROM files WHERE id IN ({','.join('?' * len(ch))})", ch))
            if paths and any(paths <= st for st in GroupWriter.ignore_by_path.get(next(iter(paths)), ())):
                GroupWriter.ignored += 1       # on the user's permanent ignore list
                return
        reps = {}
        for m in members:
            reps.setdefault(m[2], m)     # one entry per distinct inode
        if len(reps) < 2:
            return                       # already hardlinks of each other
        sizes = [m[1] for m in reps.values()]
        gid = self.next
        self.next += 1
        self.groups.append((self.sid, gid, label, len(members), sum(sizes) - max(sizes)))
        self.updates.extend((gid, m[0]) for m in members)
        if len(self.updates) > 5000:
            self.flush()

    def flush(self):
        if self.groups:
            self.conn.executemany("INSERT INTO groups(scan_id,id,label,n,wasted) VALUES(?,?,?,?,?)", self.groups)
            self.conn.executemany("UPDATE files SET group_id=? WHERE id=?", self.updates)
            self.conn.commit()
        self.groups, self.updates = [], []

    @property
    def count(self):
        return self.next - 1


# ---------------------------------------------------------------- scanner
class Scanner(threading.Thread):
    def __init__(self, scan_id, params, trash_name, workers=2, deadline=None):
        super().__init__(daemon=True)
        self.deadline = deadline          # epoch seconds: stop politely when a scheduled time window ends
        self.stop_reason = ""
        self.scan_id = scan_id
        self.p = params
        self.trash_name = trash_name
        self.workers = max(1, workers)
        self.cancel = threading.Event()
        self._tl = threading.local()
        self._conns = []
        self._last = 0.0
        self._phase, self._phase_start = None, 0.0
        self.errors = []
        self.err_count = 0
        self.file_count = 0
        self.dir_count = 0
        self.cache_hits = 0

    # --- bookkeeping
    def _set(self, **kw):
        cols = ",".join(f"{k}=?" for k in kw)
        self.conn.execute(f"UPDATE scans SET {cols} WHERE id=?", (*kw.values(), self.scan_id))
        self.conn.commit()

    def _progress(self, phase, done, total, message="", force=False):
        now = time.time()
        if phase != self._phase:                       # new phase: remember when it began (for rate / ETA)
            self._phase, self._phase_start, force = phase, now, True
        if not force and now - self._last < 0.4:
            return
        self._last = now
        self._set(phase=phase, done=done, total=total, message=message, phase_start=self._phase_start)

    def _err(self, path, exc):
        self.err_count += 1
        if len(self.errors) < 50:
            self.errors.append(f"{path}: {exc}")

    def _check(self):
        if self.cancel.is_set():
            raise Cancelled()
        if self.deadline and time.time() > self.deadline:
            self.stop_reason = "Stopped when the scheduled time window ended. Work already done is cached, so the next run continues faster."
            raise Cancelled()

    def _rconn(self):
        c = getattr(self._tl, "c", None)
        if c is None:
            c = db.connect(same_thread=False)   # worker threads open it, the scan thread closes it
            self._tl.c = c
            self._conns.append(c)
        return c

    # --- main
    def run(self):
        lower_priority()
        t0 = time.time()
        self.conn = db.connect()
        self.ignore_dirs = ignores.folders(self.conn, ("scan", "all"))      # skipped by duplicate / health scans
        self.ignore_empty = ignores.folders(self.conn, ("empty", "all"))    # kept by the empty-folder scan
        GroupWriter.setup(ignores.group_sets(self.conn))
        status, msg = "done", ""
        groups = removed = 0
        try:
            self._set(status="running")
            mode = self.p["mode"]
            if self.p.get("family") == "folders":
                groups = emptyfolders.find(self)
                if self.p.get("auto_remove") and groups:
                    self._check()
                    self._progress("removing empty folders", 0, groups, force=True)
                    r = emptyfolders.remove(self.conn, self.scan_id, self.p, only_selected=False, check=self._check)
                    removed = r["done"]
                    for e in r["errors"][:20]:
                        self._err(e, "")
                mode = None
            else:
                self._walk()
            if mode == "content":
                groups = self._content()
            elif mode in ("name", "name_size"):
                groups = self._names(mode == "name_size")
            elif mode == "image":
                groups = self._images()
            elif mode == "video_health":
                groups = self._health()
            elif mode == "large_files":
                groups = self._large()
            elif mode in MEDIA_MODES:
                groups = self._media(mode)
        except Cancelled:
            status, msg = "cancelled", self.stop_reason
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            status, msg = "error", f"{type(e).__name__}: {e}"
        finally:
            stats = {"files": self.file_count, "folders": self.dir_count, "groups": groups, "removed": removed, "ignored_groups": GroupWriter.ignored, "cache_hits": self.cache_hits, "errors": self.err_count,
                     "error_samples": self.errors, "seconds": round(time.time() - t0, 1)}
            try:
                self._set(status=status, finished=time.time(), message=msg,
                          stats=json.dumps(stats), phase="finished")
                if self.p.get("family") != "folders":      # cache housekeeping; never affects the scan result
                    try:
                        db.mark_seen(self.conn, self.scan_id)
                        if status == "done":
                            db.prune_cache(self.conn, CACHE_DAYS)
                    except Exception:  # noqa: BLE001
                        traceback.print_exc()
            finally:
                for c in self._conns:
                    c.close()
                self.conn.close()

    # --- phase 1: walk
    def _dir_excluded(self, name, path, patterns, trash_paths):
        if name == self.trash_name:
            return True
        for pat in patterns:
            if fnmatch.fnmatch(name, pat):
                return True
        return False

    def _walk(self):
        p = self.p
        min_size = int(float(p.get("min_kb") or 0) * 1024)
        max_size = int(float(p["max_mb"]) * 1048576) if p.get("max_mb") else None
        split = lambda s: {e.lower().lstrip("*").lstrip(".") for e in re.split(r"[,;|\s]+", s or "") if e.strip("*. ")}
        inc, exc = split(p.get("include_ext")), split(p.get("exclude_ext"))
        base = IMG_EXT if p["mode"] == "image" else media.FAMILY_EXT.get(p.get("family", "regular"))
        if base:
            inc = (inc & base) if inc else set(base)
        patterns = [g.strip() for g in (p.get("exclude_dirs") or "").split(",") if g.strip()]
        roots = sorted(p["roots"], key=lambda r: not r.get("protected"))   # protected roots win overlaps
        visited, batch, n = set(), [], 0
        sql = ("INSERT OR IGNORE INTO files(scan_id,path,name,size,mtime_ns,ikey,protected) "
               "VALUES(?,?,?,?,?,?,?)")
        for root in roots:
            if ignores.norm(root["path"]) in self.ignore_dirs:
                continue
            prot = 1 if root.get("protected") else 0
            stack = [root["path"]]
            while stack:
                d = stack.pop()
                if d in visited:
                    continue
                visited.add(d)
                try:
                    it = os.scandir(d)
                except OSError as e:
                    self._err(d, e)
                    continue
                with it:
                    for e in it:
                        self._check()
                        try:
                            if e.is_symlink():
                                continue
                            if e.is_dir(follow_symlinks=False):
                                if not self._dir_excluded(e.name, e.path, patterns, None) and e.path not in self.ignore_dirs:
                                    stack.append(e.path)
                                continue
                            if not e.is_file(follow_symlinks=False):
                                continue
                            st = e.stat(follow_symlinks=False)
                        except OSError as ex:
                            self._err(e.path, ex)
                            continue
                        if st.st_size < min_size or (max_size and st.st_size > max_size):
                            continue
                        ext = os.path.splitext(e.name)[1].lower().lstrip(".")
                        if (inc and ext not in inc) or ext in exc:
                            continue
                        batch.append((self.scan_id, e.path, e.name.lower(), st.st_size, db.clamp_ns(st.st_mtime_ns),
                                      f"{st.st_dev}:{st.st_ino}", prot))
                        n += 1
                        if len(batch) >= 2000:
                            self.conn.executemany(sql, batch)
                            self.conn.commit()
                            batch = []
                            self._progress("scanning folders", n, 0, f"{n:,} files found  ({d})")
        if batch:
            self.conn.executemany(sql, batch)
            self.conn.commit()
        self.dir_count = len(visited)
        self.file_count = self.conn.execute("SELECT count(*) FROM files WHERE scan_id=?", (self.scan_id,)).fetchone()[0]
        self._progress("scanning folders", self.file_count, self.file_count, f"{self.file_count:,} files found", force=True)

    # --- helpers for hashing phases
    def _mk_cand(self, where, args):
        c = self.conn
        c.execute("DROP TABLE IF EXISTS temp.cand")
        c.execute("CREATE TEMP TABLE cand(id INTEGER PRIMARY KEY)")
        c.execute(f"INSERT INTO cand SELECT id FROM files WHERE scan_id=? AND ({where})", (self.scan_id, *args))
        return c.execute("SELECT count(*) FROM cand").fetchone()[0]

    def _cand_chunks(self, size=400):
        last = 0
        while True:
            rows = self.conn.execute(
                "SELECT f.id,f.path,f.size,f.mtime_ns FROM cand c JOIN files f ON f.id=c.id "
                "WHERE c.id>? ORDER BY c.id LIMIT ?", (last, size)).fetchall()
            if not rows:
                return
            last = rows[-1][0]
            yield rows

    def _pool(self, phase, total, fn, apply, slow=False):
        """Run fn over the candidate files. slow=True (ffmpeg / image work) uses tiny batches so progress moves per file."""
        done = 0
        self._progress(phase, 0, total, "starting…", force=True)
        with ThreadPoolExecutor(self.workers, initializer=lower_priority) as ex:
            for rows in self._cand_chunks(self.workers * 2 if slow else 400):
                results = []
                for n, res in enumerate(ex.map(fn, rows), 1):
                    if res[-1]:                       # error string
                        self._err(res[1], res[-1])
                    else:
                        results.append(res)
                    self._progress(phase, done + n, total, res[1])
                apply(results)
                self.conn.commit()
                done += len(rows)
                self._progress(phase, done, total, rows[-1][1])
        self._progress(phase, total, total, "", force=True)

    def _cache(self, path, size, mtime):
        r = self._rconn().execute(
            "SELECT partial,hash,dhash,meta,sig FROM cache WHERE path=? AND size=? AND mtime_ns=?",
            (path, size, mtime)).fetchone()
        if r is not None:
            self.cache_hits += 1
        return r

    def _store(self, col_updates, cache_rows):
        for sql, rows in col_updates:
            self.conn.executemany(sql, rows)
        self.conn.executemany(db.CACHE_UPSERT, cache_rows)

    # --- exact content
    def _content(self):
        sid = self.scan_id
        total = self._mk_cand("size IN (SELECT size FROM files WHERE scan_id=? GROUP BY size HAVING count(DISTINCT ikey)>1)", (sid,))

        def quick(row):
            fid, path, size, mt = row
            try:
                self._check()
                c = self._cache(path, size, mt)
                if size <= 2 * PART:
                    h = c["hash"] if c and c["hash"] else sha_full(path, self.cancel)
                    return fid, path, size, mt, h, h, None
                p = c["partial"] if c and c["partial"] else sha_partial(path, size)
                return fid, path, size, mt, p, (c["hash"] if c else None), None
            except OSError as e:
                return fid, path, size, mt, None, None, str(e)

        def apply_quick(res):
            self._store([("UPDATE files SET partial=?,hash=? WHERE id=?", [(r[4], r[5], r[0]) for r in res])],
                        [(r[1], r[2], r[3], r[4], r[5], None, None, None) for r in res])

        self._pool("quick check (first/last 64 KB)", total, quick, apply_quick)

        total = self._mk_cand(
            "hash IS NULL AND partial IS NOT NULL AND (size,partial) IN "
            "(SELECT size,partial FROM files WHERE scan_id=? AND partial IS NOT NULL GROUP BY size,partial HAVING count(DISTINCT ikey)>1)",
            (sid,))

        def full(row):
            fid, path, size, mt = row
            try:
                c = self._cache(path, size, mt)
                h = c["hash"] if c and c["hash"] else sha_full(path, self.cancel)
                return fid, path, size, mt, h, None
            except OSError as e:
                return fid, path, size, mt, None, str(e)

        def apply_full(res):
            self._store([("UPDATE files SET hash=? WHERE id=?", [(r[4], r[0]) for r in res])],
                        [(r[1], r[2], r[3], None, r[4], None, None, None) for r in res])

        self._pool("full SHA-256 of possible duplicates", total, full, apply_full)

        self._progress("building groups", 0, 0, "", force=True)
        gw = GroupWriter(self.conn, sid)
        self._stream(gw, """
            SELECT f.id,f.size,f.ikey,f.protected,f.hash FROM files f
            JOIN (SELECT size,hash FROM files WHERE scan_id=? AND hash IS NOT NULL GROUP BY size,hash HAVING count(DISTINCT ikey)>1) d
              ON f.size=d.size AND f.hash=d.hash
            WHERE f.scan_id=? ORDER BY f.size,f.hash""", lambda r: (r[1], r[4]), lambda k: k[1][:12])
        gw.flush()
        self._enrich()
        return gw.count

    # --- by name
    def _names(self, with_size):
        gw = GroupWriter(self.conn, self.scan_id)
        if with_size:
            sql = """SELECT f.id,f.size,f.ikey,f.protected,f.name FROM files f
                     JOIN (SELECT name,size FROM files WHERE scan_id=? GROUP BY name,size HAVING count(DISTINCT ikey)>1) d
                       ON f.name=d.name AND f.size=d.size WHERE f.scan_id=? ORDER BY f.name,f.size"""
            key = lambda r: (r[4], r[1])
        else:
            sql = """SELECT f.id,f.size,f.ikey,f.protected,f.name FROM files f
                     JOIN (SELECT name FROM files WHERE scan_id=? GROUP BY name HAVING count(DISTINCT ikey)>1) d
                       ON f.name=d.name WHERE f.scan_id=? ORDER BY f.name"""
            key = lambda r: r[4]
        self._progress("building groups", 0, 0, "", force=True)
        self._stream(gw, sql, key, lambda k: k[0] if isinstance(k, tuple) else k)
        gw.flush()
        return gw.count

    def _stream(self, gw, sql, keyfunc, labelfunc):
        rconn = db.connect()
        try:
            cur = rconn.execute(sql, (self.scan_id, self.scan_id))
            for key, grp in itertools.groupby(cur, key=keyfunc):
                self._check()
                gw.add(labelfunc(key), [(r[0], r[1], r[2], r[3]) for r in grp])
        finally:
            rconn.close()

    # --- similar images
    def _images(self):
        sid = self.scan_id
        flips = bool(self.p.get("flips"))
        total = self._mk_cand("1=1", ())

        def fp(row):
            fid, path, size, mt = row
            try:
                self._check()
                c = self._cache(path, size, mt)
                if c and c["dhash"] and c["meta"] and (not flips or ":" in c["dhash"]):
                    return fid, path, size, mt, c["dhash"], c["meta"], None
                h, meta = dhash(path)
                return fid, path, size, mt, h, json.dumps(meta), None
            except Cancelled:
                raise
            except Exception as e:  # noqa: BLE001  (corrupt / unsupported image)
                return fid, path, size, mt, None, None, f"{type(e).__name__}: {e}"

        def apply_fp(res):
            self._store([("UPDATE files SET dhash=?,meta=? WHERE id=?", [(r[4], r[5], r[0]) for r in res])],
                        [(r[1], r[2], r[3], None, None, r[4], r[5], None) for r in res])

        self._pool("fingerprinting images", total, fp, apply_fp, slow=True)

        import numpy as np
        rows = self.conn.execute(
            "SELECT id,size,ikey,protected,dhash FROM files WHERE scan_id=? AND dhash IS NOT NULL", (sid,)).fetchall()
        n = len(rows)
        parts = [r[4].split(":") for r in rows]
        arr = np.array([int(x[0], 16) for x in parts], dtype=np.uint64)
        var = (np.array([[int(h, 16) for h in (x[1:4] if len(x) == 4 else [x[0]] * 3)] for x in parts], dtype=np.uint64)
               if flips and n else None)
        thr = int(self.p.get("threshold", 4))
        parent = list(range(n))
        moved = []                      # pairs that matched only after mirroring / rotating

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for i in range(n - 1):
            if i % 256 == 0:
                self._check()
                self._progress("comparing images", i, n, f"{i:,} of {n:,} images")
            d0 = np.bitwise_count(arr[i + 1:] ^ arr[i])
            d = d0
            if flips:
                d = np.minimum(d0, np.bitwise_count(var[i + 1:] ^ arr[i]).min(axis=1))
            for j in np.nonzero(d <= thr)[0]:
                a, b = find(i), find(int(j) + i + 1)
                if flips and d0[j] > thr:
                    moved.append(i)
                if a != b:
                    parent[b] = a
        clusters = {}
        for i in range(n):
            clusters.setdefault(find(i), []).append(i)
        moved_roots = {find(i) for i in moved}
        gw = GroupWriter(self.conn, sid)
        for root, members in clusters.items():
            if len(members) > 1:
                gw.add("similar images (mirrored / rotated)" if root in moved_roots else "similar images",
                       [(rows[i][0], rows[i][1], rows[i][2], rows[i][3]) for i in members])
        gw.flush()
        return gw.count

    # --- large files: the biggest files found (no matching), with a compression hint for each
    def _large(self):
        sid, top = self.scan_id, max(10, min(5000, int(self.p.get("top_n") or 500)))
        self._progress("ranking the biggest files", 0, 0, force=True)
        cand = self.conn.execute(
            "SELECT id,path,size,mtime_ns FROM files WHERE scan_id=? AND state='ok' AND id IN "
            "(SELECT min(id) FROM files WHERE scan_id=? GROUP BY COALESCE(ikey, id)) ORDER BY size DESC LIMIT ?", (sid, sid, top * 3 + 50)).fetchall()
        rows = []
        for r in cand:        # one row per real file, so a mirrored path or hardlink is listed once
            try:             # skip "files" that are mostly empty space: virtual files like /proc/kcore (128 TB) and sparse images
                st = os.lstat(r[1])
                if getattr(st, "st_blocks", None) is not None and st.st_blocks * 512 < st.st_size * 0.1:
                    continue
            except OSError:
                continue
            rows.append(r)
            if len(rows) >= top:
                break
        for fid, path, size, mt in rows:
            kind, why = media.shrink_hint(path)
            self.conn.execute("INSERT OR REPLACE INTO health(scan_id,file_id,path,size,mtime_ns,kind,sev,reason,detail) VALUES(?,?,?,?,?,?,?,?,?)",
                              (sid, fid, path, size, mt, kind, 0, why, "{}"))
        self.conn.commit()
        return len(rows)

    # --- health check: damaged / truncated / blank videos
    def _health(self):
        sid, p = self.scan_id, self.p
        bs = float(p.get("blank_secs", 45) or 45)
        opts = {"blank_secs": bs, "step": max(10.0, min(60.0, bs * 0.75)), "deep": bool(p.get("deep")),
                "mode": "full" if p.get("health_mode") == "full" else "quick"}
        key = f"{media.HEALTH_VERSION}:{bs:g}:{opts['mode']}:{int(opts['deep'])}"
        total = self._mk_cand("1=1", ())

        def fn(row):
            fid, path, size, mt = row
            try:
                self._check()
                r = self._rconn().execute("SELECT result FROM health_cache WHERE path=? AND opts=? AND size=? AND mtime_ns=?",
                                          (path, key, size, mt)).fetchone()
                if r:
                    self.cache_hits += 1
                    return fid, path, size, mt, r[0], False, None
                res = media.health_video(path, size, opts, check=self._check)
                return fid, path, size, mt, json.dumps(res), True, None
            except Cancelled:
                raise
            except Exception as e:  # noqa: BLE001
                return fid, path, size, mt, None, False, f"{type(e).__name__}: {e}"

        def apply(res):
            for fid, path, size, mt, js, fresh, _ in res:
                d = json.loads(js)
                if fresh:
                    self.conn.execute("INSERT OR REPLACE INTO health_cache(path,size,mtime_ns,opts,result,seen) VALUES(?,?,?,?,?,?)",
                                      (path, size, mt, key, js, time.time()))
                if not d.get("ok"):
                    self.conn.execute(
                        "INSERT OR REPLACE INTO health(scan_id,file_id,path,size,mtime_ns,kind,sev,reason,detail) VALUES(?,?,?,?,?,?,?,?,?)",
                        (sid, fid, path, size, mt, d.get("kind"), d.get("sev", 1), d.get("reason", ""),
                         json.dumps({k: d.get(k) for k in ("start", "end", "dur")})))

        self._pool("checking videos", total, fn, apply, slow=True)
        return self.conn.execute("SELECT count(*) FROM health WHERE scan_id=?", (sid,)).fetchone()[0]

    # --- metadata for the members of finished groups (resolution, duration, bitrate ...)
    def _enrich(self):
        if self.p.get("family", "regular") == "regular":
            return
        total = self._mk_cand("group_id IS NOT NULL", ())
        if not total:
            return

        def fn(row):
            fid, path, size, mt = row
            try:
                self._check()
                c = self._cache(path, size, mt)
                if c and c["meta"]:
                    return fid, path, size, mt, c["meta"], None
                kind = media.kind_of(path)
                m = media.photo_meta(path) if kind == "img" else media.probe(path) if kind in ("video", "audio") else {}
                return fid, path, size, mt, json.dumps(m), None
            except Cancelled:
                raise
            except Exception as e:  # noqa: BLE001
                return fid, path, size, mt, None, f"{type(e).__name__}: {e}"

        def apply(res):
            self._store([("UPDATE files SET meta=? WHERE id=?", [(r[4], r[0]) for r in res])],
                        [(r[1], r[2], r[3], None, None, None, r[4], None) for r in res])

        self._pool("reading media details", total, fn, apply, slow=True)

    # --- video / audio methods that need metadata or fingerprints
    def _media(self, mode):
        sid, p = self.scan_id, self.p
        need_sig = mode in ("video_similar", "audio_fp")
        mirror = bool(p.get("flips"))
        total = self._mk_cand("1=1", ())

        def fn(row):
            fid, path, size, mt = row
            try:
                self._check()
                c = self._cache(path, size, mt)
                meta = json.loads(c["meta"]) if c and c["meta"] else media.probe(path)
                sig = c["sig"] if c and c["sig"] else None
                if need_sig and (not sig or (mirror and mode == "video_similar" and "|" not in sig)):
                    dur = meta.get("dur")
                    sig = media.video_sig(path, dur) if mode == "video_similar" else media.audio_fp(path, dur)
                return fid, path, size, mt, json.dumps(meta), sig, None
            except Cancelled:
                raise
            except Exception as e:  # noqa: BLE001
                return fid, path, size, mt, None, None, f"{type(e).__name__}: {e}"

        def apply(res):
            self._store([("UPDATE files SET meta=?,sig=? WHERE id=?", [(r[4], r[5], r[0]) for r in res])],
                        [(r[1], r[2], r[3], None, None, None, r[4], r[5]) for r in res])

        label = {"video_similar": "fingerprinting video frames", "audio_fp": "fingerprinting audio"}.get(mode, "reading media details")
        self._pool(label, total, fn, apply, slow=True)

        rows = self.conn.execute("SELECT id,size,ikey,protected,meta,sig FROM files WHERE scan_id=? AND meta IS NOT NULL", (sid,)).fetchall()
        recs = [{"m": (r[0], r[1], r[2], r[3]), "meta": json.loads(r[4]), "sig": r[5]} for r in rows]
        tol = float(p.get("dur_tol", 2) or 0)
        parent = list(range(len(recs)))

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            a, b = find(a), find(b)
            if a != b:
                parent[b] = a

        self._progress("comparing", 0, 0, "", force=True)
        dur = lambda i: recs[i]["meta"].get("dur")

        def chain(idx):
            idx = sorted((i for i in idx if dur(i) is not None), key=dur)
            for a, b in zip(idx, idx[1:]):
                if dur(b) - dur(a) <= tol:
                    union(a, b)

        if mode == "video_duration":
            chain([i for i in range(len(recs)) if (dur(i) or 0) >= 1])
        elif mode == "video_similar":
            thr = float(p.get("vthreshold", 10))
            order = sorted((i for i in range(len(recs)) if recs[i]["sig"] and dur(i) is not None), key=dur)
            vmoved = []
            for n, i in enumerate(order):
                if n % 50 == 0:
                    self._check()
                    self._progress("comparing videos", n, len(order), f"{n:,} of {len(order):,} videos")
                for j in order[n + 1:]:
                    if dur(j) - dur(i) > tol:
                        break
                    d = media.video_distance(recs[i]["sig"], recs[j]["sig"])
                    if d is not None and d <= thr:
                        union(i, j)
                    elif mirror:
                        d2 = media.video_distance(recs[i]["sig"], recs[j]["sig"], True)
                        if d2 is not None and d2 <= thr:
                            union(i, j)
                            vmoved.append(i)
        elif mode in ("audio_tags", "audio_tags_dur"):
            bykey = {}
            for i, r in enumerate(recs):
                m = r["meta"]
                a, t = media.norm_text(m.get("artist")), media.norm_text(m.get("title"))
                if not a or not t:
                    continue
                key = (a, t, media.norm_text(m.get("album")) if p.get("include_album") else "")
                bykey.setdefault(key, []).append(i)
            for idx in bykey.values():
                if len(idx) < 2:
                    continue
                if mode == "audio_tags":
                    for k in idx[1:]:
                        union(idx[0], k)
                else:
                    chain(idx)
        elif mode == "audio_fp":
            ber = float(p.get("ber", 30)) / 100.0
            S, L = media.FP_SHIFT, media.FP_LEN
            order = sorted((i for i in range(len(recs)) if recs[i]["sig"] and dur(i) is not None), key=dur)
            import numpy as np
            A = np.stack([media.fp_array(recs[i]["sig"])[: L + 2 * S] for i in order]) if order else None
            durs = np.array([dur(i) for i in order]) if order else None
            for n in range(len(order)):
                if n % 100 == 0:
                    self._check()
                    self._progress("comparing audio", n, len(order), f"{n:,} of {len(order):,} tracks")
                hi = int(np.searchsorted(durs, durs[n] + tol, side="right"))
                if hi <= n + 1:
                    continue
                ref = A[n, S:S + L]
                best = np.full(hi - n - 1, 1.0)
                for s in range(-S, S + 1):
                    x = np.bitwise_count(A[n + 1:hi, S + s:S + s + L] ^ ref).sum(axis=1) / (32.0 * L)
                    best = np.minimum(best, x)
                for k in np.nonzero(best <= ber)[0]:
                    union(order[n], order[n + 1 + int(k)])

        clusters = {}
        for i in range(len(recs)):
            clusters.setdefault(find(i), []).append(i)
        vm_roots = {find(i) for i in vmoved} if mode == "video_similar" and mirror else set()
        gw = GroupWriter(self.conn, sid)
        for root, idx in clusters.items():
            if len(idx) < 2:
                continue
            first = recs[idx[0]]["meta"]
            if mode in ("audio_tags", "audio_tags_dur"):
                lab = f"{first.get('artist', '')} – {first.get('title', '')}"
            elif mode == "audio_fp":
                lab = "same recording"
            elif mode == "video_duration":
                lab = "same length"
            else:
                lab = "similar video (mirrored)" if root in vm_roots else "similar video"
            gw.add(lab, [recs[i]["m"] for i in idx])
        gw.flush()
        return gw.count
