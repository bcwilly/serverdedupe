"""Empty-folder finder and remover.

A folder counts as empty when it holds no files at all, directly or in any subfolder. Optionally (the "junk" option)
Thumbs.db, .DS_Store, desktop.ini, ._* files and Synology's @eaDir folders are ignored, so a folder that holds only
those also counts as empty. Symlinks, folders named in the skip list (#recycle, #snapshot, .git ...) and unreadable
folders always count as content, so they are never listed or removed. The folders you pick as scan roots are never removed.
"""
import os
import shutil

import actions
import db
import ignores

JUNK_FILES = {"thumbs.db", "ehthumbs.db", ".ds_store", "desktop.ini"}
JUNK_DIRS = {"@eaDir"}


def junk_file(name):
    n = name.lower()
    return n in JUNK_FILES or n.startswith("._")


def _depth(p):
    return p.count(os.sep)


def find(sc):
    """Walk the scan roots and store every empty folder. `sc` is the running Scanner (progress, cancel, errors)."""
    p = sc.p
    junk_ok = bool(p.get("junk", True))
    patterns = [g.strip() for g in (p.get("exclude_dirs") or "").split(",") if g.strip()]
    roots = [os.path.normpath(r["path"]) for r in p["roots"] if not r.get("protected")]
    rootset = set(roots)
    info, seen, n = {}, set(), 0
    for root in roots:
        if root in sc.ignore_empty:
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False,
                                                    onerror=lambda e: sc._err(getattr(e, "filename", "?"), e)):
            sc._check()
            if dirpath in seen:
                dirnames[:] = []
                continue
            seen.add(dirpath)
            content = junk = False
            kids, keep = [], []
            for d in dirnames:
                full = os.path.join(dirpath, d)
                if os.path.islink(full):
                    content = True
                elif d in JUNK_DIRS and junk_ok:
                    junk = True                                  # ignorable, and not looked into
                elif sc._dir_excluded(d, full, patterns, None) or full in sc.ignore_empty:
                    content = True                               # #recycle, .git, or on the ignore list: leave alone, parent is not empty
                else:
                    keep.append(d)
                    kids.append(full)
            dirnames[:] = keep
            for f in filenames:
                if junk_ok and junk_file(f):
                    junk = True
                else:
                    content = True
            info[dirpath] = (content, junk, kids)
            n += 1
            if n % 200 == 0:
                sc._progress("looking for empty folders", n, 0, f"{n:,} folders checked")
    sc.file_count = n
    sc._progress("looking for empty folders", n, 0, f"{n:,} folders checked", force=True)
    empty = {}
    for path in sorted(info, key=_depth, reverse=True):          # deepest first
        content, junk, kids = info[path]
        if content or any(k not in empty for k in kids):
            continue
        empty[path] = junk or any(empty[k] for k in kids)
    rows = [(sc.scan_id, path, 1 if j else 0, _depth(path)) for path, j in empty.items() if path not in rootset]
    sc.conn.executemany("INSERT OR IGNORE INTO empties(scan_id,path,junk,depth) VALUES(?,?,?,?)", rows)
    sc.conn.commit()
    return len(rows)


def remove(conn, scan_id, params, only_selected=True, check=None):
    """rmdir the listed empty folders, deepest first. Re-checks every folder is still empty first."""
    junk_ok = bool(params.get("junk", True))
    roots = [os.path.normpath(r["path"]) for r in params["roots"] if not r.get("protected")]
    base = "SELECT id,path FROM empties WHERE scan_id=? AND state='ok'"
    rows = conn.execute(base + (" AND selected=1" if only_selected else ""), (scan_id,)).fetchall()
    chosen = {r["path"] for r in rows}
    if only_selected and chosen:      # a chosen folder takes everything listed inside it with it
        for r in conn.execute(base, (scan_id,)).fetchall():
            if any(r["path"].startswith(c + "/") for c in chosen):
                chosen.add(r["path"])
    ids = {r["path"]: r["id"] for r in conn.execute(base, (scan_id,)).fetchall()}
    res = {"done": 0, "skipped": 0, "errors": []}
    keep = ignores.folders(conn, ("empty", "all"))       # folders the user wants kept (even empty)

    def skip(path, why):
        res["skipped"] += 1
        if len(res["errors"]) < 100:
            res["errors"].append(f"{path}: {why}")

    for path in sorted(chosen, key=_depth, reverse=True):
        if check:
            check()
        if not any(path.startswith(r + "/") for r in roots):
            skip(path, "outside the scanned folders")
            continue
        if any(path == i or path.startswith(i + "/") or i.startswith(path + "/") for i in keep):
            skip(path, "is, or holds, a folder on your ignore list")
            continue
        if not os.path.lexists(path):
            conn.execute("UPDATE empties SET state='gone',selected=0 WHERE id=?", (ids[path],))
            continue
        if os.path.islink(path) or not os.path.isdir(path):
            skip(path, "not a plain folder any more")
            continue
        try:
            # Belt and braces: look through the WHOLE subtree. Any real file, symlink or unreadable folder anywhere
            # below means this folder is not empty, whatever the scan said, and it is left alone.
            bad = []
            for r, ds, fs in os.walk(path, followlinks=False, onerror=lambda x: bad.append(x)):
                if bad:
                    break
                if any(os.path.islink(os.path.join(r, d)) for d in ds):
                    bad.append(r)
                    break
                for f in fs:
                    if not (junk_ok and junk_file(f)) or os.path.islink(os.path.join(r, f)):
                        bad.append(os.path.join(r, f))
                        break
                if bad:
                    break
                ds[:] = [d for d in ds if not (junk_ok and d in JUNK_DIRS)]
            if bad:
                raise OSError("contains files or data below it, left untouched")
            leftovers = []
            for name in os.listdir(path):
                full = os.path.join(path, name)
                if junk_ok and name in JUNK_DIRS and os.path.isdir(full) and not os.path.islink(full):
                    leftovers.append((full, True))
                elif junk_ok and junk_file(name) and os.path.isfile(full) and not os.path.islink(full):
                    leftovers.append((full, False))
                else:
                    raise OSError("no longer empty")
            for full, is_dir in leftovers:
                shutil.rmtree(full) if is_dir else os.remove(full)
            os.rmdir(path)
        except OSError as e:
            skip(path, str(e))
            actions._log(conn, scan_id, "rmdir", path, str(e), False)
            continue
        conn.execute("UPDATE empties SET state='removed',selected=0 WHERE id=?", (ids[path],))
        actions._log(conn, scan_id, "rmdir", path, "", True)
        res["done"] += 1
    conn.commit()
    return res
