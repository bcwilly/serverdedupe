"""The permanent ignore list: folders to leave alone and duplicate groups to never show again.

kind 'folder': a folder path. scope 'empty' = never listed or removed by the empty-folder scan (and the folders above it
               are not empty either), 'scan' = skipped by duplicate and health scans, 'all' = both.
kind 'group' : a set of file paths (a duplicate pair or group). Any later duplicate group made only of those files is hidden.
"""
import json
import os
import time


def norm(p):
    return os.path.normpath(p).rstrip("/") or "/"


def folders(conn, scopes):
    ph = ",".join("?" * len(scopes))
    return {r[0] for r in conn.execute(f"SELECT path FROM ignores WHERE kind='folder' AND scope IN ({ph})", tuple(scopes))}


def group_sets(conn):
    out = []
    for r in conn.execute("SELECT path FROM ignores WHERE kind='group'"):
        try:
            out.append(frozenset(json.loads(r[0])))
        except ValueError:
            pass
    return out


def add_folder(conn, path, scope, note=""):
    conn.execute("INSERT OR IGNORE INTO ignores(kind,scope,path,note,created) VALUES('folder',?,?,?,?)",
                 (scope, norm(path), note, time.time()))


def add_group(conn, paths, note=""):
    key = json.dumps(sorted(set(paths)))
    conn.execute("INSERT OR IGNORE INTO ignores(kind,scope,path,note,created) VALUES('group','scan',?,?,?)", (key, note, time.time()))


def under(path, prefixes):
    return any(path == p or path.startswith(p + "/") for p in prefixes)


def listing(conn):
    out = []
    for r in conn.execute("SELECT id,kind,scope,path,note,created FROM ignores ORDER BY created DESC"):
        d = {"id": r["id"], "kind": r["kind"], "scope": r["scope"], "note": r["note"], "created": r["created"]}
        if r["kind"] == "group":
            try:
                d["paths"] = json.loads(r["path"])
            except ValueError:
                d["paths"] = []
        else:
            d["path"] = r["path"]
        out.append(d)
    return out
