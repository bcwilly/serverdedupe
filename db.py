"""SQLite helpers for SynologyDedupe."""
import os
import sqlite3
import time

DATA_DIR = os.environ.get("APP_DATA", "/app/data")
DB_PATH = os.path.join(DATA_DIR, "dedupe.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started REAL, finished REAL,
    status TEXT, mode TEXT, params TEXT,
    phase TEXT, phase_start REAL, done INTEGER DEFAULT 0, total INTEGER DEFAULT 0,
    message TEXT, stats TEXT,
    job_id INTEGER, source TEXT
);
CREATE TABLE IF NOT EXISTS jobs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT, enabled INTEGER DEFAULT 1,
    params TEXT, schedule TEXT,
    keep_runs INTEGER DEFAULT 3,
    next_run REAL, last_run REAL, last_scan_id INTEGER,
    created REAL
);
CREATE TABLE IF NOT EXISTS files(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    path TEXT NOT NULL,
    name TEXT,
    size INTEGER,
    mtime_ns INTEGER,
    ikey TEXT,
    protected INTEGER DEFAULT 0,
    partial TEXT, hash TEXT, dhash TEXT, meta TEXT, sig TEXT,
    group_id INTEGER,
    selected INTEGER DEFAULT 0,
    state TEXT DEFAULT 'ok',
    UNIQUE(scan_id, path)
);
CREATE INDEX IF NOT EXISTS ix_files_size  ON files(scan_id, size);
CREATE INDEX IF NOT EXISTS ix_files_group ON files(scan_id, group_id);
CREATE INDEX IF NOT EXISTS ix_files_name  ON files(scan_id, name);
CREATE INDEX IF NOT EXISTS ix_files_hash  ON files(scan_id, hash);
-- covering indexes: the results screen counts groups / selected files on every click; with these the counts are
-- answered from small index pages instead of reading every (long-path) file row from disk
CREATE INDEX IF NOT EXISTS ix_files_cov_g ON files(scan_id, group_id, state, selected, size);
CREATE INDEX IF NOT EXISTS ix_files_cov_s ON files(scan_id, selected, state, size);
CREATE TABLE IF NOT EXISTS groups(
    scan_id INTEGER, id INTEGER, label TEXT, n INTEGER, wasted INTEGER,
    PRIMARY KEY(scan_id, id)
);
CREATE INDEX IF NOT EXISTS ix_groups_w ON groups(scan_id, wasted DESC);
CREATE TABLE IF NOT EXISTS empties(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER, path TEXT, junk INTEGER DEFAULT 0, depth INTEGER,
    selected INTEGER DEFAULT 0, state TEXT DEFAULT 'ok',
    UNIQUE(scan_id, path)
);
CREATE TABLE IF NOT EXISTS ignores(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT, scope TEXT, path TEXT, note TEXT, created REAL,
    UNIQUE(kind, scope, path)
);
CREATE TABLE IF NOT EXISTS health(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER, file_id INTEGER, path TEXT, size INTEGER, mtime_ns INTEGER,
    kind TEXT, sev INTEGER, reason TEXT, detail TEXT,
    selected INTEGER DEFAULT 0, state TEXT DEFAULT 'ok',
    UNIQUE(scan_id, path)
);
CREATE INDEX IF NOT EXISTS ix_health_scan ON health(scan_id, state, sev);
CREATE TABLE IF NOT EXISTS health_cache(
    path TEXT, size INTEGER, mtime_ns INTEGER, opts TEXT, result TEXT, seen REAL,
    PRIMARY KEY(path, opts)
);
CREATE TABLE IF NOT EXISTS cache(
    path TEXT PRIMARY KEY,
    size INTEGER, mtime_ns INTEGER,
    partial TEXT, hash TEXT, dhash TEXT, meta TEXT, sig TEXT
);
CREATE TABLE IF NOT EXISTS trash(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    orig_path TEXT, trash_path TEXT, size INTEGER, ts REAL,
    restored INTEGER DEFAULT 0, purged INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS action_log(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL, scan_id INTEGER, action TEXT, path TEXT, detail TEXT, ok INTEGER
);
"""


def connect(same_thread=True):
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=same_thread)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA cache_size=-16384")          # 16 MB page cache per connection
    conn.execute("PRAGMA mmap_size=268435456")         # let all connections share the OS cache for the file
    conn.execute("PRAGMA temp_store=MEMORY")
    return conn


def init():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = connect()
    conn.executescript(SCHEMA)
    have = {r[1] for r in conn.execute("PRAGMA table_info(scans)")}
    for col, typ in (("phase_start", "REAL"), ("job_id", "INTEGER"), ("source", "TEXT")):
        if col not in have:
            conn.execute(f"ALTER TABLE scans ADD COLUMN {col} {typ}")
    for t in ("files", "cache"):        # upgrade databases created by older versions
        have = {r[1] for r in conn.execute(f"PRAGMA table_info({t})")}
        for c in ("meta", "sig"):
            if c not in have:
                conn.execute(f"ALTER TABLE {t} ADD COLUMN {c} TEXT")
    have = {r[1] for r in conn.execute("PRAGMA table_info(cache)")}
    if "seen" not in have:                 # when a cached file was last seen by a scan (for housekeeping)
        conn.execute("ALTER TABLE cache ADD COLUMN seen REAL")
        conn.execute("UPDATE cache SET seen=?", (time.time(),))
    conn.execute("CREATE INDEX IF NOT EXISTS ix_cache_seen ON cache(seen)")
    # a container restart kills any running scan
    conn.execute("UPDATE scans SET status='interrupted' WHERE status IN ('running','queued')")
    conn.commit()
    conn.close()


CACHE_UPSERT = """
INSERT INTO cache(path,size,mtime_ns,partial,hash,dhash,meta,sig,seen) VALUES(?,?,?,?,?,?,?,?,strftime('%s','now'))
ON CONFLICT(path) DO UPDATE SET
  partial = COALESCE(excluded.partial, CASE WHEN cache.size=excluded.size AND cache.mtime_ns=excluded.mtime_ns THEN cache.partial END),
  hash    = COALESCE(excluded.hash,    CASE WHEN cache.size=excluded.size AND cache.mtime_ns=excluded.mtime_ns THEN cache.hash END),
  dhash   = COALESCE(excluded.dhash,   CASE WHEN cache.size=excluded.size AND cache.mtime_ns=excluded.mtime_ns THEN cache.dhash END),
  meta    = COALESCE(excluded.meta,    CASE WHEN cache.size=excluded.size AND cache.mtime_ns=excluded.mtime_ns THEN cache.meta END),
  sig     = COALESCE(excluded.sig,     CASE WHEN cache.size=excluded.size AND cache.mtime_ns=excluded.mtime_ns THEN cache.sig END),
  size=excluded.size, mtime_ns=excluded.mtime_ns
"""


def clamp_ns(v):
    """Keep a file timestamp inside SQLite's signed 64-bit range (some files carry dates past year 2262)."""
    return max(-(2 ** 63), min(2 ** 63 - 1, int(v)))


def mark_seen(conn, scan_id):
    """Refresh 'last seen' for every cached file this scan looked at."""
    conn.execute("UPDATE cache SET seen=? WHERE path IN (SELECT path FROM files WHERE scan_id=?)", (time.time(), scan_id))
    conn.execute("UPDATE health_cache SET seen=? WHERE path IN (SELECT path FROM files WHERE scan_id=?)", (time.time(), scan_id))
    conn.commit()


def prune_cache(conn, days):
    """Forget cached fingerprints for files not seen by any scan for `days` days.
    Files still waiting in the quarantine are kept (they may be restored); once purged they age out like the rest."""
    cutoff = time.time() - days * 86400
    cur = conn.execute("DELETE FROM cache WHERE COALESCE(seen,0) < ? AND path NOT IN "
                       "(SELECT orig_path FROM trash WHERE restored=0 AND purged=0)", (cutoff,))
    conn.execute("DELETE FROM health_cache WHERE COALESCE(seen,0) < ?", (cutoff,))
    conn.commit()
    return cur.rowcount
