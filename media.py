"""Media helpers: file-type sets, metadata (ffprobe / Pillow), video frame signatures, audio fingerprints."""
import base64
import json
import os
import re
import shutil
import subprocess
import time
import unicodedata

import numpy as np

FFMPEG = os.environ.get("FFMPEG") or shutil.which("ffmpeg") or "ffmpeg"
FFPROBE = os.environ.get("FFPROBE") or shutil.which("ffprobe") or "ffprobe"

try:                                   # iPhone HEIC support if the wheel is installed
    import pillow_heif
    pillow_heif.register_heif_opener()
    HEIC = True
except Exception:                      # noqa: BLE001
    HEIC = False

IMG_EXT = {"jpg", "jpeg", "png", "bmp", "gif", "webp", "tif", "tiff"} | ({"heic", "heif"} if HEIC else set())
RAW_EXT = {"dng", "cr2", "cr3", "nef", "arw", "orf", "rw2", "raf", "pef", "srw"}
PHOTO_EXT = IMG_EXT | RAW_EXT | {"heic", "heif"}
VIDEO_EXT = {"mp4", "m4v", "mov", "avi", "mkv", "wmv", "flv", "webm", "mpg", "mpeg", "ts", "m2ts", "mts", "3gp", "vob"}
AUDIO_EXT = {"mp3", "flac", "m4a", "aac", "ogg", "oga", "opus", "wma", "wav", "aif", "aiff", "ape", "alac", "wv"}
FAMILY_EXT = {"photo": PHOTO_EXT, "video": VIDEO_EXT, "audio": AUDIO_EXT, "health": VIDEO_EXT}   # health: videos for now, photos later

# which match methods belong to which family
METHODS = {
    "regular": ["content", "name", "name_size"],
    "photo": ["content", "image"],
    "video": ["content", "video_duration", "video_similar"],
    "audio": ["content", "audio_tags", "audio_tags_dur", "audio_fp"],
    "folders": ["empty"],
    "health": ["video_health"],
    "large": ["large_files"],
}


def ext_of(path):
    return os.path.splitext(path)[1].lower().lstrip(".")


def kind_of(path):
    e = ext_of(path)
    if e in IMG_EXT:
        return "img"
    if e in VIDEO_EXT:
        return "video"
    if e in AUDIO_EXT:
        return "audio"
    return ""


def have_ffmpeg():
    return bool(shutil.which(FFPROBE) or os.path.isfile(FFPROBE)) and bool(shutil.which(FFMPEG) or os.path.isfile(FFMPEG))


# ---------------------------------------------------------------- metadata
def _num(v, cast=float):
    try:
        return cast(v)
    except (TypeError, ValueError):
        return None


def probe(path):
    """Duration, resolution, codec, bitrate and tags for a video/audio file."""
    r = subprocess.run([FFPROBE, "-v", "error", "-print_format", "json", "-show_format", "-show_streams", path],
                       capture_output=True, timeout=60)
    if r.returncode != 0:
        raise OSError("ffprobe could not read file")
    j = json.loads(r.stdout or b"{}")
    fmt = j.get("format", {})
    streams = j.get("streams", [])
    v = next((s for s in streams if s.get("codec_type") == "video" and s.get("disposition", {}).get("attached_pic") != 1), None)
    a = next((s for s in streams if s.get("codec_type") == "audio"), None)
    tags = {k.lower(): str(val) for k, val in (fmt.get("tags") or {}).items()}
    for s in (a, v):
        if s:
            for k, val in (s.get("tags") or {}).items():
                tags.setdefault(k.lower(), str(val))
    m = {"dur": _num(fmt.get("duration")) or (_num(v.get("duration")) if v else None) or (_num(a.get("duration")) if a else None),
         "br": _num(fmt.get("bit_rate"), int) or (_num(a.get("bit_rate"), int) if a else None),
         "codec": (v or a or {}).get("codec_name")}
    if v:
        m["w"], m["h"] = _num(v.get("width"), int), _num(v.get("height"), int)
    if a and v:
        m["acodec"] = a.get("codec_name")
    for k in ("artist", "title", "album"):
        if tags.get(k):
            m[k] = tags[k].strip()
    if "artist" not in m and tags.get("album_artist"):
        m["artist"] = tags["album_artist"].strip()
    return {k: v for k, v in m.items() if v is not None}


def photo_meta(path):
    from PIL import Image
    with Image.open(path) as im:
        m = {"w": im.width, "h": im.height}
        try:
            taken = im.getexif().get_ifd(0x8769).get(36867)
            if taken:
                m["taken"] = str(taken)
        except Exception:      # noqa: BLE001
            pass
    return m


def norm_text(s):
    s = unicodedata.normalize("NFKD", (s or "").casefold())
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = re.sub(r"^the\s+", "", s)
    return re.sub(r"[\W_]+", "", s)


# ---------------------------------------------------------------- video signature
FRAME_POINTS = (0.10, 0.30, 0.50, 0.70, 0.90)


def _frame_hash(px):
    v = 0
    for row in range(8):
        for c in range(8):
            v = (v << 1) | (1 if px[row * 9 + c] > px[row * 9 + c + 1] else 0)
    return "%016x" % v


def video_sig(path, dur):
    """Five 64-bit difference hashes of frames at fixed fractions of the runtime ('-' = blank/unreadable frame),
    then '|' and the same five for the mirrored picture (so a flipped copy can be recognised)."""
    out, flipped = [], []
    dur = dur or 0
    for f in FRAME_POINTS:
        t = max(0.0, dur * f)
        r = subprocess.run([FFMPEG, "-v", "error", "-ss", f"{t:.2f}", "-i", path, "-frames:v", "1", "-an", "-sn",
                            "-vf", "scale=9:8:flags=area,format=gray", "-f", "rawvideo", "-"],
                           capture_output=True, timeout=60)
        px = r.stdout
        if len(px) != 72 or max(px) == min(px):
            out.append("-")
            flipped.append("-")
            continue
        out.append(_frame_hash(px))
        flipped.append(_frame_hash(bytes(px[row * 9 + (8 - c)] for row in range(8) for c in range(9))))
    if sum(1 for x in out if x != "-") < 3:
        return None
    return ",".join(out) + "|" + ",".join(flipped)


def _sig_dist(x, y):
    ds = [(int(a, 16) ^ int(b, 16)).bit_count() for a, b in zip(x, y) if a != "-" and b != "-"]
    return sum(ds) / len(ds) if len(ds) >= 3 else None


def video_distance(a, b, mirror=False):
    """Average Hamming distance (0..64) over frames both signatures have, or None if too few to compare.
    With mirror=True, compares a against the mirrored version of b instead."""
    ao, _, _af = a.partition("|")
    bo, _, bf = b.partition("|")
    if not mirror:
        return _sig_dist(ao.split(","), bo.split(","))
    return _sig_dist(ao.split(","), bf.split(",")) if bf else None


# ---------------------------------------------------------------- audio fingerprint
SR = 5000
FR, HOP = 2048, 512
FP_LEN = 300            # frames compared (~30 s)
FP_SHIFT = 3            # +/- frames of alignment search (~0.3 s)


def audio_fp(path, dur):
    """Haitsma/Kalker-style 32-bit-per-frame spectral fingerprint of ~45 s of audio, base64 packed."""
    start = 15 if (dur or 0) > 75 else 0
    r = subprocess.run([FFMPEG, "-v", "error", "-ss", str(start), "-t", "45", "-i", path, "-vn", "-ac", "1",
                        "-ar", str(SR), "-f", "s16le", "-"], capture_output=True, timeout=180)
    pcm = np.frombuffer(r.stdout[: len(r.stdout) // 2 * 2], dtype=np.int16).astype(np.float32)
    if len(pcm) < SR * 35 or np.abs(pcm).max() < 50:
        return None
    n = 1 + (len(pcm) - FR) // HOP
    idx = np.arange(FR)[None, :] + HOP * np.arange(n)[:, None]
    spec = np.abs(np.fft.rfft(pcm[idx] * np.hanning(FR), axis=1)) ** 2
    bins = np.round(np.logspace(np.log10(300), np.log10(2000), 34) * FR / SR).astype(int)
    E = np.stack([spec[:, bins[i]:max(bins[i + 1], bins[i] + 1)].sum(1) for i in range(33)], axis=1)
    d = E[:, :-1] - E[:, 1:]
    bits = (d[1:] - d[:-1]) > 0
    words = (bits.astype(np.uint64) * (1 << np.arange(32, dtype=np.uint64))).sum(1).astype(np.uint32)
    if len(words) < FP_LEN + 2 * FP_SHIFT:
        return None
    return base64.b64encode(words.tobytes()).decode()


def fp_array(sig):
    return np.frombuffer(base64.b64decode(sig), dtype=np.uint32)


# ---------------------------------------------------------------- large files: how well will it compress?
_POOR = {"jpg", "jpeg", "png", "gif", "webp", "heic", "heif", "avif", "mp4", "m4v", "mov", "mkv", "avi", "wmv", "webm", "flv", "3gp", "mpg", "mpeg",
         "mp3", "m4a", "aac", "ogg", "opus", "flac", "wma", "zip", "7z", "rar", "gz", "bz2", "xz", "tgz", "zst", "cab", "jar", "apk", "pdf",
         "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub", "dmg"}
_GOOD = {"txt", "log", "csv", "tsv", "json", "xml", "html", "htm", "sql", "db", "sqlite", "sqlite3", "mdb", "bak", "tar", "iso", "img", "vmdk", "vhd",
         "vhdx", "vdi", "qcow2", "bmp", "wav", "aif", "aiff", "tif", "tiff", "psd", "dmp", "pst", "ost", "mbox", "eml", "dwg", "dxf", "md", "ini", "cfg"}


def shrink_hint(path):
    """('good'|'maybe'|'poor', text): a guess at how much compressing this file type will save."""
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    if ext in _GOOD:
        return "good", "Usually compresses well"
    if ext in _POOR:
        return "poor", "Already compressed: little or no saving"
    return "maybe", "May compress somewhat"


# ---------------------------------------------------------------- health check (damaged / truncated / blank video)
HEALTH_VERSION = 2


def fmt_t(t):
    t = int(round(t))
    h, m, s = t // 3600, t % 3600 // 60, t % 60
    return (f"{h}:{m:02d}" if h else str(m)) + f":{s:02d}"


def _run(cmd, timeout, check=None):
    """subprocess.run that can be cancelled: `check` is called about once a second and may raise."""
    if check is None:
        return subprocess.run(cmd, capture_output=True, timeout=timeout)
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    t0 = time.time()
    while True:
        try:
            out, err = p.communicate(timeout=1.0)
            return subprocess.CompletedProcess(cmd, p.returncode, out, err)
        except subprocess.TimeoutExpired:
            try:
                check()
                if time.time() - t0 > timeout:
                    raise subprocess.TimeoutExpired(cmd, timeout)
            except BaseException:
                p.kill()
                p.communicate()
                raise


def _sample(path, t):
    """What the picture at t seconds looks like: 'ok', 'blank' (one flat colour, usually black) or 'err' (no picture could be read)."""
    try:
        r = subprocess.run([FFMPEG, "-v", "error", "-ss", f"{max(0.0, t):.2f}", "-i", path, "-frames:v", "1", "-an", "-sn",
                            "-vf", "scale=32:18:flags=area,format=gray", "-f", "rawvideo", "-"],
                           capture_output=True, timeout=45)
    except subprocess.TimeoutExpired:
        return "err"
    px = r.stdout
    if len(px) != 32 * 18:
        return "err"
    return "blank" if max(px) - min(px) <= 8 else "ok"


def health_video(path, size, opts, check=None):
    """Check one video. Returns {"ok": True} or {"ok": False, "kind", "sev", "reason", "start", "end", "dur"}.
    kinds: unreadable, novideo, noduration, truncated (data stops early), blank_end, blank_mid, damaged_mid, tiny, decode_errors."""
    blank_secs = float(opts.get("blank_secs", 45))
    step = float(opts.get("step") or max(10.0, min(60.0, blank_secs * 0.75)))   # any blank stretch of blank_secs holds at least one sample
    quick = opts.get("mode", "quick") != "full"
    issues = []

    def bad(kind, sev, reason, **kw):
        issues.append(dict(kind=kind, sev=sev, reason=reason, **kw))

    try:
        meta = probe(path)
    except Exception:  # noqa: BLE001
        return {"ok": False, "kind": "unreadable", "sev": 3, "start": 0, "end": 0, "dur": 0,
                "reason": "Cannot be opened: the video header is damaged or the file is cut off (ffprobe could not read it)"}
    if "w" not in meta:
        return {"ok": False, "kind": "novideo", "sev": 2, "start": 0, "end": 0, "dur": meta.get("dur") or 0,
                "reason": "No video stream found in this file"}
    dur = meta.get("dur")
    if not dur or dur <= 0:
        if size > 1024 * 1024:
            return {"ok": False, "kind": "noduration", "sev": 2, "start": 0, "end": 0, "dur": 0,
                    "reason": "The header has no length. This often happens when a recording was cut off"}
        return {"ok": True}
    if dur >= 60 and size * 8 / dur < 20000:
        bad("tiny", 2, f"Only {size / 1048576:.1f} MB for {fmt_t(dur)} of video: far too small, so much of it is probably missing",
            start=0, end=dur, dur=dur)

    # --- sample frames. full: one every `step` seconds over the whole video. quick: the start, then only the last couple of minutes
    # (finds cut-off files and blank endings; where a problem begins is then found by bisecting, so quick mode is still exact)
    step = max(step, dur / 600.0)
    ts = [0.5 if dur > 1 else 0.0]
    if quick:
        window = blank_secs + 2 * step
        t = dur - 1.5
        while t > max(1.0, dur - window):
            ts.append(t)
            t -= step
    else:
        t = step
        while t < dur - 1:
            ts.append(t)
            t += step
    ts.append(max(0.0, dur - 1.5))
    ts = sorted(set(round(x, 2) for x in ts))
    st = []
    for x in ts:
        if check:
            check()
        st.append(_sample(path, x))
    n = len(ts)

    def refine(lo, hi, want_bad):
        """lo/hi bracket the change between good and bad pictures; find it to about a second."""
        for _ in range(14):
            if hi - lo <= 1.5:
                break
            mid = (lo + hi) / 2
            s_ = _sample(path, mid)
            if (s_ != "ok") == want_bad:
                hi = mid
            else:
                lo = mid
        return hi

    i = 0
    while i < n:
        if st[i] == "ok":
            i += 1
            continue
        j = i
        while j + 1 < n and st[j + 1] != "ok":
            j += 1
        at_end = j == n - 1
        a_ts = ts[i]
        b_ts = dur if at_end else ts[j + 1]
        approx = b_ts - (ts[i - 1] if i > 0 else a_ts)           # longest the bad stretch could be
        short_video = dur < blank_secs
        if (not short_video and approx >= blank_secs) or (short_video and (b_ts - a_ts) >= 0.9 * dur):
            start = refine(ts[i - 1], a_ts, True) if i > 0 else 0.0
            end = dur if at_end else refine(ts[j], b_ts, False)
            length = end - start
            if (not short_video and length >= blank_secs) or (short_video and length >= 0.9 * dur):
                errs = any(x == "err" for x in st[i:j + 1])
                pct = round(100 * length / dur)
                if at_end and errs:
                    bad("truncated", 3, f"Data stops at {fmt_t(start)}: the file says {fmt_t(dur)} but nothing can be read after that "
                        f"({fmt_t(length)} missing, {pct}%)", start=start, end=end, dur=dur)
                elif at_end:
                    bad("blank_end", 2, f"Blank (black) from {fmt_t(start)} to the end: {fmt_t(length)} of {fmt_t(dur)} ({pct}%)",
                        start=start, end=end, dur=dur)
                elif errs:
                    bad("damaged_mid", 3, f"Cannot be read from {fmt_t(start)} to {fmt_t(end)} ({fmt_t(length)})",
                        start=start, end=end, dur=dur)
                else:
                    bad("blank_mid", 1, f"Blank for {fmt_t(length)} from {fmt_t(start)} to {fmt_t(end)}",
                        start=start, end=end, dur=dur)
        i = j + 1

    # --- optional deep check: decode everything and collect errors
    if opts.get("deep"):
        try:
            r = _run([FFMPEG, "-v", "error", "-i", path, "-f", "null", "-"], max(900, dur * 6), check)
            lines = [x.strip() for x in r.stderr.decode("utf-8", "replace").splitlines() if x.strip()]
            if lines:
                bad("decode_errors", 2, f"{len(lines)} decode errors, first: {lines[0][:140]}", start=0, end=dur, dur=dur)
        except subprocess.TimeoutExpired:
            pass

    if not issues:
        return {"ok": True}
    issues.sort(key=lambda d: -d["sev"])
    top = dict(issues[0])
    if len(issues) > 1:
        top["reason"] += "  ·  also: " + "; ".join(x["reason"] for x in issues[1:])
    top["ok"] = False
    return top
