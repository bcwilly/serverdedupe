# Changelog

Newest first. The running version is shown in the page header and comes from `VERSION` in `app.py`.

- 1.6.0: new "Large files" scan type: lists the biggest files in the folders you pick (no duplicate matching), with a bar for relative size and a hint of how well each file type compresses. Remove, move, or compress them to 7z or zip (tested, then the original goes to quarantine unless you tick "Keep the original too"). 7z needs the Docker image rebuilt (the Dockerfile now installs p7zip-full); zip works without. @appdata is now skipped by default.
- 1.5.8: the deleted-files check now runs in the background on every scan when results open (no 50,000-file limit), so the page opens straight away.
- 1.5.7: results are re-checked when opened (and with a "Check for deleted files" button): files deleted outside the app drop out of the list. Scheduled jobs have a "Clear results" button that deletes the saved results but keeps the job.
- 1.5.6: scheduled jobs that auto-delete empty folders show an AUTO-DELETES tag in the Schedule list, and "N deleted automatically" in Last run.
- 1.5.5: extension lists accept commas, semicolons, spaces or "*.ext" (previously only commas, so "odt;odp" matched nothing); example placeholders added.
- 1.5.4: PDFs get a "View PDF" button in results and open in the viewer; Compare all shows the PDFs side by side (scrollable, in the browser PDF viewer).
- 1.5.3: photo copies in the viewer and Compare all show format, megapixels, bits per pixel (compression), date taken and modified date, with a "largest file" tag next to "highest resolution".
- 1.5.2: the file-details window has "Move to folder…" to move that one file to another folder on the server (the results list refreshes afterwards).
- 1.5.1: video copies in the viewer and Compare all now show codec, bitrate, audio and length, with a "highest bitrate" tag next to "highest resolution", to explain why a smaller-picture copy can be the bigger file.
- 1.5.0: permanent Ignore list (History tab): keep an empty folder forever (it, and anything inside, is never listed or removed, and its parents no longer count as empty), skip a folder in duplicate/health scans, or hide a duplicate group/pair for good. "Ignore" buttons on empty folders and duplicate groups; right-click menu can ignore the chosen folder. Applies to all scans including scheduled jobs. New file: ignores.py.
- 1.4.1: Health check is much faster: a "Quick" mode (default) checks only the start and the last couple of minutes (about 8x fewer frames on long videos), and "Full" now samples every ~34 s instead of every 15 s for a 45 s rule. Same exact start/end of the problem either way.
- 1.4.0: new "Health check" scan (videos): finds files that are unreadable, cut off, or blank (black) for 45 s+ (set it yourself) at the end or in the middle, with an optional slow full-decode check. Results show the frames before and inside the problem, whether other copies exist and look healthy, and can be quarantined or moved. Schedulable like any scan. Photos will be added later.
- 1.3.0: optional "match mirrored / sideways copies" checkbox for similar photos (mirror, 90° either way) and similar videos (mirror). Slower, so off by default; the first scan after ticking it re-fingerprints cached images/videos once.
- 1.2.7: right-click Mark menu has a "Work from folder" chooser: pick the file's folder or any folder above it for the folder / tree / outside / copies-elsewhere rules.
- 1.2.6: each group shows why it matched (exact checksum / looks the same / same name...) in the list header and in the viewer.
- 1.2.5: viewer "Compare all" (key C): every copy in the group side by side, "Keep this" under each (or press its number). Buttons split into two rows.
- 1.2.4: viewer gets a "Select all" button (key A): marks every copy in the group and moves to the next group.
- 1.2.3: viewer gets a "Keep only this" button (key K); "Mark & next" renamed.
- 1.2.2: viewer image now fits the window so the buttons are always visible; click the image (or press Z) to zoom to full size and scroll.
- 1.2.1: click a thumbnail to open a viewer: mark for removal and step to the next file (Space), unmark, previous/next file and group, keyboard shortcuts.
- 1.2.0: speed-up cache housekeeping: entries for files not seen in 30 days (CACHE_DAYS) are removed after each scan, quarantined files are kept; History shows the cache and a Clean cache now button; results show how many files were reused from the cache.
- 1.1.6: the Mark / Unmark menu and "Keep one copy in each" now run inside the database in one pass (minutes down to seconds on very large scans).
- 1.1.5: faster results screen on very large scans (covering indexes, cheaper counts), "Working…" indicator. The first start after this update builds the indexes, which can take a minute or two on a big database.
- 1.1.4: click a folder in the empty-folder list to see what is inside it and open it on the NAS.
- 1.1.3: the empty-folder tool skips folders named Drive (Synology Drive) by default.
- 1.1.2: empty-folder list shows the full path with the folder to be deleted in red.
- 1.1.1: empty-folder removal now checks the whole subtree for files before deleting anything.
- 1.1.0: empty-folder finder and remover (manual or scheduled, optional auto-remove).
- 1.0.0: scan types (regular, photo, video, audio), scheduled jobs, open-file panel, text select, remove groups, Mark/Unmark menu, all-copies-ticked warning.
