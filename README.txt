VOLCANO SENSI - latest safe source

Put the existing Info.plist you already use in the repository root (or Sources/).
The workflow copies that existing Info.plist; it does not generate or replace it.

Battery Scan:
Import CurrentPowerlog.PLSQL (and, when available, its -wal and -shm companion files)
through the Files picker. The app extracts readable strings and Bundle IDs from the
imported Powerlog database and reports heuristic indicators. It does not access
private iOS paths or bypass the iOS sandbox.
