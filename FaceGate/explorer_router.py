"""Lightweight shell entry path: do not load Qt/OpenCV for ordinary folders."""
import ntpath
from pathlib import Path
import sqlite3


def find_protected_root(folder, database):
    database = Path(database)
    if not database.is_file():
        return None
    # Read-only: opening an ordinary folder must not create a DB or test folder.
    with sqlite3.connect(database.resolve().as_uri() + '?mode=ro', uri=True) as con:
        rows = con.execute('SELECT path FROM protected_folders').fetchall()
    selected = ntpath.normcase(ntpath.abspath(folder))
    matches = []
    for (root,) in rows:
        normalized = ntpath.normcase(ntpath.abspath(root))
        try:
            if ntpath.commonpath([selected, normalized]) == normalized:
                matches.append(root)
        except ValueError:  # Different drives.
            continue
    return max(matches, key=len) if matches else None
