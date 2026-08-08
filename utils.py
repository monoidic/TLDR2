#!/usr/bin/env python3

import sys
import pathlib
import datetime
import os
import json

basepath = pathlib.Path("walk_lists")
db_path = pathlib.Path("mtime_db.txt")


def read_mtime_db() -> dict[str, int]:
    rows = db_path.read_text().splitlines()
    rows = {t[0]: int(t[1]) for t in (row.split() for row in rows)}
    return rows


def write_mtime_db(d: dict[str, int]):
    entries = [(k, v) for k, v in d.items()]
    entries.sort()
    text = "\n".join(f"{zone} {timestamp}" for zone, timestamp in entries)

    db_path.write_text(text)


def sort_timed() -> None:
    zones = sys.stdin.read().splitlines()
    mtime_db = read_mtime_db()
    zones.sort(key=lambda z: (mtime_db[z] if z in mtime_db else 0))

    for zone in zones:
        print(zone)


def update_timed() -> None:
    zones = json.loads(os.environ["walkable"])
    mtime_db = read_mtime_db()
    now = int(datetime.datetime.now().timestamp())
    mtime_db |= {zone: now for zone in zones}
    write_mtime_db(mtime_db)


def main() -> None:
    funcs = {f.__name__: f for f in [sort_timed, update_timed]}

    if len(sys.argv) < 2:
        return

    arg = sys.argv[1]
    if arg not in funcs:
        print("no arg given", file=sys.stderr)
        sys.exit(1)

    funcs[arg]()


if __name__ == "__main__":
    main()
