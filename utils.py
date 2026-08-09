#!/usr/bin/env python3

import sys
import pathlib
import datetime
import os
import json
import sqlite3
import csv

basepath = pathlib.Path("walk_lists")
walk_mtime_db_path = pathlib.Path("walk_mtime_db.csv")
axfr_mtime_db_path = pathlib.Path("axfr_mtime_db.csv")
nsec3_db_path = pathlib.Path("nsec3_db.csv")
db = "tldr.sqlite3"


def read_mtime_db(path: pathlib.Path) -> dict[str, int]:
    ret = {}
    with open(path) as fd:
        reader = csv.DictReader(fd)
        for row in reader:
            ret[row["zone"]] = int(row["timestamp"])
    return ret


def write_mtime_db(path: pathlib.Path, d: dict[str, int]):
    entries = [{"zone": k, "timestamp": v} for k, v in d.items()]
    entries.sort(key=lambda e: e["zone"])

    with open(path, "w") as fd:
        writer = csv.DictWriter(fd, ["zone", "timestamp"])
        writer.writeheader()
        writer.writerows(entries)


def read_nsec3_db() -> dict[str, tuple[str, int]]:
    ret = {}
    with open(nsec3_db_path) as fd:
        reader = csv.DictReader(fd)
        for row in reader:
            ret[row["zone"]] = (row["status"], int(row["timestamp"]))

    return ret


def write_nsec3_db(d: dict[str, tuple[str, int]]) -> None:
    entries = [{"zone": k, "status": t[0], "timestamp": t[1]} for k, t in d.items()]
    entries.sort(key=lambda e: e["zone"])

    with open(nsec3_db_path, "w") as fd:
        writer = csv.DictWriter(fd, ["zone", "status", "timestamp"])
        writer.writeheader()
        writer.writerows(entries)


def sort_walks_by_mtimedb() -> None:
    zones = sys.stdin.read().splitlines()
    mtime_db = read_mtime_db(walk_mtime_db_path)
    zones.sort(key=lambda z: (mtime_db[z] if z in mtime_db else 0))

    for zone in zones:
        print(zone)


def update_walk_mtimedb() -> None:
    zones = json.loads(os.environ["walkable"])
    mtime_db = read_mtime_db(walk_mtime_db_path)
    now = int(datetime.datetime.now().timestamp())
    mtime_db |= {zone: now for zone in zones}
    write_mtime_db(walk_mtime_db_path, mtime_db)


def update_axfrable_mtimedb() -> None:
    with sqlite3.connect(db) as conn:
        c = conn.execute("""
            SELECT DISTINCT zone.name FROM zone_ns_ip
            INNER JOIN name AS zone ON zone_ns_ip.zone_id=zone.id
            WHERE zone_ns_ip.axfrable=TRUE
            """)
        zones = [t[0] for t in c.fetchall()]
        c.close()

    now = int(datetime.datetime.now().timestamp())
    mtime_db = read_mtime_db(axfr_mtime_db_path)
    mtime_db |= {zone: now for zone in zones}
    write_mtime_db(axfr_mtime_db_path, mtime_db)


def update_nsec3_db() -> None:
    query = """
            SELECT zone.name FROM zone_nsec_state
            INNER JOIN name AS zone ON zone_nsec_state.zone_id=zone.id
            INNER JOIN nsec_state ON zone_nsec_state.nsec_state_id=nsec_state.id
            WHERE nsec_state.name='nsec3' AND zone_nsec_state.opt_out={}
            ORDER BY zone.name
            """
    with sqlite3.connect(db) as conn:
        c = conn.execute(query.format("TRUE"))
        opt_out = [t[0] for t in c.fetchall()]
        c.close()

        c = conn.execute(query.format("FALSE"))
        no_opt_out = [t[0] for t in c.fetchall()]
        c.close()

    nsec3_db = read_nsec3_db()
    now = int(datetime.datetime.now().timestamp())
    nsec3_db |= {zone: ("opt_out", now) for zone in opt_out}
    nsec3_db |= {zone: ("no_opt_out", now) for zone in no_opt_out}
    write_nsec3_db(nsec3_db)


def main() -> None:
    funcs = [
        sort_walks_by_mtimedb,
        update_walk_mtimedb,
        update_axfrable_mtimedb,
        update_nsec3_db,
    ]
    funcs = {f.__name__: f for f in funcs}

    if len(sys.argv) < 2:
        return

    arg = sys.argv[1]
    if arg not in funcs:
        print("no arg given", file=sys.stderr)
        sys.exit(1)

    funcs[arg]()


if __name__ == "__main__":
    main()
