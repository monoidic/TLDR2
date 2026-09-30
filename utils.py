#!/usr/bin/env python3

import sys
import pathlib
import datetime
import os
import json
import sqlite3
import csv
import io

basepath = pathlib.Path("walk_lists")
walk_mtime_db_path = pathlib.Path("walk_mtime_db.csv")
axfr_mtime_db_path = pathlib.Path("axfr_mtime_db.csv")
nsec3_db_path = pathlib.Path("nsec3_db.csv")
db = "tldr.sqlite3"


def old_read_mtime_db(path: pathlib.Path) -> dict[str, int]:
    ret = {}
    with open(path, newline="") as fd:
        reader = csv.DictReader(fd)
        for row in reader:
            ret[row["zone"]] = int(row["timestamp"])
    return ret


def read_mtime_db(path: pathlib.Path) -> dict[str, int]:
    ret = {}
    raw = path.read_bytes().decode("utf-8")
    timestamps, zones = raw.split("\r\n\r\n")
    timestamp_map: dict[int, int] = {}

    with io.StringIO(timestamps) as fd:
        reader = csv.DictReader(fd)
        for i, row in enumerate(reader):
            timestamp_map[i + 1] = int(row["timestamp"])

    with io.StringIO(zones) as fd:
        reader = csv.DictReader(fd)
        for row in reader:
            ret[row["zone"]] = timestamp_map[int(row["timestamp"])]

    return ret


def write_mtime_db(path: pathlib.Path, d: dict[str, int]):
    timestamps_s = sorted(set(d.values()))
    timestamps_m = {timestamp: i + 1 for i, timestamp in enumerate(timestamps_s)}
    timestamps_entries = [{"timestamp": timestamp} for timestamp in timestamps_s]

    entries = [{"zone": k, "timestamp": timestamps_m[v]} for k, v in d.items()]
    entries.sort(key=lambda e: e["zone"])

    with open(path, "w", newline="") as fd:
        writer = csv.DictWriter(fd, ["timestamp"])
        writer.writeheader()
        writer.writerows(timestamps_entries)
        fd.write("\r\n")

        writer = csv.DictWriter(fd, ["zone", "timestamp"])
        writer.writeheader()
        writer.writerows(entries)


def read_nsec3_db() -> dict[str, tuple[str, int]]:
    ret = {}
    raw = nsec3_db_path.read_bytes().decode("utf-8")
    timestamps, zones = raw.split("\r\n\r\n")
    timestamp_map: dict[int, int] = {}

    with io.StringIO(timestamps) as fd:
        reader = csv.DictReader(fd)
        for i, row in enumerate(reader):
            timestamp_map[i + 1] = int(row["timestamp"])

    with io.StringIO(zones) as fd:
        reader = csv.DictReader(fd)
        for row in reader:
            ret[row["zone"]] = (row["status"], timestamp_map[int(row["timestamp"])])

    return ret


def write_nsec3_db(d: dict[str, tuple[str, int]]) -> None:
    timestamps_s = sorted(set(t[1] for t in d.values()))
    timestamps_m = {timestamp: i + 1 for i, timestamp in enumerate(timestamps_s)}
    timestamps_entries = [{"timestamp": timestamp} for timestamp in timestamps_s]

    entries = [
        {"zone": k, "status": t[0], "timestamp": timestamps_m[t[1]]}
        for k, t in d.items()
    ]
    entries.sort(key=lambda e: e["zone"])

    with open(nsec3_db_path, "w", newline="") as fd:
        writer = csv.DictWriter(fd, ["timestamp"])
        writer.writeheader()
        writer.writerows(timestamps_entries)
        fd.write("\r\n")

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
