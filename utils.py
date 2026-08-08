#!/usr/bin/env python3

import sys
import pathlib
from functools import cmp_to_key

basepath = pathlib.Path("walk_lists")


def cmp_time(left_k: str, right_k: str) -> int:
    left, right = (basepath / f"{path}list" for path in (left_k, right_k))
    if any(not f.exists() for f in (left, right)):
        if left.exists():
            return 1
        if right.exists():
            return -1
        return 0

    return left.lstat().st_mtime_ns - right.lstat().st_mtime_ns


def sort_timed() -> None:
    zones = sys.stdin.read().splitlines()
    zones.sort(key=cmp_to_key(cmp_time))

    for zone in zones:
        print(zone)


def main() -> None:
    funcs = {f.__name__: f for f in [sort_timed]}

    if len(sys.argv) < 2:
        return

    arg = sys.argv[1]
    if arg not in funcs:
        print("no arg given", file=sys.stderr)
        sys.exit(1)

    funcs[arg]()


if __name__ == "__main__":
    main()
