#!/usr/bin/env python3

"""Drop rows of a generated token table that another table already carries.

Both tables are included into one tokens[] array, so a (chain, address) pair
listed in both is stored twice. The duplicate must carry the same ticker and
decimals; a pair the two sources label differently stops the build.
"""

from __future__ import print_function

import re
import sys

ROW = re.compile(r'^X\((\d+), "((?:\\x[0-9A-Fa-f]{2}){20})", " ([^"]*)", (\d+)\)')


def parse(line):
    match = ROW.match(line)
    if not match:
        return None
    chain, address, ticker, decimals = match.groups()
    return (int(chain), address.lower()), (ticker, int(decimals))


def main(argv):
    if len(argv) != 3:
        print("usage: %s KEEP_DEF FILTER_DEF" % argv[0], file=sys.stderr)
        return 2
    keep = {}
    with open(argv[1]) as source:
        for line in source:
            row = parse(line)
            if row:
                keep[row[0]] = row[1]
    kept, dropped = [], 0
    with open(argv[2]) as source:
        for line in source:
            row = parse(line)
            if row and row[0] in keep:
                if keep[row[0]] != row[1]:
                    print("token %s labelled %s in %s but %s in %s" %
                          (line.split('"')[1], keep[row[0]], argv[1], row[1],
                           argv[2]), file=sys.stderr)
                    return 1
                dropped += 1
                continue
            kept.append(line)
    with open(argv[2], "w") as out:
        out.writelines(kept)
    print("%s: %d duplicate rows dropped" % (argv[2], dropped))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
