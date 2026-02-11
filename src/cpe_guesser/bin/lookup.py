#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json

from cpe_guesser import CPEGuesser


def main():
    parser = argparse.ArgumentParser(
        description="Find potential CPE names from a list of keyword(s) and return a JSON of the results"
    )
    parser.add_argument(
        "word",
        metavar="WORD",
        type=str,
        nargs="+",
        help="One or more keyword(s) to lookup",
    )
    parser.add_argument(
        "--unique",
        action="store_true",
        help="Return the best CPE matching the keywords given",
        default=False,
    )
    args = parser.parse_args()

    cpeGuesser = CPEGuesser()
    cpes = cpeGuesser.guessCpe(args.word)

    if not args.unique:
        print(json.dumps(cpes))
    else:
        r = []
        if len(cpes) > 0:
            if len(cpes[0]) >= 2:
                cpes = cpes[0][1]

        print(json.dumps(r))


if __name__ == "__main__":
    main()
