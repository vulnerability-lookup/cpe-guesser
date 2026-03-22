#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import sys
import urllib.error

import valkey
from dynaconf import Dynaconf

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from lib.cpeimport import (
    CPEDownloader,
    CVEListV5Handler,
    DEFAULT_MISSING_PRODUCT_SET,
    DEFAULT_MISSING_VENDOR_SET,
    reset_rank_state,
)

# Configuration
settings = Dynaconf(settings_files=["../config/settings.yaml"])
cvelist_path = settings.get("cvelistv5.path", "./data/cvelistv5.ndjson")
cvelist_source = settings.get(
    "cvelistv5.source", "https://vulnerability.circl.lu/dumps/cvelistv5.ndjson"
)
valkey_host = settings.get("valkey.host", "127.0.0.1")
valkey_port = settings.get("valkey.port", 6379)
valkey_db = settings.get("valkey.db", 8)

rdb = valkey.Valkey(host=valkey_host, port=valkey_port, db=valkey_db)


if __name__ == "__main__":
    argparser = argparse.ArgumentParser(
        description="Populate Valkey vendor/product tuple rankings from CVE v5 NDJSON."
    )
    argparser.add_argument(
        "--download",
        "-d",
        action="store_true",
        default=False,
        help="Force downloading the CVE v5 NDJSON even if it already exists locally.",
    )
    argparser.add_argument(
        "--preserve-rank",
        action="store_true",
        default=False,
        help=(
            "Keep existing rank:cpe, rank:vendor_product, and the missing vendor/product "
            "sets instead of resetting them before importing."
        ),
    )
    argparser.add_argument(
        "--index-words",
        action="store_true",
        default=False,
        help=(
            "Also index vendor/product words into w:<word> and s:<word> like "
            "bin/import.py does."
        ),
    )
    argparser.add_argument(
        "--missing-vendor-set",
        default=DEFAULT_MISSING_VENDOR_SET,
        help=(
            "Valkey set name used to store vendor words seen in CVE v5 CPEs that "
            "were not already present in w:<word>."
        ),
    )
    argparser.add_argument(
        "--missing-product-set",
        default=DEFAULT_MISSING_PRODUCT_SET,
        help=(
            "Valkey set name used to store product words seen in CVE v5 CPEs that "
            "were not already present in w:<word>."
        ),
    )
    args = argparser.parse_args()

    if args.download or not os.path.isfile(cvelist_path):
        downloader = CPEDownloader(url=cvelist_source, dest_path=cvelist_path)
        try:
            cvelist_file = downloader.download(force=args.download)
        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            FileNotFoundError,
            PermissionError,
        ):
            sys.exit(1)
    else:
        print(f"Using existing file {cvelist_path} ...")
        cvelist_file = cvelist_path

    if args.preserve_rank:
        print(
            "Preserving existing rank:cpe, rank:vendor_product, and "
            f"{args.missing_vendor_set}/{args.missing_product_set}."
        )
    else:
        removed = reset_rank_state(
            rdb,
            args.missing_vendor_set,
            args.missing_product_set,
        )
        print(f"Reset {removed} existing rank key(s) before importing.")

    handler = CVEListV5Handler(
        rdb,
        index_words=args.index_words,
        missing_vendor_key=args.missing_vendor_set,
        missing_product_key=args.missing_product_set,
    )
    label = f"{handler.__class__.__name__}[{os.path.basename(cvelist_file)}]"
    print(f"Using {handler.__class__.__name__} to parse file {cvelist_file}...")
    handler.parse_file(cvelist_file, label=label)

    rank_size = rdb.zcard("rank:cpe")
    alias_size = rdb.zcard("rank:vendor_product")
    missing_vendor_count = rdb.scard(args.missing_vendor_set)
    missing_product_count = rdb.scard(args.missing_product_set)
    print(
        "Done! "
        f"{rank_size} vendor/product tuples stored in rank:cpe, "
        f"{alias_size} in rank:vendor_product, "
        f"{missing_vendor_count} vendor words tracked in {args.missing_vendor_set}, "
        f"and {missing_product_count} product words tracked in {args.missing_product_set}."
    )
