#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import sys
import urllib.error

import valkey
from dynaconf import Dynaconf

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from lib.cpeimport import CPEDownloader, CVEListV5Handler

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
        "--replace-rank",
        action="store_true",
        default=False,
        help="Delete existing rank:cpe and rank:vendor_product sorted sets before importing.",
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

    if args.replace_rank:
        removed = rdb.delete("rank:cpe", "rank:vendor_product")
        print(f"Deleted {removed} existing rank key(s) from the database.")

    handler = CVEListV5Handler(rdb)
    label = f"{handler.__class__.__name__}[{os.path.basename(cvelist_file)}]"
    print(f"Using {handler.__class__.__name__} to parse file {cvelist_file}...")
    handler.parse_file(cvelist_file, label=label)

    rank_size = rdb.zcard("rank:cpe")
    alias_size = rdb.zcard("rank:vendor_product")
    print(
        "Done! "
        f"{rank_size} vendor/product tuples stored in rank:cpe and "
        f"{alias_size} in rank:vendor_product."
    )
