#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import os
import valkey
import urllib.error
from dynaconf import Dynaconf

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from lib.cpeimport import CPEDownloader, NVDCPEHandler, XMLCPEHandler

# Configuration
settings = Dynaconf(settings_files=["../config/settings.yaml"])
cpe_path = settings.get("cpe.path", "./data/nvdcpe-2.0.tar")
cpe_source = settings.get(
    "cpe.source",
    "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz",
)
valkey_host = settings.get("valkey.host", "127.0.0.1")
valkey_port = settings.get("valkey.port", 6379)
valkey_db = settings.get("valkey.db", 8)

rdb = valkey.Valkey(host=valkey_host, port=valkey_port, db=valkey_db)


def default_worker_count():
    cpu_count = os.cpu_count() or 1
    return max(1, min(8, cpu_count))


if __name__ == "__main__":
    argparser = argparse.ArgumentParser(
        description="Initializes the Redis database with CPE dictionary."
    )
    argparser.add_argument(
        "--download",
        "-d",
        action="store_true",
        default=False,
        help="Download the CPE dictionary even if it already exists.",
    )
    argparser.add_argument(
        "--replace",
        "-r",
        action="store_true",
        default=False,
        help="Flush and repopulated the CPE database.",
    )
    argparser.add_argument(
        "--workers",
        type=int,
        default=default_worker_count(),
        help="Number of parallel workers to use for NVD JSON imports.",
    )
    argparser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="Number of products each worker processes per Redis pipeline batch.",
    )
    args = argparser.parse_args()

    if not args.replace and rdb.dbsize() > 0:
        print(f"Warning! The Redis database already has {rdb.dbsize()} keys.")
        print("Use --replace if you want to flush the database and repopulate it.")
        sys.exit(0)

    if args.download or not os.path.isfile(cpe_path):
        downloader = CPEDownloader(url=cpe_source, dest_path=cpe_path)
        try:
            cpe_file = downloader.download(force=args.download)
        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            FileNotFoundError,
            PermissionError,
        ) as e:
            sys.exit(1)

    elif os.path.isfile(cpe_path):
        print(f"Using existing file {cpe_path} ...")
        cpe_file = cpe_path

    if rdb.dbsize() > 0 and args.replace:
        print(f"Flushing {rdb.dbsize()} keys from the database...")
        rdb.flushdb()

    print("Populating the database (please be patient)...")

    _, ext = os.path.splitext(cpe_file)
    ext = ext.lower()
    if ext == ".tar" or ext == ".json":
        handler = NVDCPEHandler(
            rdb,
            workers=max(1, args.workers),
            batch_size=max(1, args.batch_size),
        )
    elif ext == ".xml":
        handler = XMLCPEHandler(rdb)
    else:
        print(f"Error! No handler for the file type of {cpe_file}")
        sys.exit(1)

    print(f"Using {handler.__class__.__name__} to parse file {cpe_file}...")
    label = f"{handler.__class__.__name__}[{os.path.basename(cpe_file)}]"
    handler.parse_file(cpe_file, label=label)

    print(f"Done! {rdb.dbsize()} keys inserted.")
