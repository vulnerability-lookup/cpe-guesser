#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import os
import sys
import urllib.error

import valkey
from dynaconf import Dynaconf
from valkey.client import Valkey

from cpe_guesser.cpeimport import CPEDownloader, NVDCPEHandler, XMLCPEHandler


def dbsize(rdb: Valkey) -> int:
    dbsize = rdb.dbsize()
    if isinstance(dbsize, int):
        return dbsize
    return 0


def main():
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
    args = argparser.parse_args()

    # Configuration
    settings = Dynaconf(settings_files=["../config/settings.yaml"])
    cpe_path = settings.get("cpe.path", "./data/nvdcpe-2.0.tar")
    cpe_source = settings.get(
        "cpe.source",
        "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz",
    )
    valkey_host = settings.get("valkey.host", "127.0.0.1")
    valkey_port = settings.get("valkey.port", 6666)
    valkey_db = settings.get("valkey.db", 8)

    rdb = valkey.Valkey(host=valkey_host, port=valkey_port, db=valkey_db)

    if not args.replace and dbsize(rdb) > 0:
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
            print(f"Error: {e}")
            sys.exit(1)

    elif os.path.isfile(cpe_path):
        print(f"Using existing file {cpe_path} ...")
        cpe_file = cpe_path

    if rdb.dbsize() > 0 and args.replace:  # ty:ignore[unsupported-operator]
        print(f"Flushing {rdb.dbsize()} keys from the database...")
        rdb.flushdb()

    print("Populating the database (please be patient)...")

    _, ext = os.path.splitext(cpe_file)
    ext = ext.lower()
    if ext == ".tar" or ext == ".json":
        handler = NVDCPEHandler(rdb)
    elif ext == ".xml":
        handler = XMLCPEHandler(rdb)
    else:
        print(f"Error! No handler for the file type of {cpe_file}")
        sys.exit(1)

    print(f"Using {handler.__class__.__name__} to parse file {cpe_file}...")
    label = f"{handler.__class__.__name__}[{os.path.basename(cpe_file)}]"
    handler.parse_file(cpe_file, label=label)

    print(f"Done! {rdb.dbsize()} keys inserted.")


if __name__ == "__main__":
    main()
