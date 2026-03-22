# -*- coding: utf-8 -*-
from typing import List, Tuple

import valkey
from dynaconf import Dynaconf

# Configuration
settings = Dynaconf(settings_files=["../config/settings.yaml"])
valkey_host = settings.get("valkey.host", "127.0.0.1")
valkey_port = settings.get("valkey.port", 6379)
valkey_db = settings.get("valkey.db", 8)


class CPEGuesser:
    def __init__(self):
        self.rdb = valkey.Valkey(
            host=valkey_host,
            port=valkey_port,
            db=valkey_db,
            decode_responses=True,
        )

    def guessCpe(self, words) -> List[Tuple[int, str]]:
        k = []
        for keyword in words:
            k.append(f"w:{keyword.lower()}")

        maxinter = len(k)
        cpes = []
        for x in reversed(range(maxinter)):
            ret = self.rdb.sinter(k[x])
            cpes.append(list(ret))  # ty:ignore[invalid-argument-type]
        result = set(cpes[0]).intersection(*cpes)

        ranked = []

        for cpe in result:
            rank = self.rdb.zrank("rank:cpe", cpe)
            ranked.append((rank, cpe))
        return sorted(ranked, reverse=True)
