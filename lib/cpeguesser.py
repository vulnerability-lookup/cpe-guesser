#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import valkey
import re
from dynaconf import Dynaconf

# Configuration
settings = Dynaconf(settings_files=["../config/settings.yaml"])
valkey_host = settings.get("valkey.host", "127.0.0.1")
valkey_port = settings.get("valkey.port", 6379)
valkey_db = settings.get("valkey.db", 8)


class CPEGuesser:
    def __init__(self, rdb=None):
        self.rdb = rdb or valkey.Valkey(
            host=valkey_host,
            port=valkey_port,
            db=valkey_db,
            decode_responses=True,
        )

    def _word_score(self, word, cpe):
        score = self.rdb.zscore(f"s:{word}", cpe)
        return score or 0

    def _rank_score(self, cpe):
        score = self.rdb.zscore("rank:cpe", cpe)
        return score or 0

    def _normalize_keywords(self, words):
        normalized = []
        for word in words:
            parts = [part for part in re.split(r"[\s_-]+", word.lower()) if part]
            normalized.extend(parts)
        return normalized

    def guessCpe(self, words):
        k = []
        normalized_words = self._normalize_keywords(words)
        for keyword in normalized_words:
            k.append(f"w:{keyword.lower()}")

        if not k:
            return []

        result = self.rdb.sinter(*k)
        if not result:
            return []

        ranked = []
        lowered_words = normalized_words

        for cpe in result:
            search_score = sum(self._word_score(word, cpe) for word in lowered_words)
            rank_score = self._rank_score(cpe)
            total_score = search_score + rank_score
            ranked.append((total_score, rank_score, cpe))

        return [
            (total_score, cpe) for total_score, _, cpe in sorted(ranked, reverse=True)
        ]
