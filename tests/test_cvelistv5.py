import io
import json
import unittest

from lib.cpeimport.cvelistv5 import CVEListV5Handler, reset_rank_state


class FakePipeline:
    def __init__(self, rdb):
        self.rdb = rdb
        self.operations = []

    def sadd(self, key, value):
        self.operations.append(("sadd", key, value))

    def zadd(self, key, mapping, incr=False):
        self.operations.append(("zadd", key, mapping, incr))

    def execute(self):
        for operation in self.operations:
            if operation[0] == "sadd":
                _, key, value = operation
                self.rdb.sadd(key, value)
            elif operation[0] == "zadd":
                _, key, mapping, incr = operation
                self.rdb.zadd(key, mapping, incr=incr)
        self.operations.clear()


class FakeRDB:
    def __init__(self):
        self.sets = {}
        self.sorted_sets = {}

    def delete(self, *keys):
        removed = 0
        for key in keys:
            removed += int(key in self.sets or key in self.sorted_sets)
            self.sets.pop(key, None)
            self.sorted_sets.pop(key, None)
        return removed

    def pipeline(self, transaction=False):
        return FakePipeline(self)

    def sadd(self, key, value):
        self.sets.setdefault(key, set()).add(value)

    def zadd(self, key, mapping, incr=False):
        zset = self.sorted_sets.setdefault(key, {})
        for member, score in mapping.items():
            if incr:
                zset[member] = zset.get(member, 0) + score
            else:
                zset[member] = score

    def exists(self, key):
        return key in self.sets or key in self.sorted_sets


class CVEListV5HandlerTestCase(unittest.TestCase):
    def test_reset_rank_state_clears_previous_import_data(self):
        rdb = FakeRDB()
        rdb.zadd("rank:cpe", {"cpe:2.3:a:acme:widget": 3})
        rdb.zadd("rank:vendor_product", {"cpe:2.3:a:acme:widget": 3})
        rdb.sadd("set:missing_words_from_cvelistv5", "widget")
        rdb.sadd("w:widget", "cpe:2.3:a:acme:widget")

        removed = reset_rank_state(rdb)

        self.assertEqual(removed, 3)
        self.assertNotIn("rank:cpe", rdb.sorted_sets)
        self.assertNotIn("rank:vendor_product", rdb.sorted_sets)
        self.assertNotIn("set:missing_words_from_cvelistv5", rdb.sets)
        self.assertIn("w:widget", rdb.sets)

    def test_extracts_cpes_from_metadata_and_configurations(self):
        record = {
            "containers": {
                "cna": {
                    "affected": [
                        {
                            "vendor": "Acme",
                            "product": "Widget",
                            "cpes": [
                                "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*",
                                "cpe:2.3:a:acme:widget:1.1:*:*:*:*:*:*:*",
                            ],
                        }
                    ]
                }
            },
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"criteria": "cpe:2.3:a:acme:gadget:*:*:*:*:*:*:*:*"},
                                {"criteria": "cpe:/a:legacy:thing:2.0"},
                            ]
                        }
                    ]
                }
            ],
        }

        handler = CVEListV5Handler(FakeRDB())
        cpes = handler.extract_cpes(record)

        self.assertEqual(
            cpes,
            [
                "cpe:2.3:a:acme:gadget",
                "cpe:2.3:a:acme:widget",
                "cpe:2.3:a:legacy:thing",
            ],
        )

    def test_process_ndjson_counts_unique_vendor_product_tuples_per_record(self):
        record_one = {
            "containers": {
                "cna": {
                    "affected": [
                        {
                            "cpes": [
                                "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*",
                                "cpe:2.3:a:acme:widget:1.1:*:*:*:*:*:*:*",
                            ]
                        }
                    ]
                }
            },
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}
                            ]
                        }
                    ]
                }
            ],
        }
        record_two = {
            "containers": {
                "adp": [
                    {
                        "affected": [
                            {
                                "cpes": [
                                    "cpe:2.3:a:acme:widget:2.0:*:*:*:*:*:*:*",
                                    "cpe:2.3:a:acme:gadget:3.0:*:*:*:*:*:*:*",
                                ]
                            }
                        ]
                    }
                ]
            }
        }
        payload = io.StringIO(
            "\n".join([json.dumps(record_one), json.dumps(record_two), "{bad json}"])
        )

        rdb = FakeRDB()
        handler = CVEListV5Handler(rdb)
        handler.process_ndjson_file(payload)

        self.assertEqual(handler.itemcount, 3)
        self.assertEqual(handler.wordcount, 0)
        self.assertEqual(handler.skipped, 1)
        self.assertEqual(rdb.sorted_sets["rank:cpe"]["cpe:2.3:a:acme:widget"], 2)
        self.assertEqual(rdb.sorted_sets["rank:cpe"]["cpe:2.3:a:acme:gadget"], 1)
        self.assertEqual(
            rdb.sorted_sets["rank:vendor_product"]["cpe:2.3:a:acme:widget"], 2
        )
        self.assertEqual(
            rdb.sets["set:missing_words_from_cvelistv5"],
            {"acme", "gadget", "widget"},
        )

    def test_index_words_adds_w_and_s_entries(self):
        record = {
            "containers": {
                "cna": {
                    "affected": [
                        {
                            "cpes": [
                                "cpe:2.3:a:acme:rocket_launcher:1.0:*:*:*:*:*:*:*",
                                "cpe:2.3:a:acme:rocket_launcher:2.0:*:*:*:*:*:*:*",
                            ]
                        }
                    ]
                }
            }
        }
        payload = io.StringIO(json.dumps(record))

        rdb = FakeRDB()
        handler = CVEListV5Handler(rdb, index_words=True)
        handler.process_ndjson_file(payload)

        self.assertEqual(handler.itemcount, 1)
        self.assertEqual(handler.wordcount, 3)
        self.assertEqual(rdb.sets["w:acme"], {"cpe:2.3:a:acme:rocket_launcher"})
        self.assertEqual(rdb.sets["w:rocket"], {"cpe:2.3:a:acme:rocket_launcher"})
        self.assertEqual(rdb.sets["w:launcher"], {"cpe:2.3:a:acme:rocket_launcher"})
        self.assertEqual(
            rdb.sorted_sets["s:rocket"]["cpe:2.3:a:acme:rocket_launcher"], 1
        )
        self.assertEqual(
            rdb.sorted_sets["rank:cpe"]["cpe:2.3:a:acme:rocket_launcher"], 3
        )

    def test_only_tracks_missing_words_absent_from_existing_index(self):
        record = {
            "containers": {
                "cna": {
                    "affected": [
                        {
                            "cpes": [
                                "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*",
                                "cpe:2.3:a:acme:gadget:1.0:*:*:*:*:*:*:*",
                            ]
                        }
                    ]
                }
            }
        }

        rdb = FakeRDB()
        rdb.sadd("w:acme", "cpe:2.3:a:acme:existing")
        rdb.sadd("w:widget", "cpe:2.3:a:acme:existing")
        handler = CVEListV5Handler(rdb)
        handler.process_ndjson_file(io.StringIO(json.dumps(record)))

        self.assertEqual(rdb.sets["set:missing_words_from_cvelistv5"], {"gadget"})

    def test_skips_single_invalid_multiline_record_and_continues(self):
        record_one = {
            "containers": {
                "cna": {
                    "affected": [{"cpes": ["cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"]}]
                }
            }
        }
        record_two = {
            "containers": {
                "cna": {
                    "affected": [{"cpes": ["cpe:2.3:a:acme:gadget:2.0:*:*:*:*:*:*:*"]}]
                }
            }
        }
        payload = io.StringIO(
            "\n".join(
                [
                    json.dumps(record_one),
                    '{"containers":{"cna":{"affected":[{"cpes":["cpe:2.3:a:broken',
                    json.dumps(record_two),
                ]
            )
        )

        rdb = FakeRDB()
        handler = CVEListV5Handler(rdb)
        handler.process_ndjson_file(payload)

        self.assertEqual(handler.itemcount, 2)
        self.assertEqual(handler.skipped, 1)
        self.assertEqual(rdb.sorted_sets["rank:cpe"]["cpe:2.3:a:acme:widget"], 1)
        self.assertEqual(rdb.sorted_sets["rank:cpe"]["cpe:2.3:a:acme:gadget"], 1)


if __name__ == "__main__":
    unittest.main()
