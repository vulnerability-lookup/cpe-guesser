import io
import json
import unittest

from lib.cpeimport.cvelistv5 import CVEListV5Handler


class FakePipeline:
    def __init__(self, rdb):
        self.rdb = rdb
        self.operations = []

    def zadd(self, key, mapping, incr=False):
        self.operations.append(("zadd", key, mapping, incr))

    def execute(self):
        for operation in self.operations:
            _, key, mapping, incr = operation
            self.rdb.zadd(key, mapping, incr=incr)
        self.operations.clear()


class FakeRDB:
    def __init__(self):
        self.sorted_sets = {}

    def pipeline(self, transaction=False):
        return FakePipeline(self)

    def zadd(self, key, mapping, incr=False):
        zset = self.sorted_sets.setdefault(key, {})
        for member, score in mapping.items():
            if incr:
                zset[member] = zset.get(member, 0) + score
            else:
                zset[member] = score


class CVEListV5HandlerTestCase(unittest.TestCase):
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
