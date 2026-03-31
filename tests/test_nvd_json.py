import io
import json
import unittest

from lib.cpeimport.nvd_json import NVDCPEHandler


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

    def dbsize(self):
        return len(self.sets) + len(self.sorted_sets)


class NVDCPEHandlerTestCase(unittest.TestCase):
    def sample_products(self):
        return [
            {
                "cpe": {
                    "cpeName": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*",
                }
            },
            {
                "cpe": {
                    "cpeName": "cpe:2.3:a:acme:rocket_launcher:2.0:*:*:*:*:*:*:*",
                }
            },
            {"cpe": {"deprecated": True}},
            {"cpe": {}},
        ]

    def test_parallel_import_batches_and_skips_entries(self):
        rdb = FakeRDB()
        handler = NVDCPEHandler(rdb, workers=2, batch_size=2)
        payload = io.StringIO(json.dumps({"products": self.sample_products()}))

        handler.process_json_file(payload)

        self.assertEqual(handler.itemcount, 2)
        self.assertEqual(handler.wordcount, 5)
        self.assertEqual(handler.skipped, 2)
        self.assertEqual(
            rdb.sets["w:acme"],
            {"cpe:2.3:a:acme:widget", "cpe:2.3:a:acme:rocket_launcher"},
        )
        self.assertEqual(rdb.sorted_sets["rank:cpe"]["cpe:2.3:a:acme:widget"], 2)
        self.assertEqual(
            rdb.sorted_sets["rank:cpe"]["cpe:2.3:a:acme:rocket_launcher"], 3
        )

    def test_serial_and_parallel_import_match(self):
        serial_rdb = FakeRDB()
        parallel_rdb = FakeRDB()
        payload = {"products": self.sample_products()}

        serial_handler = NVDCPEHandler(serial_rdb, workers=1, batch_size=1)
        serial_handler.process_json_file(io.StringIO(json.dumps(payload)))

        parallel_handler = NVDCPEHandler(parallel_rdb, workers=3, batch_size=1)
        parallel_handler.process_json_file(io.StringIO(json.dumps(payload)))

        self.assertEqual(serial_handler.itemcount, parallel_handler.itemcount)
        self.assertEqual(serial_handler.wordcount, parallel_handler.wordcount)
        self.assertEqual(serial_handler.skipped, parallel_handler.skipped)
        self.assertEqual(serial_rdb.sets, parallel_rdb.sets)
        self.assertEqual(serial_rdb.sorted_sets, parallel_rdb.sorted_sets)

    def test_import_splits_hyphenated_vendor_and_product_words(self):
        rdb = FakeRDB()
        handler = NVDCPEHandler(rdb, workers=1, batch_size=10)
        payload = io.StringIO(
            json.dumps(
                {
                    "products": [
                        {
                            "cpe": {
                                "cpeName": (
                                    "cpe:2.3:a:foo-bar:rocket-launcher:1.0:*:*:*:*:*:*:*"
                                )
                            }
                        }
                    ]
                }
            )
        )

        handler.process_json_file(payload)

        self.assertEqual(rdb.sets["w:foo"], {"cpe:2.3:a:foo-bar:rocket-launcher"})
        self.assertEqual(rdb.sets["w:bar"], {"cpe:2.3:a:foo-bar:rocket-launcher"})
        self.assertEqual(rdb.sets["w:rocket"], {"cpe:2.3:a:foo-bar:rocket-launcher"})
        self.assertEqual(rdb.sets["w:launcher"], {"cpe:2.3:a:foo-bar:rocket-launcher"})


if __name__ == "__main__":
    unittest.main()
