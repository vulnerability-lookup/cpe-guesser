import sys
import types
import unittest

sys.modules.setdefault("valkey", types.SimpleNamespace(Valkey=object))
sys.modules.setdefault(
    "dynaconf",
    types.SimpleNamespace(
        Dynaconf=lambda *args, **kwargs: types.SimpleNamespace(get=lambda *a, **k: None)
    ),
)

from lib.cpeguesser import CPEGuesser


class FakeRDB:
    def __init__(self):
        self.sets = {}
        self.sorted_sets = {}

    def sadd(self, key, value):
        self.sets.setdefault(key, set()).add(value)

    def zadd(self, key, mapping):
        self.sorted_sets.setdefault(key, {}).update(mapping)

    def sinter(self, *keys):
        if not keys:
            return set()

        values = [self.sets.get(key, set()) for key in keys]
        if not values:
            return set()
        return set.intersection(*values)

    def zscore(self, key, member):
        return self.sorted_sets.get(key, {}).get(member)


class CPEGuesserTestCase(unittest.TestCase):
    def test_guess_cpe_combines_word_scores_and_rank_score(self):
        rdb = FakeRDB()
        widget = "cpe:2.3:a:acme:widget"
        gadget = "cpe:2.3:a:acme:gadget"

        rdb.sadd("w:acme", widget)
        rdb.sadd("w:acme", gadget)
        rdb.sadd("w:widget", widget)
        rdb.sadd("w:widget", gadget)

        rdb.zadd("s:acme", {widget: 3, gadget: 1})
        rdb.zadd("s:widget", {widget: 2, gadget: 4})
        rdb.zadd("rank:cpe", {widget: 10, gadget: 2})

        guesser = CPEGuesser(rdb=rdb)

        self.assertEqual(
            guesser.guessCpe(["Acme", "Widget"]),
            [
                (15, widget),
                (7, gadget),
            ],
        )

    def test_guess_cpe_uses_rank_score_when_word_scores_are_missing(self):
        rdb = FakeRDB()
        widget = "cpe:2.3:a:acme:widget"
        gadget = "cpe:2.3:a:acme:gadget"

        for key in ("w:acme", "w:tool"):
            rdb.sadd(key, widget)
            rdb.sadd(key, gadget)

        rdb.zadd("rank:cpe", {widget: 7, gadget: 3})

        guesser = CPEGuesser(rdb=rdb)

        self.assertEqual(
            guesser.guessCpe(["acme", "tool"]),
            [
                (7, widget),
                (3, gadget),
            ],
        )

    def test_guess_cpe_normalizes_dashes_underscores_and_spaces(self):
        rdb = FakeRDB()
        launcher = "cpe:2.3:a:acme:rocket_launcher"

        for key in ("w:acme", "w:rocket", "w:launcher"):
            rdb.sadd(key, launcher)
            rdb.zadd(f"s:{key[2:]}", {launcher: 1})

        guesser = CPEGuesser(rdb=rdb)

        self.assertEqual(guesser.guessCpe(["acme", "rocket-launcher"]), [(3, launcher)])
        self.assertEqual(guesser.guessCpe(["acme", "rocket_launcher"]), [(3, launcher)])
        self.assertEqual(guesser.guessCpe(["acme", "rocket launcher"]), [(3, launcher)])


if __name__ == "__main__":
    unittest.main()
