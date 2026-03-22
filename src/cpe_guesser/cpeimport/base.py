import time
from abc import ABC, abstractmethod


class CPEImportHandler(ABC):
    """Base class with common functionality for importing CPE data."""

    def __init__(self, rdb):
        self.rdb = rdb
        self.itemcount = 0
        self.wordcount = 0
        self.skipped = 0
        self.start_time = time.time()

    @abstractmethod
    def _parse_impl(self, filepath):
        """Subclasses implement parsing logic for their format."""
        pass

    def parse_file(self, filepath, label=""):
        """Common entry point for all handlers."""
        self.start_time = time.time()
        self.itemcount = 0
        self.wordcount = 0
        self.skipped = 0

        self._parse_impl(filepath)

        elapsed = round(time.time() - self.start_time)
        msg = f"Finished {label}: {self.itemcount} items ({self.wordcount} words)"
        if self.skipped:
            msg += f", {self.skipped} skipped"
        msg += f" in {elapsed} seconds."
        print(msg)

    def CPEExtractor(self, cpe):
        fields = cpe.split(":")
        vendor = fields[3]
        product = fields[4]
        cpeline = ":".join(fields[:5])
        return {"vendor": vendor, "product": product, "cpeline": cpeline}

    def canonize(self, value):
        return value.lower().split("_")

    def insert(self, word, cpe):
        self.rdb.sadd(f"w:{word}", cpe)
        self.rdb.zadd(f"s:{word}", {cpe: 1}, incr=True)
        self.rdb.zadd("rank:cpe", {cpe: 1}, incr=True)

    def batch_insert(self, word_cpe_pairs):
        pipe = self.rdb.pipeline()
        for word, cpe in word_cpe_pairs:
            pipe.sadd(f"w:{word}", cpe)
            pipe.zadd(f"s:{word}", {cpe: 1}, incr=True)
            pipe.zadd("rank:cpe", {cpe: 1}, incr=True)
        pipe.execute()

    def process_cpe(self, cpe):
        """Shared vendor/product → Redis word indexing logic."""
        to_insert = self.CPEExtractor(cpe=cpe)

        word_cpe_pairs = []

        for word in self.canonize(to_insert["vendor"]):
            # self.insert(word=word, cpe=to_insert["cpeline"])
            word_cpe_pairs.append((word, to_insert["cpeline"]))
            self.wordcount += 1

        for word in self.canonize(to_insert["product"]):
            # self.insert(word=word, cpe=to_insert["cpeline"])
            word_cpe_pairs.append((word, to_insert["cpeline"]))
            self.wordcount += 1

        self.batch_insert(word_cpe_pairs)

        self.itemcount += 1

        if self.itemcount % 5000 == 0:
            time_elapsed = round(time.time() - self.start_time)
            print(
                f"... {self.itemcount} items processed "
                f"({self.wordcount} words) in {time_elapsed} seconds"
            )
