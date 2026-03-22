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
        self._next_progress_report = 5000

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
        self._next_progress_report = 5000

        self._parse_impl(filepath)

        elapsed = round(time.time() - self.start_time)
        msg = f"Finished {label}: {self.itemcount} items " f"({self.wordcount} words)"
        if self.skipped:
            msg += f", {self.skipped} skipped"
        msg += f" in {elapsed} seconds."
        print(msg)

    def CPEExtractor(self, cpe):
        fields = cpe.split(":")
        if cpe.startswith("cpe:/"):
            if len(fields) < 4:
                raise ValueError(f"Invalid legacy CPE: {cpe}")
            part = fields[1].lstrip("/") or "*"
            vendor = fields[2]
            product = fields[3]
            cpeline = f"cpe:2.3:{part}:{vendor}:{product}"
        else:
            if len(fields) < 5:
                raise ValueError(f"Invalid CPE 2.3 entry: {cpe}")
            vendor = fields[3]
            product = fields[4]
            cpeline = ":".join(fields[:5])

        if not vendor or not product:
            raise ValueError(f"Invalid vendor/product tuple in CPE: {cpe}")
        return {"vendor": vendor, "product": product, "cpeline": cpeline}

    def canonize(self, value):
        return value.lower().split("_")

    def insert(self, word, cpe):
        self.rdb.sadd(f"w:{word}", cpe)
        self.rdb.zadd(f"s:{word}", {cpe: 1}, incr=True)
        self.rdb.zadd("rank:cpe", {cpe: 1}, incr=True)
        self.rdb.zadd("rank:vendor_product", {cpe: 1}, incr=True)

    def build_insert_words(self, cpe):
        to_insert = self.CPEExtractor(cpe=cpe)
        words = []
        words.extend(self.canonize(to_insert["vendor"]))
        words.extend(self.canonize(to_insert["product"]))
        return to_insert["cpeline"], words

    def process_cpe_batch(self, cpes, rdb=None):
        """Insert a batch of CPEs using a single pipeline execution."""
        if not cpes:
            return 0, 0

        client = rdb or self.rdb
        pipeline = client.pipeline(transaction=False)
        itemcount = 0
        wordcount = 0

        for cpe in cpes:
            cpeline, words = self.build_insert_words(cpe)
            for word in words:
                pipeline.sadd(f"w:{word}", cpeline)
                pipeline.zadd(f"s:{word}", {cpeline: 1}, incr=True)
                pipeline.zadd("rank:cpe", {cpeline: 1}, incr=True)
                pipeline.zadd("rank:vendor_product", {cpeline: 1}, incr=True)
                wordcount += 1
            itemcount += 1

        pipeline.execute()
        return itemcount, wordcount

    def process_rank_batch(self, cpes, rdb=None):
        """Insert only vendor/product tuple ranking data for a batch of CPEs."""
        if not cpes:
            return 0, 0

        client = rdb or self.rdb
        pipeline = client.pipeline(transaction=False)
        itemcount = 0

        for cpe in cpes:
            cpeline = self.CPEExtractor(cpe=cpe)["cpeline"]
            pipeline.zadd("rank:cpe", {cpeline: 1}, incr=True)
            pipeline.zadd("rank:vendor_product", {cpeline: 1}, incr=True)
            itemcount += 1

        pipeline.execute()
        return itemcount, 0

    def collect_missing_words(self, words, missing_word_key, rdb=None):
        """Record words that are not yet indexed in Valkey."""
        if not missing_word_key or not words:
            return 0

        client = rdb or self.rdb
        pipeline = client.pipeline(transaction=False)
        new_words = 0

        for word in words:
            if client.exists(f"w:{word}"):
                continue
            pipeline.sadd(missing_word_key, word)
            new_words += 1

        if new_words:
            pipeline.execute()
        return new_words

    def record_progress(self, itemcount, wordcount):
        self.itemcount += itemcount
        self.wordcount += wordcount

        while self.itemcount >= self._next_progress_report:
            time_elapsed = round(time.time() - self.start_time)
            print(
                f"... {self.itemcount} items processed "
                f"({self.wordcount} words) in {time_elapsed} seconds"
            )
            self._next_progress_report += 5000

    def process_cpe(self, cpe):
        """Shared vendor/product → Redis word indexing logic."""
        itemcount, wordcount = self.process_cpe_batch([cpe])
        self.record_progress(itemcount=itemcount, wordcount=wordcount)

    def create_worker_rdb(self):
        connection_pool = getattr(self.rdb, "connection_pool", None)
        connection_kwargs = getattr(connection_pool, "connection_kwargs", None)
        if not connection_kwargs:
            return self.rdb
        return self.rdb.__class__(**connection_kwargs)
