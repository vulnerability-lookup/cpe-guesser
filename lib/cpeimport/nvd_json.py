import json
import tarfile
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import CPEImportHandler


class NVDCPEHandler(CPEImportHandler):
    """Handler for NVD CPE Dictionary 2.0 (JSON format)"""

    def __init__(self, rdb, workers=1, batch_size=1000):
        super().__init__(rdb)
        self.workers = max(1, workers)
        self.batch_size = max(1, batch_size)

    def _parse_impl(self, path):
        """Parse both JSON files and tar archives containing JSON files."""
        if tarfile.is_tarfile(path):
            self.process_tar_archive(path)
        elif path.endswith(".json"):
            with open(path, "r", encoding="utf-8") as f:
                self.process_json_file(f)
        else:
            raise ValueError(f"Unsupported file type: {path}")

    def process_tar_archive(self, path):
        """Process each JSON file in a tar archive."""
        with tarfile.open(path, "r:*") as tar:
            for member in tar.getmembers():
                if member.isfile() and member.name.endswith(".json"):
                    print(f"{self.__class__.__name__} parsing {member.name}...")
                    with tar.extractfile(member) as f:
                        self.process_json_file(f)

    def process_json_file(self, fileobj):
        """Process a single JSON file."""
        try:
            data = json.load(fileobj)
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON file: {e}")
            return

        products = data.get("products")
        if not isinstance(products, list):
            print("Warning: 'products' key missing or not a list")
            return

        if self.workers == 1:
            self.process_products_serial(products)
            return

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = [
                executor.submit(self.process_product_batch, batch)
                for batch in self.iter_product_batches(products)
            ]
            for future in as_completed(futures):
                itemcount, wordcount, skipped = future.result()
                self.skipped += skipped
                self.record_progress(itemcount=itemcount, wordcount=wordcount)

    def process_products_serial(self, products):
        for product in products:
            try:
                cpe, skipped = self.extract_cpe(product)
            except Exception as e:
                print(f"Skipping invalid product entry: {e}")
                continue

            self.skipped += skipped
            if cpe is None:
                continue

            self.process_cpe(cpe)

    def iter_product_batches(self, products):
        for idx in range(0, len(products), self.batch_size):
            yield products[idx : idx + self.batch_size]

    def process_product_batch(self, products):
        worker_rdb = self.create_worker_rdb()
        cpes = []
        skipped = 0

        for product in products:
            try:
                cpe, product_skipped = self.extract_cpe(product)
            except Exception as e:
                print(f"Skipping invalid product entry: {e}")
                continue

            skipped += product_skipped
            if cpe is not None:
                cpes.append(cpe)

        itemcount, wordcount = self.process_cpe_batch(cpes, rdb=worker_rdb)
        return itemcount, wordcount, skipped

    def extract_cpe(self, product):
        """Extract a single CPE string from a product entry."""
        cpe_obj = product.get("cpe", {})
        if not cpe_obj or cpe_obj.get("deprecated", False):
            return None, 1

        cpe = cpe_obj.get("cpeName")
        if not cpe:
            return None, 0

        return cpe, 0
