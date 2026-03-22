import json
import tarfile

from .base import CPEImportHandler


class NVDCPEHandler(CPEImportHandler):
    """Handler for NVD CPE Dictionary 2.0 (JSON format)"""

    def _parse_impl(self, filepath):
        """Parse both JSON files and tar archives containing JSON files."""
        if tarfile.is_tarfile(filepath):
            self.process_tar_archive(filepath)
        elif filepath.endswith(".json"):
            with open(filepath, "r", encoding="utf-8") as f:
                self.process_json_file(f)
        else:
            raise ValueError(f"Unsupported file type: {filepath}")

    def process_tar_archive(self, path):
        """Process each JSON file in a tar archive."""
        with tarfile.open(path, "r:*") as tar:
            for member in tar.getmembers():
                if member.isfile() and member.name.endswith(".json"):
                    print(f"{self.__class__.__name__} parsing {member.name}...")
                    extracted = tar.extractfile(member)
                    if extracted is not None:
                        with extracted as f:
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

        for product in products:
            try:
                self.process_product(product)
            except Exception as e:
                print(f"Skipping invalid product entry: {e}")

    def process_product(self, product):
        """Process a single CPE product entry."""
        cpe_obj = product.get("cpe", {})
        if not cpe_obj or cpe_obj.get("deprecated", False):
            self.skipped += 1
            return
        cpe = cpe_obj.get("cpeName")
        if not cpe:
            return
        self.process_cpe(cpe)
