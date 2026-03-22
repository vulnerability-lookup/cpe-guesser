import json

from .base import CPEImportHandler


class CVEListV5Handler(CPEImportHandler):
    """Handler for CVE Record Format v5 NDJSON exports."""

    CPE_PREFIXES = ("cpe:2.3:", "cpe:/")

    def _parse_impl(self, path):
        if not path.endswith(".ndjson"):
            raise ValueError(f"Unsupported file type: {path}")

        with open(path, "r", encoding="utf-8") as f:
            self.process_ndjson_file(f)

    def process_ndjson_file(self, fileobj):
        for line_number, line in enumerate(fileobj, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"Skipping invalid NDJSON record on line {line_number}: {e}")
                self.skipped += 1
                continue

            cpes = self.extract_cpes(record)
            if not cpes:
                self.skipped += 1
                continue

            itemcount, wordcount = self.process_rank_batch(cpes)
            self.record_progress(itemcount=itemcount, wordcount=wordcount)

    def extract_cpes(self, record):
        cpes = set()
        self._collect_cpes(record, cpes)
        valid = []

        for cpe in cpes:
            try:
                valid.append(self.CPEExtractor(cpe)["cpeline"])
            except (IndexError, ValueError):
                self.skipped += 1

        return sorted(set(valid))

    def _collect_cpes(self, node, cpes):
        if isinstance(node, dict):
            for value in node.values():
                self._collect_cpes(value, cpes)
            return

        if isinstance(node, list):
            for item in node:
                self._collect_cpes(item, cpes)
            return

        if isinstance(node, str) and node.startswith(self.CPE_PREFIXES):
            cpes.add(node)
