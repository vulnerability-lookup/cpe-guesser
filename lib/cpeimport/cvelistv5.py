import json

from .base import CPEImportHandler

DEFAULT_MISSING_VENDOR_SET = "set:missing_vendors_from_cvelistv5"
DEFAULT_MISSING_PRODUCT_SET = "set:missing_products_from_cvelistv5"


def reset_rank_state(
    rdb,
    missing_vendor_key=DEFAULT_MISSING_VENDOR_SET,
    missing_product_key=DEFAULT_MISSING_PRODUCT_SET,
):
    """Delete the CVE v5 ranking keys so each import starts from a clean state."""
    return rdb.delete(
        "rank:cpe",
        "rank:vendor_product",
        missing_vendor_key,
        missing_product_key,
    )


class CVEListV5Handler(CPEImportHandler):
    """Handler for CVE Record Format v5 NDJSON exports."""

    CPE_PREFIXES = ("cpe:2.3:", "cpe:/")
    INCOMPLETE_ERROR_PREFIXES = (
        "Unterminated string",
        "Expecting value",
        "Expecting ',' delimiter",
        "Expecting ':' delimiter",
        "Expecting property name enclosed in double quotes",
    )

    def __init__(
        self,
        rdb,
        index_words=False,
        missing_vendor_key=DEFAULT_MISSING_VENDOR_SET,
        missing_product_key=DEFAULT_MISSING_PRODUCT_SET,
    ):
        super().__init__(rdb)
        self.index_words = index_words
        self.missing_vendor_key = missing_vendor_key
        self.missing_product_key = missing_product_key

    def _parse_impl(self, path):
        if not path.endswith(".ndjson"):
            raise ValueError(f"Unsupported file type: {path}")

        with open(path, "r", encoding="utf-8") as f:
            self.process_ndjson_file(f)

    def process_ndjson_file(self, fileobj):
        pending_lines = []
        pending_start = None

        for line_number, raw_line in enumerate(fileobj, start=1):
            if not raw_line.strip():
                continue

            if pending_lines:
                candidate = "".join(pending_lines) + raw_line
                record, error = self._load_record(candidate)
                if record is not None:
                    self._process_record(record)
                    pending_lines = []
                    pending_start = None
                    continue

                if self._looks_like_record_start(raw_line):
                    self._skip_invalid_record(pending_start, error)
                    pending_lines = []
                    pending_start = None
                else:
                    pending_lines.append(raw_line)
                    continue

            record, error = self._load_record(raw_line)
            if record is not None:
                self._process_record(record)
                continue

            if self._is_incomplete_record(raw_line, error):
                pending_lines = [raw_line]
                pending_start = line_number
                continue

            self._skip_invalid_record(line_number, error)

        if pending_lines:
            record, error = self._load_record("".join(pending_lines))
            if record is not None:
                self._process_record(record)
            else:
                self._skip_invalid_record(pending_start, error)

    def _process_record(self, record):
        cpes = self.extract_cpes(record)
        if not cpes:
            self.skipped += 1
            return

        vendor_words = set()
        product_words = set()
        for cpe in cpes:
            extracted = self.CPEExtractor(cpe)
            vendor_words.update(self.canonize(extracted["vendor"]))
            product_words.update(self.canonize(extracted["product"]))

        self.collect_missing_words(
            sorted(vendor_words),
            self.missing_vendor_key,
        )
        self.collect_missing_words(
            sorted(product_words),
            self.missing_product_key,
        )

        if self.index_words:
            itemcount, wordcount = self.process_cpe_batch(cpes)
        else:
            itemcount, wordcount = self.process_rank_batch(cpes)

        self.record_progress(itemcount=itemcount, wordcount=wordcount)

    def _load_record(self, payload):
        try:
            return json.loads(payload), None
        except json.JSONDecodeError as error:
            return None, error

    def _is_incomplete_record(self, payload, error):
        if error is None:
            return False
        if payload[error.pos :].strip():
            return False
        return error.msg.startswith(self.INCOMPLETE_ERROR_PREFIXES)

    def _looks_like_record_start(self, payload):
        stripped = payload.lstrip()
        return stripped.startswith("{") or stripped.startswith("[")

    def _skip_invalid_record(self, line_number, error):
        print(f"Skipping invalid NDJSON record on line {line_number}: {error}")
        self.skipped += 1

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
