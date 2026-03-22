import xml.sax

from .base import CPEImportHandler


class XMLCPEHandler(CPEImportHandler, xml.sax.ContentHandler):
    """Handler for legacy XML CPE format."""

    def __init__(self, rdb):
        super().__init__(rdb)
        xml.sax.ContentHandler.__init__(self)
        self.record = {}
        self.refs = []
        self.title = ""
        self.title_seen = False

    def _parse_impl(self, filepath):
        parser = xml.sax.make_parser()
        parser.setContentHandler(self)
        parser.parse(filepath)

    def startElement(self, name, attrs):
        if name == "cpe-23:cpe23-item":
            self.record["cpe-23"] = attrs["name"]
        if name == "title":
            self.title_seen = True
        if name == "reference":
            self.refs.append(attrs["href"])

    def characters(self, content) -> None:
        if self.title_seen:
            self.title += content

    def endElement(self, name):
        if name == "title":
            self.record["title"] = self.title
            self.title = ""
            self.title_seen = False
        if name == "references":
            self.record["refs"] = self.refs
            self.refs = []
        if name == "cpe-item":
            self.process_cpe(self.record["cpe-23"])
            self.record = {}
