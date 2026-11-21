"""Read report XML without loading a DTD, entities or external resources."""

from xml.etree import ElementTree as ET
from xml.parsers import expat

MAX_MASSCAN_BYTES = 1024 * 1024


def read_report(stream):
    """Bound the preamble and Masscan input while preserving large Nmap reports."""
    scanner = None
    prefix = expat.ParserCreate()

    def root_start(name, attributes):
        nonlocal scanner
        if scanner is None:
            scanner = attributes.get("scanner", "")

    def check_doctype(name, system, public, has_subset):
        # Nmap emits a bare <!DOCTYPE nmaprun> in ordinary reports.
        if name != "nmaprun" or system or public or has_subset:
            raise ValueError("Unsupported XML document type")

    prefix.StartElementHandler = root_start
    prefix.StartDoctypeDeclHandler = check_doctype
    parser = ET.XMLParser()  # ElementTree does not evaluate XInclude.
    size = 0
    while chunk := stream.read(65536):
        size += len(chunk) if isinstance(chunk, bytes) else len(chunk.encode("utf-8"))
        if scanner is None:
            try:
                prefix.Parse(chunk, False)
            except expat.ExpatError as error:
                raise ET.ParseError(str(error)) from error
        if (scanner is None or scanner == "masscan") and size > MAX_MASSCAN_BYTES:
            raise ValueError("XML preamble or Masscan report exceeds 1 MiB")
        parser.feed(chunk)
    return parser.close()
