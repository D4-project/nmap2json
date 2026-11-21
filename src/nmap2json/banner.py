"""Preserve received banners; optionally produce an NSE-sized display preview."""

import re

BANNER_LENGTH = 64
BANNER_SCRIPTS = {"banner", "masscan-detection"}
_ESCAPED_BYTE = re.compile(r"\\(?:x)?([0-9a-f]{2})", re.IGNORECASE)


def normalize_banner(text, script_id, limit=None):
    """Count encoded characters and keep complete escaped bytes when clipping."""
    if not isinstance(text, str) or script_id not in BANNER_SCRIPTS:
        return text
    if script_id == "banner":
        text = text.replace("\n", "")
    text = _ESCAPED_BYTE.sub(lambda match: "\\x" + match.group(1).upper(), text.strip())
    text = "".join(
        chr(byte) if 32 <= byte <= 126 else f"\\x{byte:02X}"
        for byte in text.encode("utf-8")
    )
    if limit is None or len(text) <= limit:
        return text
    result = []
    size = 0
    for token in re.findall(r"\\x[0-9A-F]{2}|.", text):
        if size + len(token) > limit - 3:
            break
        result.append(token)
        size += len(token)
    return "".join(result) + "..."
