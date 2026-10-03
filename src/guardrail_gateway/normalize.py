"""Alternative readings of content that an encoding or obfuscation may hide.

Section 10 of the design specification lists encoding and obfuscation
normalization as a layer of prompt-injection evidence. A pattern detector only
sees the characters it is given, so an instruction that is base64 encoded,
percent-encoded, spelled with look-alike letters, spaced out, or rotated reads
as noise. Each function here recovers one such reading; the detectors then
inspect every reading as well as the original.
"""

from __future__ import annotations

import base64
import codecs
import re
import unicodedata
from binascii import Error as BinasciiError
from urllib.parse import unquote

_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_BASE64URL_RUN = re.compile(r"[A-Za-z0-9_-]{20,}={0,2}")
_HEX_RUN = re.compile(r"(?:0x)?((?:[0-9A-Fa-f]{2}){10,})")
_HEX_ESCAPES = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){6,}")
_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
# Single characters separated by one space, dot, dash, or underscore.
_SPACED_LETTERS = re.compile(r"(?<![^\W_])(?:[^\W\d_][ ._-]){5,}[^\W\d_](?![^\W_])")
_SPACER = re.compile(r"[ ._-]")

# Characters that render as nothing, or reorder what is displayed.
_INVISIBLE = {
    codepoint: None
    for codepoint in (
        0x00AD,  # soft hyphen
        0x180E,
        *range(0x200B, 0x2010),  # zero-width space .. right-to-left mark
        *range(0x202A, 0x202F),  # bidirectional embedding controls
        *range(0x2060, 0x2065),  # word joiner, invisible operators
        *range(0x2066, 0x206A),  # bidirectional isolates
        0xFEFF,  # zero-width no-break space
        *range(0xE0000, 0xE0080),  # tag characters
    )
}

# Letters from other scripts that are drawn like a Latin letter, by code point.
# NFKC folds width and style variants but leaves these alone.
_CONFUSABLES: dict[int, str] = {
    # Cyrillic
    0x0430: "a",
    0x0435: "e",
    0x043E: "o",
    0x0440: "p",
    0x0441: "c",
    0x0445: "x",
    0x0443: "y",
    0x0456: "i",
    0x0458: "j",
    0x0455: "s",
    0x04BB: "h",
    0x0501: "d",
    0x051B: "q",
    0x051D: "w",
    0x0410: "A",
    0x0412: "B",
    0x0415: "E",
    0x041A: "K",
    0x041C: "M",
    0x041D: "H",
    0x041E: "O",
    0x0420: "P",
    0x0421: "C",
    0x0422: "T",
    0x0425: "X",
    0x0405: "S",
    0x0406: "I",
    0x0408: "J",
    # Greek
    0x03B1: "a",
    0x03BF: "o",
    0x03C1: "p",
    0x03BD: "v",
    0x03B9: "i",
    0x03BA: "k",
    0x03C4: "t",
    0x0391: "A",
    0x0392: "B",
    0x0395: "E",
    0x0396: "Z",
    0x0397: "H",
    0x0399: "I",
    0x039A: "K",
    0x039C: "M",
    0x039D: "N",
    0x039F: "O",
    0x03A1: "P",
    0x03A4: "T",
    0x03A5: "Y",
    0x03A7: "X",
}

_MIN_PRINTABLE_SHARE = 0.8


def alternative_readings(content: str) -> list[str]:
    """Return every distinct reading of the content other than the content itself."""

    readings: list[str] = []
    seen = {content}

    def offer(candidate: str | None) -> None:
        if candidate and candidate not in seen:
            seen.add(candidate)
            readings.append(candidate)

    offer(_without_unicode_tricks(content))
    offer(_percent_decoded(content))
    offer(_unspaced(content))
    offer(codecs.decode(content, "rot13"))
    for pattern in (_BASE64_RUN, _BASE64URL_RUN):
        for match in pattern.finditer(content):
            offer(_base64_decoded(match.group()))
    for match in _HEX_RUN.finditer(content):
        offer(_hex_decoded(match.group(1)))
    for match in _HEX_ESCAPES.finditer(content):
        offer(_hex_decoded(match.group().replace("\\x", "")))

    # One more pass over what was recovered, so a doubly wrapped payload such
    # as percent-encoded base64 is still read.
    for reading in list(readings):
        offer(_percent_decoded(reading))
        for match in _BASE64_RUN.finditer(reading):
            offer(_base64_decoded(match.group()))
    return readings


def _without_unicode_tricks(content: str) -> str:
    folded = unicodedata.normalize("NFKC", content).translate(_INVISIBLE)
    return folded.translate(_CONFUSABLES)


def _percent_decoded(content: str) -> str | None:
    if not _PERCENT_ESCAPE.search(content):
        return None
    return unquote(content)


def _unspaced(content: str) -> str | None:
    if not _SPACED_LETTERS.search(content):
        return None
    return _SPACED_LETTERS.sub(lambda match: _SPACER.sub("", match.group()), content)


def _base64_decoded(run: str) -> str | None:
    blob = run.rstrip("=").replace("-", "+").replace("_", "/")
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
    except (BinasciiError, ValueError):
        return None
    return _printable(raw)


def _hex_decoded(run: str) -> str | None:
    try:
        raw = bytes.fromhex(run)
    except ValueError:  # pragma: no cover - the pattern only admits hex pairs
        return None
    return _printable(raw)


def _printable(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    if sum(character.isprintable() for character in text) / len(text) <= _MIN_PRINTABLE_SHARE:
        return None
    return text
