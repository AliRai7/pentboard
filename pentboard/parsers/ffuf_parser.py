"""Parser for ffuf (Fuzz Faster U Fool) output in JSON and text formats.

ffuf is a web fuzzer commonly used for directory/vhost/parameter discovery.
Output formats:
- JSON (``-of json``): Standard ``{"results": [...], "config": {...}}``
- Text (plain): ``word  [Status: 200, Size: 1234, Words: 56, Lines: 12, Duration: 10ms]``

This parser handles both. JSON is preferred since it includes the full URL
and host info.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FfufEntry:
    """A single fuzz result entry."""

    url: str = ""
    input_word: str = ""
    status: int = 0
    length: int = 0
    words: int = 0
    lines: int = 0
    content_type: str = ""
    redirect_location: str = ""
    host: str = ""
    duration_ms: int = 0


@dataclass
class FfufResult:
    """Complete ffuf scan result."""

    target_url: str = ""
    wordlist: str = ""
    method: str = "GET"
    results: list[FfufEntry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _parse_ffuf_json(content: str) -> FfufResult:
    """Parse ffuf JSON output (``-of json``).

    Expected structure::

        {
            "commandline": "...",
            "results": [{...}, ...],
            "config": {"url": "...", "wordlist": "...", "method": "..."}
        }
    """
    result = FfufResult()

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        result.errors.append(f"JSON parse error: {exc}")
        return result

    if not isinstance(data, dict):
        result.errors.append("Expected JSON object at top level")
        return result

    # Config
    config = data.get("config", {})
    if isinstance(config, dict):
        result.target_url = config.get("url", "")
        result.wordlist = config.get("wordlist", "")
        result.method = config.get("method", "GET")

    # Results
    for entry_data in data.get("results", []):
        if not isinstance(entry_data, dict):
            continue

        input_data = entry_data.get("input", {})
        input_word = ""
        if isinstance(input_data, dict):
            # Take the first input key value (usually FUZZ)
            for val in input_data.values():
                input_word = str(val)
                break

        try:
            status = int(entry_data.get("status", 0))
        except (ValueError, TypeError):
            status = 0

        try:
            length = int(entry_data.get("length", 0))
        except (ValueError, TypeError):
            length = 0

        try:
            word_count = int(entry_data.get("words", 0))
        except (ValueError, TypeError):
            word_count = 0

        try:
            line_count = int(entry_data.get("lines", 0))
        except (ValueError, TypeError):
            line_count = 0

        entry = FfufEntry(
            url=str(entry_data.get("url", "")),
            input_word=input_word,
            status=status,
            length=length,
            words=word_count,
            lines=line_count,
            content_type=str(entry_data.get("content-type", "")),
            redirect_location=str(entry_data.get("redirectlocation", "")),
            host=str(entry_data.get("host", "")),
        )
        result.results.append(entry)

    return result


def _parse_ffuf_text(output: str) -> FfufResult:
    """Parse ffuf plain text output.

    Lines look like::

        admin  [Status: 200, Size: 4521, Words: 213, Lines: 98, Duration: 12ms]
    """
    result = FfufResult()

    for line in output.splitlines():
        line = line.strip()

        # URL config
        url_match = re.match(r"::\s+URL\s+:\s+(.+)", line)
        if url_match:
            result.target_url = url_match.group(1).strip()
            continue

        # Method config
        method_match = re.match(r"::\s+Method\s+:\s+(\w+)", line)
        if method_match:
            result.method = method_match.group(1).strip()
            continue

        # Wordlist config
        wl_match = re.match(r"::\s+Wordlist\s+:\s+(?:FUZZ:\s+)?(.+)", line)
        if wl_match:
            result.wordlist = wl_match.group(1).strip()
            continue

        # Result line: word [Status: NNN, Size: NNN, Words: NNN, Lines: NNN, Duration: NNms]
        entry_match = re.match(
            r"(\S+)\s+\[Status:\s+(\d+),\s+Size:\s+(\d+)"
            r"(?:,\s+Words:\s+(\d+))?"
            r"(?:,\s+Lines:\s+(\d+))?"
            r"(?:,\s+Duration:\s+(\d+)ms)?",
            line,
        )
        if entry_match:
            input_word = entry_match.group(1)
            # Build URL from target_url template if available
            url = input_word
            if result.target_url and "FUZZ" in result.target_url:
                url = result.target_url.replace("FUZZ", input_word)

            entry = FfufEntry(
                url=url,
                input_word=input_word,
                status=int(entry_match.group(2)),
                length=int(entry_match.group(3)),
                words=int(entry_match.group(4) or 0),
                lines=int(entry_match.group(5) or 0),
                duration_ms=int(entry_match.group(6) or 0),
            )
            result.results.append(entry)

    return result


def parse_ffuf(content: str) -> FfufResult:
    """Auto-detect format and parse ffuf output.

    Tries JSON first (starts with ``{``), falls back to text parsing.
    """
    content = content.strip()
    if not content:
        return FfufResult()

    if content.startswith("{"):
        return _parse_ffuf_json(content)

    return _parse_ffuf_text(content)
