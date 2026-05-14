import os
import re
from dataclasses import dataclass
from typing import Iterable, List, Optional


@dataclass
class Evidence:
    file_path: str
    line_number: int
    snippet: str
    matched_text: str = ""

    # Alias for backwards compatibility
    @property
    def line(self) -> int:
        return self.line_number


@dataclass
class Finding:
    fid: str
    title: str
    severity: str
    description: str
    attack_path: str
    adb_commands: List[str]
    evidence: Optional[Evidence] = None
    references: Optional[List[str]] = None
    extra: Optional[dict] = None


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        return handle.read()


def iter_source_files(root: str) -> Iterable[str]:
    for base, _, files in os.walk(root):
        for name in files:
            if name.endswith((".java", ".kt", ".xml")):
                yield os.path.join(base, name)


def find_line_snippet(text: str, match_start: int, context: int = 2) -> Evidence:
    lines = text.splitlines()
    running = 0
    for idx, line in enumerate(lines, start=1):
        next_running = running + len(line) + 1
        if match_start < next_running:
            start = max(1, idx - context)
            end = min(len(lines), idx + context)
            snippet = "\n".join(f"{i:04d}: {lines[i-1]}" for i in range(start, end + 1))
            return Evidence(file_path="", line_number=idx, snippet=snippet)
        running = next_running
    return Evidence(file_path="", line_number=1, snippet="")


def regex_finditer(pattern: str, text: str, flags: int = 0):
    return re.finditer(pattern, text, flags)
