"""Fetch lab-exposed wordlists (robots.txt → .dic) without free-form LLM shell."""

from __future__ import annotations

from pathlib import Path

WORDLIST_SUFFIXES = (".dic", ".lst", ".wordlist")
MAX_UNIQUE_WORDS = 25000
UNIQUE_WORDLIST_NAME = "lab_wordlist.uniq.txt"


def parse_robots_paths(body: str | None) -> list[str]:
    """Extract URL paths from robots.txt, including non-standard bare filenames."""
    if not body:
        return []
    paths: list[str] = []
    seen: set[str] = set()
    skip_prefixes = ("user-agent:", "sitemap:", "comment:", "#")
    for raw in body.splitlines():
        line = raw.strip()
        if not line:
            continue
        lowered = line.lower()
        if lowered.startswith(skip_prefixes):
            continue
        if ":" in line and lowered.split(":", 1)[0] in {"disallow", "allow"}:
            token = line.split(":", 1)[1].strip().split()[0]
        else:
            token = line.split()[0]
        token = token.strip()
        if not token or token == "/":
            continue
        if not token.startswith("/"):
            token = "/" + token
        if token in seen:
            continue
        seen.add(token)
        paths.append(token)
    return paths


def wordlist_paths(robots_paths: list[str]) -> list[str]:
    out: list[str] = []
    for path in robots_paths:
        lowered = path.lower()
        if lowered.endswith(WORDLIST_SUFFIXES) or "dic" in Path(lowered).suffix:
            out.append(path)
    return out


def uniquify_wordlist(source: Path, dest: Path | None = None, *, max_lines: int = MAX_UNIQUE_WORDS) -> Path | None:
    if not source.is_file():
        return None
    dest = dest or Path(UNIQUE_WORDLIST_NAME)
    seen: set[str] = set()
    unique: list[str] = []
    with source.open(encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            word = line.strip()
            if not word or word in seen:
                continue
            seen.add(word)
            unique.append(word)
            if len(unique) >= max_lines:
                break
    if not unique:
        return None
    dest.write_text("\n".join(unique) + "\n", encoding="utf-8")
    return dest


def http_url(ip: str, port: int | None, path: str = "/") -> str:
    scheme = "https" if port in {443, 8443} else "http"
    port_part = ""
    if port and port not in {80, 443}:
        port_part = f":{port}"
    if not path.startswith("/"):
        path = "/" + path
    return f"{scheme}://{ip}{port_part}{path}"


def local_name_for_path(path: str) -> str:
    name = Path(path).name or "download.bin"
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name)
    return safe or "download.bin"
