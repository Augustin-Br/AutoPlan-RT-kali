"""Create missing Hydra wordlists in an authorized lab (seed + optional LLM)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from V5.runtime.command_suggest import resolve_lab_wordlist

# Generic lab seeds only — not a target-specific writeup dump.
SEED_USERS = (
    "admin",
    "administrator",
    "root",
    "user",
    "test",
    "guest",
    "wordpress",
    "elliot",
    "robot",
)
SEED_PASSWORDS = (
    "admin",
    "password",
    "123456",
    "root",
    "toor",
    "pass",
    "wordpress",
    "elliot",
    "robot",
)


def ensure_lab_wordlists(*, use_llm: bool = True) -> tuple[str, str]:
    """Create users.txt / passwords.txt if Hydra would otherwise fail."""
    users_file = _existing_or_create(
        kind="users",
        default_name="users.txt",
        seed=SEED_USERS,
        use_llm=use_llm,
    )
    passwords_file = _existing_or_create(
        kind="passwords",
        default_name="passwords.txt",
        seed=SEED_PASSWORDS,
        use_llm=use_llm,
    )
    return users_file, passwords_file


def _existing_or_create(
    *,
    kind: str,
    default_name: str,
    seed: tuple[str, ...],
    use_llm: bool,
) -> str:
    existing = resolve_lab_wordlist(kind)
    if Path(existing).is_file():
        return existing
    items = list(seed)
    if use_llm:
        items.extend(_llm_wordlist_items(kind))
    unique = _uniq(items)
    Path(default_name).write_text("\n".join(unique) + "\n", encoding="utf-8")
    return default_name


def _uniq(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in items:
        value = raw.strip()
        if not value or value in seen or any(ch in value for ch in "\n\r\0"):
            continue
        if len(value) > 64:
            continue
        seen.add(value)
        out.append(value)
    return out[:40]


def _llm_wordlist_items(kind: str) -> list[str]:
    try:
        from V2.llm_provider import build_chat_client, response_content_to_text
    except Exception:
        return []
    label = "usernames" if kind == "users" else "passwords"
    prompt = (
        "Authorized isolated-lab wordlist helper. "
        f"Return JSON only: {{\"items\": [\"...\"]}} with up to 15 common {label} "
        "for a WordPress training VM. Use generic defaults (admin, password, etc.). "
        "Do not output shell commands."
    )
    try:
        client = build_chat_client(temperature=0.2)
        text = response_content_to_text(client.invoke(prompt))
        match = re.search(r"\{.*\}", text, flags=re.S)
        if not match:
            return []
        payload = json.loads(match.group(0))
        items = payload.get("items") or []
        return [str(item) for item in items if isinstance(item, (str, int))]
    except Exception:
        return []
