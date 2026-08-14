"""Runtime world state: observations from each lab action."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from V5.runtime.artifacts import parse_robots_paths, uniquify_wordlist
from V5.runtime.command_suggest import CredentialPair, normalize_target_uri
from V5.runtime.executor import ExecResult


@dataclass
class WorldState:
    target_ip: str
    port: int = 80
    facts: list[str] = field(default_factory=list)
    robots_body: str | None = None
    robots_paths: list[str] = field(default_factory=list)
    wordlist_path: str | None = None
    valid_users: list[str] = field(default_factory=list)
    credentials: list[CredentialPair] = field(default_factory=list)
    target_uri: str = "/"
    has_shell: bool = False
    has_root: bool = False
    tried: set[str] = field(default_factory=set)
    last_error: str | None = None
    last_stdout: str | None = None

    def add_fact(self, fact: str) -> None:
        if fact and fact not in self.facts:
            self.facts.append(fact)

    def snapshot(self) -> dict[str, object]:
        return {
            "target_ip": self.target_ip,
            "port": self.port,
            "facts": list(self.facts),
            "robots_paths": list(self.robots_paths),
            "wordlist_path": self.wordlist_path,
            "valid_users": list(self.valid_users),
            "credential_count": len(self.credentials),
            "target_uri": self.target_uri,
            "has_shell": self.has_shell,
            "has_root": self.has_root,
            "tried": sorted(self.tried),
            "last_error": self.last_error,
        }


def ingest_result(world: WorldState, command: str | None, result: ExecResult) -> None:
    """Update world state from a finished lab command."""
    world.last_error = result.error
    cmd = command or result.command or ""
    out = result.stdout_excerpt or ""
    world.last_stdout = out
    blob = out.lower()

    if "robots.txt" in cmd:
        world.robots_body = out
        world.robots_paths = parse_robots_paths(out)
        if world.robots_paths:
            world.add_fact("robots:" + ",".join(world.robots_paths))
        else:
            world.add_fact("robots:empty")

    if "wp-login.php" in cmd.lower() and "hydra" not in cmd.lower():
        if _looks_like_wordpress(out):
            world.add_fact("cms:wordpress")
            base = _wordpress_base_from_body(out) or _wordpress_base_from_login_url(cmd)
            if base:
                world.target_uri = normalize_target_uri(base)
                world.add_fact(f"target_uri:{world.target_uri}")

    output_file = _curl_output_file(cmd)
    if output_file:
        unique = uniquify_wordlist(Path(output_file))
        if unique:
            world.wordlist_path = str(unique)
            world.add_fact(f"wordlist:{unique}")

    if result.usernames:
        for user in result.usernames:
            if user not in world.valid_users:
                world.valid_users.append(user)
        world.add_fact("wp_users:" + ",".join(world.valid_users))

    if result.credentials:
        world.credentials = list(result.credentials)
        world.add_fact("credential_access")

    if "session opened" in blob or "meterpreter session" in blob:
        world.has_shell = True
        world.add_fact("shell_access")
    if "uid=0" in blob or "got root" in blob or "session 2 opened" in blob:
        world.has_root = True
        world.add_fact("root_access")

    missing = re.search(r"failed to load module:\s*(\S+)", blob)
    if missing:
        world.tried.add(f"missing:{missing.group(1).lower()}")



def _curl_output_file(command: str) -> str | None:
    match = re.search(r"-o\s+(\S+)", command)
    if not match:
        return None
    return match.group(1)


def _looks_like_wordpress(body: str) -> bool:
    blob = body.lower()
    markers = (
        "wordpress",
        "wp-submit",
        "user_login",
        "wp-login",
        "login_error",
        "wp-content",
        "wp-includes",
    )
    return any(marker in blob for marker in markers)


def _wordpress_base_from_login_url(command: str) -> str | None:
    match = re.search(r"https?://[^/\s]+(/[^?\s]*?)wp-login\.php", command, flags=re.I)
    if not match:
        return None
    base = match.group(1) or "/"
    return base if base.endswith("/") else base + "/"


def _wordpress_base_from_body(body: str) -> str | None:
    match = re.search(
        r"""(?:action|href)=["']([^"']*?)wp-login\.php""",
        body,
        flags=re.I,
    )
    if not match:
        return None
    path = match.group(1) or "/"
    if path.startswith("http"):
        path_match = re.search(r"https?://[^/]+(/[^?\s]*?)(?:wp-login\.php)?$", path, flags=re.I)
        path = path_match.group(1) if path_match else "/"
    if not path.startswith("/"):
        path = "/" + path
    if "wp-login" in path.lower():
        path = path.lower().split("wp-login", 1)[0]
    return path if path.endswith("/") else path + "/"
