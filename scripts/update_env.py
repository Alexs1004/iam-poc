#!/usr/bin/env python3
"""
Update a key=value entry inside a .env-style file.

This keeps existing ordering and comments intact, replacing the first
occurrence of the target key or appending a new entry when absent.
"""
from __future__ import annotations

import argparse
from pathlib import Path


def update_env(path: Path, key: str, value: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"Cannot find {path}")

    contents = path.read_text(encoding="utf-8").splitlines()
    updated = False

    for idx, line in enumerate(contents):
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in line:
            continue

        # Preserve leading whitespace when rewriting the line.
        leading_ws = line[: len(line) - len(stripped)]
        key_part, _, _ = stripped.partition("=")
        if key_part.strip() != key:
            continue

        contents[idx] = f"{leading_ws}{key}={value}"
        updated = True
        break

    if not updated:
        if contents and contents[-1] != "":
            contents.append("")
        contents.append(f"{key}={value}")

    path.write_text("\n".join(contents) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Update a key in a .env file")
    parser.add_argument("path", type=Path, help="Path to the .env file")
    parser.add_argument("key", help="Key to update (e.g. KEYCLOAK_SERVICE_CLIENT_SECRET)")
    parser.add_argument("value", help="New value for the key")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    update_env(args.path, args.key, args.value)


if __name__ == "__main__":
    main()
