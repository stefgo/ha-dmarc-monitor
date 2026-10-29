#!/usr/bin/env python3
"""Record what a real Stalwart server answers, to check the parser against it.

Reads STALWART_URL and STALWART_API_KEY from the environment or from .env and
writes the raw JMAP answers to .recorded/ (git-ignored). The files contain real
addresses and must be anonymized before anything from them goes into
tests/fixtures.

    python3 scripts/record_fixtures.py
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / ".recorded"
USING = ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"]
TYPES = ("x:DmarcExternalReport", "x:TlsExternalReport")


def load_env() -> None:
    env = ROOT / ".env"
    if not env.is_file():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and not key.startswith("#"):
            os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def request(url: str, key: str, body: dict | None = None) -> tuple[int, object]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method="POST" if body is not None else "GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode(errors="replace")[:500]


def main() -> int:
    load_env()
    base = os.environ.get("STALWART_URL", "").rstrip("/")
    key = os.environ.get("STALWART_API_KEY", "")
    if not base or not key:
        print("STALWART_URL and STALWART_API_KEY must be set (see .env.example)")
        return 1
    OUT.mkdir(exist_ok=True)

    status, session = request(f"{base}/.well-known/jmap", key)
    print(f"session: HTTP {status}")
    (OUT / "session.json").write_text(json.dumps(session, indent=2), encoding="utf-8")
    api = f"{base}/jmap/"
    account = None
    if status == 200 and isinstance(session, dict):
        api = session.get("apiUrl") or api
        account = (session.get("primaryAccounts") or {}).get("urn:stalwart:jmap")

    for object_type in TYPES:
        args: dict = {"position": 0, "limit": 20}
        if account:
            args["accountId"] = account
        status, answer = request(
            api,
            key,
            {"using": USING, "methodCalls": [[f"{object_type}/query", args, "q"]]},
        )
        print(f"{object_type}/query: HTTP {status}")
        name = object_type.split(":")[1]
        (OUT / f"{name}.query.json").write_text(
            json.dumps(answer, indent=2), encoding="utf-8"
        )
        try:
            ids = answer["methodResponses"][0][1]["ids"][:5]  # type: ignore[index]
        except (KeyError, IndexError, TypeError):
            continue
        get_args: dict = {"ids": ids}
        if account:
            get_args["accountId"] = account
        status, objects = request(
            api,
            key,
            {"using": USING, "methodCalls": [[f"{object_type}/get", get_args, "g"]]},
        )
        print(f"{object_type}/get ({len(ids)} ids): HTTP {status}")
        (OUT / f"{name}.get.json").write_text(
            json.dumps(objects, indent=2), encoding="utf-8"
        )
    print(f"Written to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
