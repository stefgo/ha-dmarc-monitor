"""JMAP client for the report objects of a Stalwart server (0.16 or newer).

Since 0.16 Stalwart manages everything through JMAP; received reports are
the objects ``x:DmarcExternalReport`` and ``x:TlsExternalReport``. Reading
them takes ``/query`` (the ids) and ``/get`` (the objects). The client asks
only for ids it has not seen before; reports never change once stored.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable
from typing import Any

import aiohttp
from yarl import URL

from .const import (
    GET_BATCH_SIZE,
    JMAP_CAPABILITY_CORE,
    JMAP_CAPABILITY_STALWART,
    QUERY_PAGE_SIZE,
    REQUEST_TIMEOUT,
)

_LOGGER = logging.getLogger(__name__)

USING = [JMAP_CAPABILITY_CORE, JMAP_CAPABILITY_STALWART]
# Stalwart keeps reports for 30 days by default; a server that holds this many
# ids is either configured for years or flooded, and either way one cycle has
# to stop somewhere.
MAX_IDS = 5000


class StalwartError(Exception):
    """Base error of the client."""


class StalwartConnectionError(StalwartError):
    """Server unreachable or the answer was not JMAP."""


class StalwartAuthError(StalwartError):
    """The API key was rejected (401) or lacks a permission (403, forbidden)."""


class StalwartClient:
    """Reads the received reports of one Stalwart server."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        url: str,
        api_key: str,
        timeout: int = REQUEST_TIMEOUT,
    ) -> None:
        self._session = session
        self._base = url.rstrip("/")
        self._api_key = api_key.strip()
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._api_url: str | None = None
        self._account_id: str | None = None

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
        }

    async def _discover(self) -> None:
        """Find the JMAP endpoint through the session resource (RFC 8620 §2).

        A key restricted to the report permissions may not be allowed to read
        the session; ``/jmap/`` is where Stalwart serves the API, so that is the
        fallback rather than a failure.
        """
        if self._api_url is not None:
            return
        try:
            async with self._session.get(
                f"{self._base}/.well-known/jmap",
                headers=self._headers,
                timeout=self._timeout,
            ) as response:
                if response.status == 401:
                    raise StalwartAuthError("API key rejected (401)")
                if response.status == 200:
                    session = await response.json(content_type=None)
                    api_url = session.get("apiUrl")
                    if isinstance(api_url, str) and api_url:
                        self._api_url = self._on_base(api_url)
                    accounts = session.get("primaryAccounts") or {}
                    account = accounts.get(JMAP_CAPABILITY_STALWART)
                    if isinstance(account, str) and account:
                        self._account_id = account
        except StalwartAuthError:
            raise
        except (aiohttp.ClientError, TimeoutError, ValueError) as err:
            _LOGGER.debug("JMAP session not readable, using /jmap/: %s", err)
        if self._api_url is None:
            self._api_url = f"{self._base}/jmap/"

    def _on_base(self, api_url: str) -> str:
        """The session's ``apiUrl`` with scheme, host and port of the base URL.

        Stalwart names its public hostname there; following it would route the
        calls past the URL the user configured, e.g. out through an external
        proxy instead of the internal address.
        """
        api = URL(api_url)
        base = URL(self._base)
        if (api.scheme, api.host, api.port) != (base.scheme, base.host, base.port):
            _LOGGER.debug(
                "Session names %s as API URL, using the path on %s", api_url, base
            )
        return str(base.with_path(api.path or "/jmap/"))

    async def _call(self, calls: list[list[Any]]) -> list[list[Any]]:
        """Send method calls; returns the method responses in order."""
        await self._discover()
        assert self._api_url is not None
        if self._account_id:
            for call in calls:
                call[1].setdefault("accountId", self._account_id)
        try:
            async with self._session.post(
                self._api_url,
                json={"using": USING, "methodCalls": calls},
                headers=self._headers,
                timeout=self._timeout,
            ) as response:
                if response.status in (401, 403):
                    raise StalwartAuthError(f"API key rejected ({response.status})")
                if response.status >= 400:
                    text = (await response.text())[:200]
                    raise StalwartConnectionError(f"HTTP {response.status}: {text}")
                data = await response.json(content_type=None)
        except StalwartError:
            raise
        except (aiohttp.ClientError, TimeoutError) as err:
            raise StalwartConnectionError(str(err) or type(err).__name__) from err
        except ValueError as err:
            raise StalwartConnectionError("Answer is not JSON") from err
        responses = data.get("methodResponses") if isinstance(data, dict) else None
        if not isinstance(responses, list):
            raise StalwartConnectionError("Answer carries no methodResponses")
        for item in responses:
            if isinstance(item, list) and item and item[0] == "error":
                details = item[1] if len(item) > 1 and isinstance(item[1], dict) else {}
                kind = details.get("type", "unknown")
                description = details.get("description", "")
                if kind in ("forbidden", "accountNotFound", "unknownCapability"):
                    raise StalwartAuthError(f"{kind}: {description}".strip(": "))
                raise StalwartConnectionError(f"{kind}: {description}".strip(": "))
        return responses

    async def query_ids(self, object_type: str) -> list[str]:
        """All ids of one object type, page by page."""
        ids: list[str] = []
        position = 0
        while len(ids) < MAX_IDS:
            responses = await self._call(
                [
                    [
                        f"{object_type}/query",
                        {"position": position, "limit": QUERY_PAGE_SIZE},
                        "q",
                    ]
                ]
            )
            result = responses[0][1] if responses and len(responses[0]) > 1 else {}
            page = [str(i) for i in result.get("ids") or []]
            ids.extend(page)
            total = result.get("total")
            position += len(page)
            if not page or (isinstance(total, int) and position >= total):
                break
            if len(page) < QUERY_PAGE_SIZE and not isinstance(total, int):
                break
        return ids[:MAX_IDS]

    async def get(self, object_type: str, ids: Iterable[str]) -> list[dict[str, Any]]:
        """The objects behind ``ids``, in batches."""
        wanted = list(ids)
        objects: list[dict[str, Any]] = []
        for start in range(0, len(wanted), GET_BATCH_SIZE):
            batch = wanted[start : start + GET_BATCH_SIZE]
            responses = await self._call([[f"{object_type}/get", {"ids": batch}, "g"]])
            result = responses[0][1] if responses and len(responses[0]) > 1 else {}
            objects.extend(o for o in result.get("list") or [] if isinstance(o, dict))
            # Give the event loop a breath between large batches.
            await asyncio.sleep(0)
        return objects

    async def async_validate(self, object_types: Iterable[str]) -> None:
        """Prove that the key may query and get every object type.

        Stalwart checks the permission of ``/get`` even for an empty id list,
        so a key that may only query is caught here rather than on the first
        fetch.
        """
        for object_type in object_types:
            await self._call(
                [
                    [f"{object_type}/query", {"position": 0, "limit": 1}, "q"],
                    [f"{object_type}/get", {"ids": []}, "g"],
                ]
            )
