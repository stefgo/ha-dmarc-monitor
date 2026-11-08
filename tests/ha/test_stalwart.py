"""The JMAP client against a mocked HTTP layer."""

from __future__ import annotations

import json

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from pytest_homeassistant_custom_component.test_util.aiohttp import (
    AiohttpClientMockResponse,
)

from custom_components.dmarc_monitor.const import OBJECT_DMARC, OBJECT_TLS
from custom_components.dmarc_monitor.stalwart import (
    StalwartAuthError,
    StalwartClient,
    StalwartConnectionError,
)

BASE = "https://mail.example.org"


def client(hass):
    return StalwartClient(async_get_clientsession(hass), BASE, " key ")


async def test_session_discovery_query_and_get(hass: HomeAssistant, aioclient_mock):
    requests = []

    async def jmap(method, url, data):
        body = json.loads(data) if isinstance(data, (str, bytes)) else data
        requests.append(body)
        name, args, call_id = body["methodCalls"][0]
        if name.endswith("/query"):
            result = {"ids": ["a", "b"], "total": 2, "position": args["position"]}
        else:
            result = {"list": [{"id": i} for i in args["ids"]]}
        return AiohttpClientMockResponse(
            method, url, json={"methodResponses": [[name, result, call_id]]}
        )

    aioclient_mock.get(
        f"{BASE}/.well-known/jmap",
        json={
            "apiUrl": f"{BASE}/jmap/",
            "primaryAccounts": {"urn:stalwart:jmap": "acc1"},
        },
    )
    aioclient_mock.post(f"{BASE}/jmap/", side_effect=jmap)

    c = client(hass)
    assert await c.query_ids(OBJECT_DMARC) == ["a", "b"]
    assert await c.get(OBJECT_DMARC, ["a", "b"]) == [{"id": "a"}, {"id": "b"}]

    first = requests[0]
    assert first["using"] == ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"]
    assert first["methodCalls"][0][0] == "x:DmarcExternalReport/query"
    assert first["methodCalls"][0][1]["accountId"] == "acc1"
    headers = aioclient_mock.mock_calls[0][3]
    assert headers["Authorization"] == "Bearer key"


async def test_api_url_of_another_host_is_moved_to_base(
    hass: HomeAssistant, aioclient_mock
):
    aioclient_mock.get(
        f"{BASE}/.well-known/jmap",
        json={
            "apiUrl": "https://public.example.org/jmap/",
            "primaryAccounts": {"urn:stalwart:jmap": "acc1"},
        },
    )
    aioclient_mock.post(
        f"{BASE}/jmap/",
        json={"methodResponses": [["x:DmarcExternalReport/query", {"ids": []}, "q"]]},
    )
    assert await client(hass).query_ids(OBJECT_DMARC) == []
    assert str(aioclient_mock.mock_calls[1][1]) == f"{BASE}/jmap/"


async def test_without_session_access_jmap_is_used(hass: HomeAssistant, aioclient_mock):
    aioclient_mock.get(f"{BASE}/.well-known/jmap", status=403)
    aioclient_mock.post(
        f"{BASE}/jmap/",
        json={"methodResponses": [["x:DmarcExternalReport/query", {"ids": []}, "q"]]},
    )
    assert await client(hass).query_ids(OBJECT_DMARC) == []


async def test_validate_checks_query_and_get(hass: HomeAssistant, aioclient_mock):
    requests = []

    async def jmap(method, url, data):
        body = json.loads(data) if isinstance(data, (str, bytes)) else data
        requests.append([call[0] for call in body["methodCalls"]])
        query, get = body["methodCalls"]
        return AiohttpClientMockResponse(
            method,
            url,
            json={
                "methodResponses": [
                    [query[0], {"ids": []}, query[2]],
                    [get[0], {"list": [], "notFound": []}, get[2]],
                ]
            },
        )

    aioclient_mock.get(f"{BASE}/.well-known/jmap", status=403)
    aioclient_mock.post(f"{BASE}/jmap/", side_effect=jmap)
    await client(hass).async_validate([OBJECT_DMARC, OBJECT_TLS])
    assert requests == [
        ["x:DmarcExternalReport/query", "x:DmarcExternalReport/get"],
        ["x:TlsExternalReport/query", "x:TlsExternalReport/get"],
    ]


async def test_validate_fails_without_get(hass: HomeAssistant, aioclient_mock):
    """A key that may query but not get is rejected at setup."""
    aioclient_mock.get(f"{BASE}/.well-known/jmap", status=403)
    aioclient_mock.post(
        f"{BASE}/jmap/",
        json={
            "methodResponses": [
                ["x:DmarcExternalReport/query", {"ids": []}, "q"],
                ["error", {"type": "forbidden"}, "g"],
            ]
        },
    )
    with pytest.raises(StalwartAuthError):
        await client(hass).async_validate([OBJECT_DMARC])


@pytest.mark.parametrize(
    ("response", "error"),
    [
        ({"status": 401}, StalwartAuthError),
        (
            {"json": {"methodResponses": [["error", {"type": "forbidden"}, "q"]]}},
            StalwartAuthError,
        ),
        ({"status": 500, "text": "boom"}, StalwartConnectionError),
        ({"text": "not json"}, StalwartConnectionError),
    ],
)
async def test_errors(hass: HomeAssistant, aioclient_mock, response, error):
    aioclient_mock.get(f"{BASE}/.well-known/jmap", status=404)
    aioclient_mock.post(f"{BASE}/jmap/", **response)
    with pytest.raises(error):
        await client(hass).query_ids(OBJECT_DMARC)
