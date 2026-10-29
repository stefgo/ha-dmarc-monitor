"""Consistency of manifest, translations and services."""

from __future__ import annotations

import importlib
import json
import re
from pathlib import Path

import pytest
from conftest import COMPONENT, PACKAGE

const = importlib.import_module(f"{PACKAGE}.const")
messages = importlib.import_module(f"{PACKAGE}.messages")


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def collect_keys(data, prefix=""):
    if isinstance(data, dict):
        keys = set()
        for key, value in data.items():
            keys |= collect_keys(value, f"{prefix}.{key}")
        return keys
    return {prefix}


def test_manifest_matches_the_domain():
    manifest = load(COMPONENT / "manifest.json")
    assert manifest["domain"] == const.DOMAIN
    assert manifest["version"] == const.INTEGRATION_VERSION
    assert manifest["config_flow"] is True


@pytest.mark.parametrize("language", ["de", "en"])
def test_translations_are_complete(language):
    strings = load(COMPONENT / "strings.json")
    translation = load(COMPONENT / "translations" / f"{language}.json")
    assert collect_keys(strings) == collect_keys(translation)


def test_services_yaml_knows_the_same_services():
    source = (COMPONENT / "services.py").read_text(encoding="utf-8")
    expected = set(re.findall(r'^SERVICE_\w+ = "(\w+)"$', source, re.MULTILINE))
    assert expected
    yaml_text = (COMPONENT / "services.yaml").read_text(encoding="utf-8")
    defined = set(re.findall(r"^(\w+):$", yaml_text, re.MULTILINE))
    assert defined == expected
    assert set(load(COMPONENT / "strings.json")["services"]) == expected


def test_message_languages_carry_the_same_texts():
    assert set(messages.TEXTS["de"]) == set(messages.TEXTS["en"])
