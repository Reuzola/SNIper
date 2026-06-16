"""Behavioral-equivalence tests for sniper.dns.

The exact same input battery recorded in tests/_golden.json (generated from
the original CLI core before the refactor) is re-run against the migrated
sniper.dns functions. Any mismatch means logic drifted during the move.
"""
from __future__ import annotations

import json
import os

import sniper.dns as dns

_GOLDEN = json.load(open(
    os.path.join(os.path.dirname(__file__), "_golden.json"), encoding="ascii"))


def _expected(case):
    """Reconstruct the original (outcome, data) tuple from JSON."""
    data = case["data"]
    if isinstance(data, list):
        data = tuple(data)
    return case["outcome"], data


def test_build_dns_query():
    for case in _GOLDEN["build_dns_query"]:
        got = dns._build_dns_query(case["host"], case["tid"], case["qtype"])
        assert got.hex() == case["hex"], case


def test_parse_dns_response():
    for case in _GOLDEN["parse_dns_response"]:
        buf = bytes.fromhex(case["buf_hex"])
        got = dns._parse_dns_response(buf, case["tid"], case["want_type"])
        assert got == _expected(case), case


def test_negative_ttl():
    for case in _GOLDEN["negative_ttl"]:
        buf = bytes.fromhex(case["buf_hex"])
        got = dns._negative_ttl(buf, case["off"], case["nscount"])
        assert got == case["result"], case


def test_skip_name():
    for case in _GOLDEN["skip_name"]:
        buf = bytes.fromhex(case["buf_hex"])
        got = dns._skip_name(buf, case["off"])
        assert got == case["result"], case


def test_parse_http_response():
    for case in _GOLDEN["parse_http_response"]:
        raw = bytes.fromhex(case["raw_hex"])
        status, body = dns._parse_http_response(raw)
        assert status == case["status"], case
        assert body.hex() == case["body_hex"], case
