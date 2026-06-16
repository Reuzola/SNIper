"""Behavioral-equivalence tests for sniper.proxy.

Re-runs the golden battery (generated from the original CLI core) against the
migrated sniper.proxy functions. Note the function the CLI called
``is_tls_client_hello`` is named ``is_client_hello`` in the GUI/package copy;
the body is identical, so the golden ``is_tls_client_hello`` cases are checked
against ``is_client_hello`` here.
"""
from __future__ import annotations

import json
import os

import sniper.proxy as proxy

_GOLDEN = json.load(open(
    os.path.join(os.path.dirname(__file__), "_golden.json"), encoding="ascii"))


def test_split_host_port():
    for case in _GOLDEN["split_host_port"]:
        got = proxy._split_host_port(case["authority"], case["default_port"])
        if isinstance(got, tuple):
            got = list(got)
        assert got == case["result"], case


def test_is_client_hello():
    for case in _GOLDEN["is_tls_client_hello"]:
        data = bytes.fromhex(case["data_hex"])
        assert proxy.is_client_hello(data) == case["result"], case


def test_strip_hop_by_hop():
    for case in _GOLDEN["strip_hop_by_hop"]:
        in_b = bytes.fromhex(case["in_hex"])
        got = proxy._strip_hop_by_hop(in_b)
        assert got.hex() == case["out_hex"], case
