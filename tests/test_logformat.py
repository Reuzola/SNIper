"""Unit tests for sniper.logformat.friendly_format.

Feeds representative raw proxy events through friendly_format and asserts the
mapped (level, text), or None for suppressed lines. Also confirms the ordering
dependency: the NXDOMAIN / no-address patterns must be matched BEFORE the
generic "Could not connect" pattern, since they share its prefix.
"""
from __future__ import annotations

from sniper.logformat import friendly_format


def test_started_doh_on():
    msg = "Proxy started on 127.0.0.1:8881  |  fragment=2B  |  DoH=on"
    assert friendly_format("INFO", msg) == (
        "OK", "Started — listening on port 8881  ·  fragment 2B  ·  secure DNS")


def test_started_doh_off():
    msg = "Proxy started on 127.0.0.1:9999  |  fragment=4B  |  DoH=off"
    assert friendly_format("INFO", msg) == (
        "OK", "Started — listening on port 9999  ·  fragment 4B  ·  system DNS")


def test_stopped():
    assert friendly_format("INFO", "Proxy stopped. Windows proxy restored.") == (
        "OK", "Stopped — system proxy restored")


def test_connect_443_hides_port():
    assert friendly_format("INFO", "CONNECT  example.com:443") == (
        "CONN", "→  example.com")


def test_connect_nonstandard_port_shown():
    assert friendly_format("INFO", "CONNECT  example.com:8080") == (
        "CONN", "→  example.com:8080")


def test_http_get():
    assert friendly_format("INFO", "GET  http://example.com/path?q=1") == (
        "CONN", "→  example.com  (HTTP)")


def test_doh_failed():
    msg = "All DoH servers failed (example.com): no A record  -> trying public UDP DNS"
    assert friendly_format("WARNING", msg) == (
        "WARNING", "Secure DNS unavailable for example.com — trying public DNS")


def test_udp_ok():
    assert friendly_format("INFO", "Resolved example.com via public UDP DNS -> 1.2.3.4") == (
        "OK", "Resolved example.com via public DNS  (1.2.3.4)")


def test_tcp_ok():
    assert friendly_format("INFO", "Resolved example.com via public TCP DNS -> 1.2.3.4") == (
        "OK", "Resolved example.com via TCP DNS  (1.2.3.4)")


def test_v6_doh_ok():
    assert friendly_format("INFO", "Resolved example.com via DoH (IPv6) -> 2001:db8::1") == (
        "OK", "Resolved example.com via IPv6  (2001:db8::1)")


def test_v6_udp_ok():
    assert friendly_format("INFO", "Resolved example.com via public UDP DNS (IPv6) -> 2001:db8::1") == (
        "OK", "Resolved example.com via IPv6 public DNS  (2001:db8::1)")


def test_v6_tcp_ok():
    assert friendly_format("INFO", "Resolved example.com via public TCP DNS (IPv6) -> 2001:db8::1") == (
        "OK", "Resolved example.com via IPv6 TCP DNS  (2001:db8::1)")


def test_public_dns_unavailable():
    assert friendly_format("WARNING", "Public DNS unavailable for example.com  -> system DNS") == (
        "WARNING", "Public DNS unreachable for example.com — using system DNS")


def test_nocon_nxdomain():
    msg = ("Could not connect to deadhost.example:443 -> "
           "[Errno 11001] deadhost.example does not exist (NXDOMAIN)")
    assert friendly_format("ERROR", msg) == (
        "WARNING", "deadhost.example — host does not exist")


def test_nocon_no_usable_address():
    msg = ("Could not connect to noaddr.example:443 -> "
           "noaddr.example has no usable address (no A or AAAA record)")
    assert friendly_format("ERROR", msg) == (
        "WARNING", "noaddr.example — no IPv4/IPv6 address")


def test_nocon_generic():
    msg = "Could not connect to host.example:443 -> [Errno 111] Connection refused"
    assert friendly_format("ERROR", msg) == ("ERROR", "Could not reach host.example")


def test_nxdomain_matched_before_generic():
    """Ordering guard: an NXDOMAIN 'Could not connect' line must map to the
    NXDOMAIN branch (WARNING / host does not exist), never the generic
    'Could not reach' branch."""
    msg = ("Could not connect to deadhost.example:443 -> "
           "[Errno 11001] deadhost.example does not exist (NXDOMAIN)")
    level, text = friendly_format("ERROR", msg)
    assert level == "WARNING"
    assert "host does not exist" in text
    assert text != "Could not reach deadhost.example"


def test_frag_line_suppressed():
    assert friendly_format("INFO", "[frag 2B]  example.com:443") is None


def test_debug_suppressed():
    assert friendly_format("DEBUG", "DoH  some internal detail") is None


def test_unknown_info_passthrough():
    # Anything unmatched keeps its original level and text.
    assert friendly_format("INFO", "some other message") == ("INFO", "some other message")
