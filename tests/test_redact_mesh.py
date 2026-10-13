"""NPDU recorder: Route Record, Link Status and APS data acks are logged structurally.

Their payloads hold only shorts, link costs and APS header fields (no EUI, no key), so after
EUI redaction of the NWK header the full hex is logged. Tails behind them are covered by
``test_debug.SECRET_FRAMES``. Dummy identities only (``AC:DE:48`` documentation OUI).
"""

from __future__ import annotations

import pytest

from fixtures import golden as g
from vicare_local_ble.zigbee_direct.debug import EuiPseudonymizer, redact_npdu
from vicare_local_ble.zigbee_direct.redact import inspect_npdu
from vicare_local_ble.zigbee_direct.types import Eui64

h = g.h
EUI_A = Eui64.from_str("AC:DE:48:00:00:00:00:0A")
EUI_B = Eui64.from_str("AC:DE:48:00:00:00:00:0B")
A, B = EUI_A.wire.hex(), EUI_B.wire.hex()
P1 = "0100000000000002"  # wire of pseudonym 02:00:00:00:00:00:00:01
P2 = "0200000000000002"

ROUTE_RECORD = h("09 18 93 CB 44 18 1D 21", A, B, "05 02 A1 96 00 00")
LINK_STATUS = h("09 10 FC FF A1 96 01 33", B, "08 62 00 00 11 93 CB 33")
APS_ACK = h("48 02 44 18 93 CB 1E 42", "02 01 01 02 04 01 01 51")


@pytest.mark.parametrize(
    ("npdu", "expected"),
    [
        (ROUTE_RECORD, h("09 18 93 CB 44 18 1D 21", P1, P2, "05 02 A1 96 00 00")),
        (LINK_STATUS, h("09 10 FC FF A1 96 01 33", P1, "08 62 00 00 11 93 CB 33")),
        (APS_ACK, APS_ACK),
    ],
    ids=["route_record", "link_status", "aps_ack"],
)
def test_logged_in_full_with_euis_replaced(npdu: bytes, expected: bytes) -> None:
    assert inspect_npdu(npdu).verdict == "ok"
    out = redact_npdu(npdu, EuiPseudonymizer())
    assert out.redacted is None
    assert out.hex == expected.hex()
    for eui in (A, B):
        assert eui not in out.hex


def test_route_record_euis_are_collected_from_the_header_only() -> None:
    fields = inspect_npdu(ROUTE_RECORD).fields
    assert fields == (("eui", EUI_A), ("eui", EUI_B))


def test_truncated_route_record_is_header_only() -> None:
    out = redact_npdu(ROUTE_RECORD[:-2], EuiPseudonymizer())
    assert out.hex is None
    assert out.redacted == "undecodable"
