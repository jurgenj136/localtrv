"""End to end over the simulator: the connection rows of the edge-case table.

Every test runs the whole library stack (``ZdConnection`` + ``ViCareBridge`` over
``SimulatedR0`` + ``SimNetwork`` + ``SimValve``) on ``VirtualClock`` with production timings;
HA-level rows go through the integration harness. Keys and EUIs are the dummies of
``default_installation``.

Edge-case row -> test (``sim`` = this file, ``net`` = ``test_e2e_sim_network.py``,
``ha`` = ``tests/components/vicare_local_ble/test_e2e_ha.py``)

Row                                         File  Test
------------------------------------------  ----  ------------------------------------------
R0 absent at startup                        ha    test_r0_absent_at_startup_not_ready
R0 drops later                              sim   test_r0_drops_later_full_rejoin
                                            ha    test_r0_drops_bridge_entity_flips_at_once
Original proxy disappears                   sim   test_original_proxy_disappears
Two adapters see the R0                     ha    test_two_adapters_one_entry_one_connection
ViCare app holds the R0                     sim   test_vicare_app_holds_the_r0
Wrong network key (twice)                   sim   test_wrong_key_twice_auth_failed
                                            ha    test_wrong_key_reauth_and_supervisor_stops
Proxy disconnect during SE3 / GATT error    sim   test_se3_transport_error_is_retryable
Counter exhaustion / write fail / cancel    sim   test_writer_failure_reconnects
Small MTU                                   sim   test_small_mtu_is_not_fatal
                                            ha    test_small_mtu_repair_issue
Oversized outgoing write rejected           sim   test_oversized_write_reconnects
                                            ha    test_oversized_write_repair_issue
Oversized indication trunc/drop/reject      sim   test_oversized_indication_miss_path
Replayed indication                         sim   test_replayed_indication_dropped
Valve does not answer                       net   test_valve_silent_unavailable_rewalk
All known valves silent while READY         net   test_all_valves_silent_rejoin
No valves found / partial discovery         net   test_no_valves_retry_schedule
                                            net   test_partial_discovery_retry_finds_rest
New valve paired later                      net   test_new_valve_paired_later
                                            ha    test_new_valve_gets_entities
Network Status for a dst                    net   test_network_status_route_error
TC assigns a different (valid) short        net   test_tc_assigns_other_short_persisted
Invalid assigned short                      net   test_invalid_assigned_short_backs_off
Address conflict (0x0D)                     net   test_address_conflict_fresh_short
Valve short changed (Device_annce)          net   test_valve_short_changed_by_annce
Valve short changed (walk)                  net   test_valve_short_changed_by_walk
Invalid attribute value / limits            net   test_invalid_values_and_limits
Concurrent setpoint writes                  net   test_concurrent_setpoints_newest_wins
Confirm read times out                      net   test_confirm_timeout_unconfirmed
Stale GATT cache                            sim   test_stale_gatt_cache_cleared_once
HA shutdown / unload                        ha    test_unload_and_stop_bounded_cache_saved
Late or duplicate response                  net   test_late_and_duplicate_responses

Every row has a simulated test. Hardware-only parts of rows (not simulable here):

* the real ESPHome/BlueZ proxy hand-over and adapter choice inside HA's bluetooth manager
  (the tests swap the resolver's result and inject adverts from two sources);
* how the real ViCare app / R0 firmware refuses a second client (simulated: one client);
* which oversize behaviour (truncate / drop / reject) and MTU the real R0 has (checklist);
* reaching counter 0xFFFFFFFF for real (the test forces the session counter to the end).
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import TYPE_CHECKING, Any

import pytest

from test_bridge import (
    BRig,
    poll,
    ready_again,
    run_until,
    settled,
    stop,
)
from vicare_local_ble.bridge import ViCareBridge
from vicare_local_ble.testing.errors import GATT_ERROR_UNLIKELY
from vicare_local_ble.testing.gatt import WriteFaultSpec
from vicare_local_ble.testing.scenario import default_installation
from vicare_local_ble.zigbee_direct.connection import (
    ConnectionIssue,
    ConnectionState,
    ZdConnection,
)
from vicare_local_ble.zigbee_direct.crypto import MAX_COUNTER
from vicare_local_ble.zigbee_direct.errors import HandshakeRejectedError
from vicare_local_ble.zigbee_direct.types import SecretBytes
from vicare_local_ble.zigbee_direct.uuids import TUNNEL_NPDU

if TYPE_CHECKING:
    from collections.abc import Callable

    from bleak.backends.device import BLEDevice

    from vicare_local_ble.bridge import BridgeCache, BridgeSnapshot
    from vicare_local_ble.testing.scenario import Installation
    from vicare_local_ble.valves import Valve
    from vicare_local_ble.zigbee_direct.connection import DeviceResolver, Generation

S = ConnectionState
CONN_LOGGER = "vicare_local_ble.zigbee_direct.connection"
TRANSPORT_LOGGER = "vicare_local_ble.zigbee_direct.transport"
WRONG_KEY = SecretBytes(b"\x99" * 16)  # dummy


def e2e_rig(
    *,
    n_valves: int = 2,
    behind_router: int = 0,
    seed: int = 0,
    network_key: SecretBytes | None = None,
    resolver: Callable[[Installation], DeviceResolver] | None = None,
    cache: BridgeCache | None = None,
    setup: Callable[[Installation], None] | None = None,
    on_update: Callable[[BRig, BridgeSnapshot], None] | None = None,
    **kwargs: Any,
) -> BRig:
    """Installation + ``ZdConnection`` + attached ``ViCareBridge`` (as ``test_bridge.make_rig``,
    plus a custom network key and resolver; ``on_update`` hooks every bridge update)."""
    inst = default_installation(n_valves=n_valves, behind_router=behind_router, seed=seed)
    if setup is not None:
        setup(inst)
    conn = ZdConnection(
        resolver(inst) if resolver is not None else inst.resolver,
        own_eui=inst.zvd_eui,
        network_key=network_key if network_key is not None else inst.network_key,
        clock=inst.clock,
        connector=inst.connector,
        rng=random.Random(1000 + seed),  # noqa: S311 - jitter only
        **kwargs,
    )
    holder: list[BRig] = []

    def update(snapshot: BridgeSnapshot) -> None:
        holder[0].updates.append((holder[0].clock.now(), snapshot))
        if on_update is not None:
            on_update(holder[0], snapshot)

    def new_valve(valve: Valve) -> None:
        holder[0].new_valves.append(valve)

    def cache_changed(changed: BridgeCache) -> None:
        holder[0].caches.append(changed)

    bridge = ViCareBridge(
        conn,
        clock=inst.clock,
        cache=cache,
        on_update=update,
        on_new_valve=new_valve,
        on_cache_changed=cache_changed,
    )
    rig = BRig(inst, conn, bridge, lambda: None)
    holder.append(rig)
    rig.detach = bridge.attach()
    return rig


def track_states(r: BRig) -> list[ConnectionState]:
    states: list[ConnectionState] = []
    r.conn.add_state_listener(states.append)
    return states


def on_attempt(r: BRig, actions: dict[int, Callable[[], None]]) -> None:
    """Run ``actions[n]`` when attempt ``n`` (1-based) enters CONNECTING."""
    count = [0]

    def listener(state: ConnectionState) -> None:
        if state is S.CONNECTING:
            count[0] += 1
            action = actions.get(count[0])
            if action is not None:
                action()

    r.conn.add_state_listener(listener)


async def begin(r: BRig, *, limit: float = 86_400.0) -> Generation:
    """Start, then run until discovery and the bridge's initial poll are done."""
    gen = await r.clock.run_task(r.conn.start(first_ready_timeout=limit), limit=limit)
    await run_until(r.clock, lambda: settled(r))
    return gen


def all_available(r: BRig) -> bool:
    snap = r.snap()
    euis = r.euis()
    return set(snap.valves) == set(euis) and all(snap.available.get(e) for e in euis)


# --- R0 drops later, proxy, app, auth --------------------------------------------------------


async def test_r0_drops_later_full_rejoin() -> None:
    devices: list[BLEDevice] = []

    def resolver(inst: Installation) -> DeviceResolver:
        def resolve() -> BLEDevice:
            devices.append(inst.r0.ble_device())
            return devices[-1]

        return resolve

    r = e2e_rig(resolver=resolver)
    gen1 = await begin(r)
    states = track_states(r)
    finished: list[str] = []

    async def generation_work() -> None:
        try:
            await asyncio.get_running_loop().create_future()
        finally:
            finished.append("cancelled")

    work = r.conn.spawn(gen1, generation_work(), name="generation work")
    await r.clock.advance(0)
    r.inst.r0.disconnect()
    await run_until(r.clock, lambda: r.conn.state is S.BACKOFF)
    assert work.cancelled()
    assert finished == ["cancelled"]  # cancelled AND awaited before BACKOFF
    assert r.conn.current is None
    assert r.conn.stats.disconnects == 1
    # valves accumulate misses while the connection is down
    snap = await r.bridge.poll()
    assert snap.connection_state is S.BACKOFF
    assert all(m == 1 for m in snap.misses.values())
    gen2 = await ready_again(r, gen1.number)
    assert states[:2] == [S.BACKOFF, S.CONNECTING]
    assert S.JOINING in states
    assert len(devices) == 2
    assert devices[1] is not devices[0]  # a fresh resolver lookup per attempt
    assert r.inst.r0.connect_count == 2
    assert gen2.node is not gen1.node
    assert r.inst.network.gated_open  # full re-join: annce + MTORR again
    snap = await poll(r)
    assert all(m == 0 for m in snap.misses.values())
    assert all(snap.available.values())
    await stop(r)


async def test_original_proxy_disappears() -> None:
    source = ["proxy-a"]

    def resolver(inst: Installation) -> DeviceResolver:
        def resolve() -> BLEDevice | None:
            return inst.r0.ble_device(source=source[0]) if source[0] else None

        return resolve

    r = e2e_rig(resolver=resolver)
    gen1 = await begin(r)
    source[0] = ""  # proxy A gone: the R0 is not seen for one attempt
    r.inst.r0.disconnect()
    await run_until(r.clock, lambda: r.conn.stats.last_failure == "not_found")
    source[0] = "proxy-b"  # another adapter now sees it
    gen2 = await ready_again(r, gen1.number)
    used = [d.details["source"] for d in r.inst.connector.devices]
    assert used == ["proxy-a", "proxy-b"]
    assert gen2.number == gen1.number + 1
    await run_until(r.clock, lambda: settled(r) and r.core.polls >= 1)
    snap = await poll(r)
    assert all(snap.available.values())
    await stop(r)


async def test_vicare_app_holds_the_r0(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger=CONN_LOGGER)
    r = e2e_rig()
    app = r.inst.r0.connect(r.inst.r0.ble_device(source="phone"), None)  # the app's session
    states = track_states(r)
    start = asyncio.ensure_future(r.conn.start(first_ready_timeout=86_400))
    await run_until(r.clock, lambda: r.conn.stats.connect_failures >= 3)
    warnings = [
        rec.getMessage()
        for rec in caplog.records
        if rec.levelno == logging.WARNING and rec.name == CONN_LOGGER
    ]
    assert len(warnings) == 1
    assert "app" in warnings[0]
    assert states.count(S.BACKOFF) == 3
    assert r.conn.stats.auth_failures == 0
    await app.disconnect()  # the user closes the app
    gen = await r.clock.run_task(start)
    assert gen.number == 1
    await run_until(r.clock, lambda: settled(r))
    assert all_available(r)
    await stop(r)


async def test_wrong_key_twice_auth_failed() -> None:
    r = e2e_rig(network_key=WRONG_KEY)
    with pytest.raises(HandshakeRejectedError):
        await r.clock.run_task(r.conn.start(first_ready_timeout=3600))
    assert r.conn.state is S.AUTH_FAILED
    assert r.conn.stats.auth_failures == 2
    assert r.inst.r0.connect_count == 2
    await r.clock.advance(6 * 3600)
    assert r.inst.r0.connect_count == 2  # the supervisor stopped
    snap = await r.bridge.poll()
    assert snap.connection_state is S.AUTH_FAILED
    assert snap.valves == {}
    await stop(r)


@pytest.mark.parametrize("fault", ["disconnect", "gatt_error"])
async def test_se3_transport_error_is_retryable(fault: str) -> None:
    r = e2e_rig()
    r0 = r.inst.r0
    r0.se3_fault = fault  # type: ignore[assignment]
    r0.se3_error_code = GATT_ERROR_UNLIKELY  # not the 0x80 rejection
    on_attempt(r, {4: lambda: setattr(r0, "se3_fault", "none")})
    gen = await begin(r)
    assert r.conn.stats.attempts == 4  # three SE3 failures, more than AUTH_FAILURES_TO_STOP
    assert r.conn.stats.auth_failures == 0
    expected = "disconnect" if fault == "disconnect" else "transport:write"
    assert r.conn.stats.last_failure == expected
    assert gen.number == 1
    assert all_available(r)
    await stop(r)


# --- writer, MTU, indications ----------------------------------------------------------------


def _exhaust_counter(r: BRig) -> None:
    session = r.conn._session
    assert session is not None
    assert session.transport is not None
    cipher = session.transport._cipher
    assert cipher is not None
    cipher._outgoing = MAX_COUNTER + 1


@pytest.mark.parametrize(
    ("fault", "reason"),
    [("counter", "write"), ("raise", "write"), ("hang", "timeout"), ("disconnect", None)],
)
async def test_writer_failure_reconnects(fault: str, reason: str | None) -> None:
    r = e2e_rig()
    gen1 = await begin(r)
    connects = r.inst.r0.connect_count
    if fault == "counter":
        _exhaust_counter(r)
    else:
        r.inst.r0.inject_write_fault(WriteFaultSpec(fault, TUNNEL_NPDU))  # type: ignore[arg-type]
    polling = asyncio.ensure_future(r.bridge.poll())
    gen2 = await ready_again(r, gen1.number)
    await r.clock.run_task(polling)
    assert gen1.node.closed
    assert gen2.number == gen1.number + 1
    if reason is not None:
        assert r.conn.stats.last_failure == f"transport:{reason}"
    assert r.inst.r0.connect_count == connects + 1  # a new handshake on a new client
    assert r.inst.r0.session_established
    await run_until(r.clock, lambda: settled(r) and r.core.polls >= 2)
    snap = await poll(r)
    assert all(snap.available.values())
    assert all(m == 0 for m in snap.misses.values())
    await stop(r)


async def test_small_mtu_is_not_fatal() -> None:
    r = e2e_rig()
    issues: list[tuple[ConnectionIssue, bool]] = []
    r.conn.add_issue_listener(lambda issue, active: issues.append((issue, active)))
    r.inst.r0.mtu_size = 100
    gen = await begin(r)
    assert issues == [(ConnectionIssue.MTU_TOO_SMALL, True)]
    assert r.conn.stats.mtu_low
    assert r.conn.state is S.READY
    assert gen.number == 1
    assert all_available(r)  # the valves still work at this MTU
    await stop(r)


async def test_oversized_write_reconnects() -> None:
    r = e2e_rig()
    issues: list[tuple[ConnectionIssue, bool]] = []
    r.conn.add_issue_listener(lambda issue, active: issues.append((issue, active)))
    r.inst.r0.mtu_size = 200  # not "small", but a 100-attribute read does not fit
    r.inst.r0.long_write_supported = False
    gen1 = await begin(r)
    valve = r.inst.valves[0]

    async def large_read() -> None:  # a frame > MTU - 3
        await gen1.node.zcl_read(valve.short, 1, 0x0201, list(range(100)))

    task = r.conn.spawn(gen1, large_read(), name="large read")
    gen2 = await ready_again(r, gen1.number)
    assert task.done()
    assert issues[0] == (ConnectionIssue.LONG_WRITE_UNSUPPORTED, True)
    assert r.conn.stats.last_failure == "transport:long_write_unsupported"
    assert gen2.number == 2
    # the new session opened at the same MTU: cleared until a large frame fails again
    assert issues[-1] == (ConnectionIssue.LONG_WRITE_UNSUPPORTED, False)
    await run_until(r.clock, lambda: settled(r) and r.core.polls >= 2)
    snap = await poll(r)
    assert all(snap.available.values())  # ordinary frames fit
    await stop(r)


@pytest.mark.parametrize("behaviour", ["truncate", "drop", "reject"])
async def test_oversized_indication_miss_path(
    behaviour: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING)
    r = e2e_rig()
    r0 = r.inst.r0
    r0.mtu_size = 100  # below 131 at open: the mtu_low issue is already surfaced
    r0.oversize_indication = behaviour  # type: ignore[assignment]
    await begin(r)
    assert ConnectionIssue.MTU_TOO_SMALL in r.conn.issues
    r0.mtu_size = 30  # from now on every valve response is larger than the MTU
    before = r0.oversized_indications
    snap = await poll(r)
    assert r0.oversized_indications > before
    assert all(m == 1 for m in snap.misses.values())  # timeouts follow the valve-miss path
    assert all(snap.available.values())
    stats = r.conn.transport_stats
    assert stats is not None
    mic_warning = [
        rec for rec in caplog.records if rec.name == TRANSPORT_LOGGER and "MIC" in rec.getMessage()
    ]
    if behaviour == "truncate":
        assert stats.mic_failures >= 3
        assert len(mic_warning) == 1
        assert "mtu=100" in mic_warning[0].getMessage()
    else:
        assert stats.mic_failures == 0
        assert mic_warning == []
    assert r.conn.state is S.READY
    await stop(r)


async def test_replayed_indication_dropped() -> None:
    r = e2e_rig()
    await begin(r)
    stats = r.conn.transport_stats
    node_stats = r.conn.last_node_stats
    assert stats is not None
    assert node_stats is not None
    rx = stats.frames_rx
    reports = node_stats.reports
    before = r.snap()
    r.inst.r0.inject_replayed_indication()
    await r.clock.advance(0)
    assert stats.replay_drops == 1
    assert stats.mic_failures == 0  # counted separately
    assert stats.frames_rx == rx
    assert node_stats.reports == reports
    assert r.snap().states == before.states
    assert r.conn.state is S.READY
    snap = await poll(r)
    assert all(snap.available.values())
    await stop(r)


async def test_stale_gatt_cache_cleared_once() -> None:
    r = e2e_rig()
    gen1 = await begin(r)
    r.inst.r0.stale_services = True  # e.g. after an R0 firmware update
    r.inst.r0.disconnect()
    gen2 = await ready_again(r, gen1.number)
    assert r.conn.stats.cache_clears == 1
    assert r.conn.stats.last_transport_error == "missing_characteristic"
    assert not r.inst.r0.stale_services
    assert gen2.number == 2
    await run_until(r.clock, lambda: settled(r) and r.core.polls >= 2)
    assert all_available(r)
    await stop(r)
