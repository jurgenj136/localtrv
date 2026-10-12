"""Config entry diagnostics, built from an explicit allowlist (spec §2.6, #2).

Nothing is serialised generically: every field below is named. Never included: the network
key, the BAK, the raw Commissioning Status, ``entry.data`` (only "has ..." booleans), the R0's
Bluetooth address. EUIs and the extended PAN go through the recorder's ``EuiPseudonymizer``,
so they match the pseudonyms in the (already redacted) NPDU ring buffer; valves are labelled
``valve_n``.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from .const import (
    CONF_NETWORK_KEY,
    CONF_ROUTE_REPLY_MODE,
    CONF_SCAN_INTERVAL,
    CONF_ZDD_EUI,
    CONF_ZVD_EUI,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from homeassistant.core import HomeAssistant

    from vicare_local_ble.bridge import BridgeSnapshot, DiscoveryStatus, SetpointStatus
    from vicare_local_ble.valves import Valve, ValveState
    from vicare_local_ble.zigbee_direct.connection import ZdConnection
    from vicare_local_ble.zigbee_direct.debug import EuiPseudonymizer
    from vicare_local_ble.zigbee_direct.node import JoinInfo, NodeStats
    from vicare_local_ble.zigbee_direct.transport import TransportStats
    from vicare_local_ble.zigbee_direct.types import Eui64

    from .coordinator import VicareConfigEntry


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: VicareConfigEntry
) -> dict[str, Any]:
    """Diagnostics of one entry (module docstring)."""
    runtime = entry.runtime_data
    connection = runtime.connection
    pseudonyms = runtime.recorder.pseudonyms
    snapshot = runtime.bridge.snapshot()
    labels = {eui: f"valve_{n}" for n, eui in enumerate(sorted(snapshot.valves, key=str), 1)}
    return {
        "entry": {
            "options": {
                CONF_SCAN_INTERVAL: entry.options.get(CONF_SCAN_INTERVAL),
                CONF_ROUTE_REPLY_MODE: entry.options.get(CONF_ROUTE_REPLY_MODE),
            },
            "has_network_key": bool(entry.data.get(CONF_NETWORK_KEY)),
            "has_zvd_eui": bool(entry.data.get(CONF_ZVD_EUI)),
            "has_zdd_eui": bool(entry.data.get(CONF_ZDD_EUI)),
        },
        "connection": _connection(connection),
        "transport": _transport(connection.transport_stats),
        "node": _node(connection.last_node_stats),
        "join": _join(connection.last_join, pseudonyms),
        "bridge": _bridge(snapshot, labels),
        "valves": {
            labels[eui]: _valve(snapshot, eui, valve, pseudonyms)
            for eui, valve in snapshot.valves.items()
        },
        "npdu_records": [json.loads(record.to_json()) for record in runtime.recorder.records()],
    }


def _connection(connection: ZdConnection) -> dict[str, Any]:
    stats = connection.stats
    return {
        "state": connection.state.value,
        "generation": stats.generation,
        "attempts": stats.attempts,
        "connects": stats.connects,
        "connect_failures": stats.connect_failures,
        "auth_failures": stats.auth_failures,
        "disconnects": stats.disconnects,
        "rejoins": stats.rejoins,
        "cache_clears": stats.cache_clears,
        "address_conflicts": stats.address_conflicts,
        "backoff": stats.backoff,
        "last_failure": stats.last_failure,
        "last_transport_error": stats.last_transport_error,
        "mtu": stats.mtu,
        "mtu_low": stats.mtu_low,
        "ready_since": stats.ready_since,
        "issues": sorted(issue.value for issue in connection.issues),
    }


def _transport(stats: TransportStats | None) -> dict[str, Any] | None:
    if stats is None:
        return None
    return {
        "counter_model": str(stats.counter_model),
        "replay_drops": stats.replay_drops,
        "mic_failures": stats.mic_failures,
        "tlv_errors": stats.tlv_errors,
        "frames_rx": stats.frames_rx,
        "frames_tx": stats.frames_tx,
    }


def _node(stats: NodeStats | None) -> dict[str, Any] | None:
    if stats is None:
        return None
    return {
        "timeouts": stats.timeouts,
        "retransmits": stats.retransmits,
        "late_drops": stats.late_drops,
        "fallback_hits": stats.fallback_hits,
        "mfr_header_missing": stats.mfr_header_missing,
        "decode_errors": stats.decode_errors,
        "unmatched": stats.unmatched,
        "reports": stats.reports,
        "device_annces": stats.device_annces,
        "network_status": stats.network_status,
        "rreq_seen": stats.rreq_seen,
        "rrep_sent": stats.rrep_sent,
        "mtorr_sent": stats.mtorr_sent,
    }


def _join(join: JoinInfo | None, pseudonyms: EuiPseudonymizer) -> dict[str, Any] | None:
    if join is None:
        return None
    network = join.network
    masks = network.channel_masks
    return {
        "own_short": join.own_short,
        "requested_short": join.requested_short,
        "zdd_short": join.zdd_short,
        "zdd_eui": _pseudo(join.zdd_eui, pseudonyms),
        "pan_id": network.pan_id,
        "extended_pan_id": (
            None
            if network.extended_pan_id is None
            else str(pseudonyms.extended_pan(network.extended_pan_id))
        ),
        "trust_center": (
            None
            if network.trust_center_address is None
            else _pseudo(network.trust_center_address, pseudonyms)
        ),
        "channels": (
            None
            if masks is None
            else [{"page": mask.page, "channels": list(mask.channels)} for mask in masks]
        ),
        "device_type": network.device_type,
        "joined_status": network.joined_status,
    }


def _bridge(snapshot: BridgeSnapshot, labels: Mapping[Eui64, str]) -> dict[str, Any]:
    return {
        "connection_state": snapshot.connection_state.value,
        "generation": snapshot.generation,
        "own_short": snapshot.own_short,
        "valves": len(snapshot.valves),
        "discovery": _discovery(snapshot.discovery, labels),
    }


def _discovery(status: DiscoveryStatus, labels: Mapping[Eui64, str]) -> dict[str, Any]:
    topology = status.topology
    return {
        "running": status.running,
        "last_run": status.last_run,
        "complete": status.complete,
        "valves_found": status.valves_found,
        "attempts": status.attempts,
        "next_retry": status.next_retry,
        "topology": (
            None
            if topology is None
            else {
                "complete": topology.complete,
                "routers": topology.routers,
                "neighbors": topology.neighbors,
                "walked_at": topology.walked_at,
                "parent_short": {
                    labels.get(eui, "other"): short for eui, short in topology.parent_of.items()
                },
            }
        ),
    }


def _valve(
    snapshot: BridgeSnapshot, eui: Eui64, valve: Valve, pseudonyms: EuiPseudonymizer
) -> dict[str, Any]:
    limits = valve.limits
    return {
        "eui": _pseudo(eui, pseudonyms),
        "short": valve.short,
        "endpoint": valve.endpoint,
        "manufacturer": valve.manufacturer,
        "model": valve.model,
        "sw_build": valve.sw_build,
        "limits": {"min_c": limits.min_c, "max_c": limits.max_c, "source": limits.source},
        "available": snapshot.available.get(eui, False),
        "misses": snapshot.misses.get(eui, 0),
        "state": _state(snapshot.states.get(eui)),
        "setpoint": _setpoint(snapshot.setpoints.get(eui)),
    }


def _state(state: ValveState | None) -> dict[str, Any] | None:
    if state is None:
        return None
    return {
        "local_temperature_c": state.local_temperature_c,
        "setpoint_c": state.setpoint_c,
        "heating_demand": state.heating_demand,
        "system_mode_raw": state.system_mode,
        "battery_pct": state.battery_pct,
        "lqi": state.lqi,
        "rssi": state.rssi,
        "window_open_raw": state.window_open_raw,
        "updated_at": state.updated_at,
    }


def _setpoint(status: SetpointStatus | None) -> dict[str, Any] | None:
    if status is None:
        return None
    return {
        "requested_c": status.requested_c,
        "acknowledged_c": status.acknowledged_c,
        "confirmed_c": status.confirmed_c,
        "version": status.version,
        "pending": status.pending,
        "confirmed_at": status.confirmed_at,
    }


def _pseudo(eui: Eui64, pseudonyms: EuiPseudonymizer) -> str:
    return str(pseudonyms.eui(eui))
