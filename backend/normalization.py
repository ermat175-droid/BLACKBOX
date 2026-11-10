from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def _pick(sources: list[dict], *keys: str) -> Any:
    """Возвращает первое найденное непустое значение."""
    for source in sources:
        if not isinstance(source, dict):
            continue

        for key in keys:
            value = source.get(key)
            if value is not None and value != "":
                return value

    return None


def _to_int(value: Any, field: str) -> int | None:
    if value is None:
        return None

    try:
        return int(value)
    except (ValueError, TypeError):
        raise ValueError(f"Invalid integer in field '{field}': {value}")


def _normalize_timestamp(value: Any) -> str:
    if value is None:
        raise ValueError("Event timestamp is required")

    if isinstance(value, datetime):
        dt = value

    elif isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(value, tz=timezone.utc)

    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"Invalid timestamp: {value}")

    else:
        raise ValueError(f"Unsupported timestamp type: {type(value)}")

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _to_bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes"}

    return bool(value)


def normalize_event(raw: dict) -> dict:
    """Преобразует входное событие в канонический формат."""

    if not isinstance(raw, dict):
        raise ValueError("Event must be a dictionary")

    data = raw.get("data")
    if not isinstance(data, dict):
        data = {}

    process = data.get("process")
    if isinstance(process, str):
        # Flat form used by scenarios: "process": "bash"
        process = {"name": process}
    elif not isinstance(process, dict):
        process = {}

    network = data.get("network")
    if not isinstance(network, dict):
        network = {}

    sources = [process, network, data, raw]

    timestamp = _pick([raw, data], "timestamp", "time")
    event_type = _pick([raw, data], "event_type", "type")

    if not event_type:
        raise ValueError("Event type is required")

    event_id = _pick([raw, data], "event_id", "id")

    severity = _pick([raw, data], "severity") or "info"

    synthetic = _pick([raw, data], "synthetic")

    protocol = _pick(sources, "protocol", "Protocol")

    http_method = _pick(sources, "http_method", "method")
    http_path = _pick(sources, "http_path", "path", "uri", "url")
    http_status = _pick(sources, "http_status", "status", "status_code")

    return {
        "schema_version": "1.0",
        "event_id": str(event_id or uuid4()),
        "timestamp": _normalize_timestamp(timestamp),
        "event_type": str(event_type).strip().lower().replace(" ", "_"),
        "source": str(
            _pick([raw, data], "source", "provider") or "unknown"
        ),
        "hostname": _pick(
            [raw, data], "hostname", "host", "computer", "Computer"
        ),
        "scenario_id": _pick([raw, data], "scenario_id"),
        "synthetic": _to_bool(synthetic),
        "severity": str(severity).strip().lower(),

        "process": {
            # "name" is only trusted inside the process object: at the top
            # level it may describe something else (e.g. a scenario).
            "name": _pick([process], "name") or _pick(
                sources,
                "process_name", "image", "Image", "source_process"
            ),
            "pid": _to_int(
                _pick(sources, "pid", "process_id", "ProcessId"),
                "pid"
            ),
            "parent_pid": _to_int(
                _pick(sources, "parent_pid", "ppid", "ParentProcessId"),
                "parent_pid"
            ),
            "command_line": _pick(
                sources, "command_line", "cmdline", "command"
            ),
            "parent_name": _pick(
                sources, "parent_process_name", "parent_name"
            ),
        },

        "network": {
            "source_ip": _pick(
                sources, "source_ip", "src_ip", "SourceIp"
            ),
            "destination_ip": _pick(
                sources, "destination_ip", "dest_ip", "DestinationIp"
            ),
            "destination_port": _to_int(
                _pick(sources, "destination_port", "dest_port", "DestinationPort"),
                "destination_port"
            ),
            "protocol": str(protocol).upper() if protocol is not None else None,
        },

        "http": {
            "method": str(http_method).upper() if http_method else None,
            "path": http_path,
            "status": _to_int(http_status, "http_status"),
            "user_agent": _pick(sources, "user_agent", "useragent", "ua"),
        },

        "raw_data": raw,
    }
