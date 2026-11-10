from typing import Any

from pydantic import BaseModel


class ProcessInfo(BaseModel):
    name: str | None = None
    pid: int | None = None
    parent_pid: int | None = None
    command_line: str | None = None


class NetworkInfo(BaseModel):
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: str | None = None


class NormalizedEvent(BaseModel):
    schema_version: str
    event_id: str
    timestamp: str
    event_type: str
    source: str
    hostname: str | None = None
    scenario_id: str | None = None
    synthetic: bool
    severity: str
    process: ProcessInfo
    network: NetworkInfo
    raw_data: dict[str, Any]


class EventResponse(NormalizedEvent):
    id: int
