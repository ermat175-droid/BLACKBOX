import threading
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import Body, Depends, FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from sqlalchemy.orm import Session

STATIC_DIR = Path(__file__).resolve().parent / "static"

from backend.correlation import correlate
from backend.database import Base, SessionLocal, engine
from backend.integrity import GENESIS, link, verify_chain
from backend.models import Event
from backend.normalization import normalize_event
from backend.reconstruction import reconstruct
from backend.infrastructure import discover, impact
from backend.validation import validate
from backend.defense import generate_rules
from backend.schemas import EventResponse
from backend import targets as targets_mod


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="BLACKBOX",
    description="Cyber Investigation Platform",
    version="0.2.0",
    lifespan=lifespan,
)


# The chain of custody is append-only and order-sensitive: reading the
# previous head and inserting the next link must not interleave across the
# concurrent collector POSTs, or two events share a prev_hash and the chain
# verifies as broken. Serialize that critical section.
_ingest_lock = threading.Lock()


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


def to_response(event: Event) -> dict:
    return {"id": event.id, **event.normalized}


@app.get("/")
def root():
    return {
        "project": "BLACKBOX",
        "status": "online"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/scenarios")
def list_scenarios(db: Session = Depends(get_db)):
    rows = db.execute(
        select(
            Event.scenario_id,
            func.count(Event.id),
            func.min(Event.timestamp),
            func.max(Event.timestamp),
        )
        .where(Event.scenario_id.is_not(None))
        .group_by(Event.scenario_id)
        .order_by(func.max(Event.timestamp).desc())
    ).all()

    return [
        {
            "scenario_id": sid,
            "event_count": count,
            "first_seen": first.isoformat() if first else None,
            "last_seen": last.isoformat() if last else None,
        }
        for sid, count, first, last in rows
    ]


@app.post("/events", response_model=EventResponse, status_code=201)
def create_event(
    raw: dict[str, Any] = Body(...),
    db: Session = Depends(get_db)
):
    try:
        normalized = normalize_event(raw)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error))

    exists = db.scalar(
        select(Event.id).where(Event.event_id == normalized["event_id"])
    )
    if exists is not None:
        raise HTTPException(
            status_code=409,
            detail=f"Event {normalized['event_id']} already exists"
        )

    process = normalized["process"]
    network = normalized["network"]
    http = normalized["http"]

    event = Event(
        event_id=normalized["event_id"],
        timestamp=datetime.fromisoformat(normalized["timestamp"]),
        event_type=normalized["event_type"],
        source=normalized["source"],
        severity=normalized["severity"],
        hostname=normalized["hostname"],
        scenario_id=normalized["scenario_id"],
        synthetic=normalized["synthetic"],
        process_name=process["name"],
        pid=process["pid"],
        parent_pid=process["parent_pid"],
        destination_ip=network["destination_ip"],
        destination_port=network["destination_port"],
        http_method=http["method"],
        http_path=http["path"],
        http_status=http["status"],
        normalized=normalized,
        raw_data=raw,
    )

    # Append to the tamper-evident chain of custody (ingestion order).
    # Reading the head and inserting the next link is serialized so
    # concurrent collector POSTs cannot share a prev_hash.
    with _ingest_lock:
        prev_hash = db.scalar(
            select(Event.chain_hash).order_by(Event.id.desc()).limit(1)
        ) or GENESIS
        content, chain = link(prev_hash, normalized)
        event.content_hash = content
        event.prev_hash = prev_hash
        event.chain_hash = chain

        db.add(event)
        db.commit()

    db.refresh(event)

    return to_response(event)


@app.get("/events", response_model=list[EventResponse])
def get_events(
    scenario_id: str | None = None,
    event_type: str | None = None,
    hostname: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    query = select(Event)

    if scenario_id:
        query = query.where(Event.scenario_id == scenario_id)
    if event_type:
        query = query.where(Event.event_type == event_type)
    if hostname:
        query = query.where(Event.hostname == hostname)

    query = query.order_by(Event.timestamp, Event.id).limit(limit).offset(offset)

    return [to_response(event) for event in db.scalars(query)]


@app.get("/events/{event_id}", response_model=EventResponse)
def get_event(event_id: int, db: Session = Depends(get_db)):
    event = db.get(Event, event_id)

    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")

    return to_response(event)


@app.get("/incidents/{scenario_id}/graph")
def incident_graph(scenario_id: str, db: Session = Depends(get_db)):
    query = (
        select(Event)
        .where(Event.scenario_id == scenario_id)
        .order_by(Event.timestamp, Event.id)
    )
    events = [event.normalized for event in db.scalars(query)]

    if not events:
        raise HTTPException(
            status_code=404,
            detail=f"No events for scenario {scenario_id}"
        )

    graph = correlate(events)
    graph["scenario_id"] = scenario_id
    graph["event_count"] = len(events)
    return graph


@app.get("/integrity")
def integrity(db: Session = Depends(get_db)):
    """Verify the tamper-evident chain of custody over all stored events."""
    rows = list(db.scalars(select(Event).order_by(Event.id)))
    result = verify_chain(rows)
    result["genesis"] = GENESIS
    return result


def _event_label(e: dict) -> str:
    """Short human label for a timeline row."""
    if e["event_type"] == "http_request":
        h = e.get("http") or {}
        return f"{h.get('method') or ''} {h.get('path') or ''}".strip()
    if e["event_type"] == "network_connection":
        n = e.get("network") or {}
        return f"{n.get('destination_ip')}:{n.get('destination_port')}"
    p = e.get("process") or {}
    pid = p.get("pid")
    return f"{p.get('name') or '?'}" + (f" (pid {pid})" if pid else "")


@app.get("/incidents/{scenario_id}/timeline")
def incident_timeline(scenario_id: str, db: Session = Depends(get_db)):
    rows = list(
        db.scalars(
            select(Event)
            .where(Event.scenario_id == scenario_id)
            .order_by(Event.timestamp, Event.id)
        )
    )
    if not rows:
        raise HTTPException(
            status_code=404,
            detail=f"No events for scenario {scenario_id}"
        )

    events = [r.normalized for r in rows]
    graph = correlate(events)
    recon = reconstruct(events, graph)

    # event_id -> stages it is evidence for, and a representative confidence.
    stage_of: dict[str, list[dict]] = {}
    for stage in recon["stages"]:
        for eid in stage["evidence"]:
            stage_of.setdefault(eid, []).append(
                {"key": stage["key"], "order": stage["order"],
                 "confidence": stage["confidence"]}
            )

    entries = []
    for r in rows:
        e = r.normalized
        eid = e["event_id"]
        entries.append({
            "event_id": eid,
            "timestamp": e["timestamp"],
            "event_type": e["event_type"],
            "severity": e.get("severity"),
            "source": e.get("source"),
            "label": _event_label(e),
            "stages": stage_of.get(eid, []),
            "chain_hash": r.chain_hash,
        })

    return {
        "scenario_id": scenario_id,
        "event_count": len(entries),
        "stage_count": recon["stage_count"],
        "entries": entries,
    }


def _events_for(scenario_id: str, db: Session) -> list[dict]:
    rows = db.scalars(
        select(Event).where(Event.scenario_id == scenario_id)
        .order_by(Event.timestamp, Event.id)
    )
    events = [e.normalized for e in rows]
    if not events:
        raise HTTPException(
            status_code=404, detail=f"No events for scenario {scenario_id}")
    return events


@app.get("/incidents/{scenario_id}/infrastructure")
def incident_infrastructure(scenario_id: str, db: Session = Depends(get_db)):
    events = _events_for(scenario_id, db)
    recon = reconstruct(events, correlate(events))
    result = discover(events, recon)
    result["scenario_id"] = scenario_id
    return result


@app.get("/incidents/{scenario_id}/impact")
def incident_impact(scenario_id: str, db: Session = Depends(get_db)):
    events = _events_for(scenario_id, db)
    recon = reconstruct(events, correlate(events))
    result = impact(events, recon)
    result["scenario_id"] = scenario_id
    return result


@app.get("/incidents/{scenario_id}/rules")
def incident_rules(scenario_id: str, db: Session = Depends(get_db)):
    events = _events_for(scenario_id, db)
    recon = reconstruct(events, correlate(events))
    result = generate_rules(recon)
    result["scenario_id"] = scenario_id
    return result


@app.post("/incidents/{scenario_id}/validate")
def incident_validate(
    scenario_id: str,
    body: dict[str, Any] = Body(...),
    db: Session = Depends(get_db),
):
    """Validate the reconstruction against an attacker-submitted action log."""
    actions = body.get("actions")
    if not isinstance(actions, list):
        raise HTTPException(status_code=422, detail="body.actions must be a list")
    events = _events_for(scenario_id, db)
    recon = reconstruct(events, correlate(events))
    result = validate(actions, events, recon)
    result["scenario_id"] = scenario_id
    result["attacker"] = body.get("attacker")
    return result


@app.get("/incidents/{scenario_id}/reconstruction")
def incident_reconstruction(scenario_id: str, db: Session = Depends(get_db)):
    query = (
        select(Event)
        .where(Event.scenario_id == scenario_id)
        .order_by(Event.timestamp, Event.id)
    )
    events = [event.normalized for event in db.scalars(query)]

    if not events:
        raise HTTPException(
            status_code=404,
            detail=f"No events for scenario {scenario_id}"
        )

    graph = correlate(events)
    result = reconstruct(events, graph)
    result["scenario_id"] = scenario_id
    result["event_count"] = len(events)
    return result


# --- Target Manager: load / run / monitor sandboxed attack targets ---------
def _target_or_400(fn, *args):
    try:
        return fn(*args)
    except targets_mod.TargetError as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.get("/docker/images")
def docker_images():
    return _target_or_400(targets_mod.list_local_images)


@app.get("/targets")
def targets_list():
    return _target_or_400(targets_mod.list_targets)


@app.post("/targets", status_code=201)
def targets_add(body: dict[str, Any] = Body(...)):
    name = body.get("name")
    source = body.get("source")
    if not name or source is None:
        raise HTTPException(status_code=422, detail="name and source are required")
    return _target_or_400(
        targets_mod.add_target, name, source,
        body.get("container_port", 80), body.get("host_port"),
        body.get("isolated", True),
    )


@app.post("/targets/{target_id}/start")
def targets_start(target_id: str):
    return _target_or_400(targets_mod.start_target, target_id)


@app.post("/targets/{target_id}/stop")
def targets_stop(target_id: str):
    return _target_or_400(targets_mod.stop_target, target_id)


@app.delete("/targets/{target_id}", status_code=204)
def targets_remove(target_id: str):
    _target_or_400(targets_mod.remove_target, target_id)


@app.get("/sensor")
def sensor_status():
    return _target_or_400(targets_mod.sensor_status)


@app.post("/sensor/start")
def sensor_start():
    return _target_or_400(targets_mod.sensor_start)


@app.post("/sensor/stop")
def sensor_stop():
    return _target_or_400(targets_mod.sensor_stop)


# The web UI is served at /ui (mounted last so it never shadows the API).
app.mount("/ui", StaticFiles(directory=STATIC_DIR, html=True), name="ui")
