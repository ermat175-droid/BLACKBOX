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
from backend.models import Event
from backend.normalization import normalize_event
from backend.reconstruction import reconstruct
from backend.schemas import EventResponse


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


# The web UI is served at /ui (mounted last so it never shadows the API).
app.mount("/ui", StaticFiles(directory=STATIC_DIR, html=True), name="ui")
