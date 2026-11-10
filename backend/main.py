from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session

from backend.database import Base, engine, SessionLocal
from backend.models import Event
from backend.schemas import EventCreate, EventResponse

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="BLACKBOX",
    description="Cyber Investigation Platform",
    version="0.1.0"
)


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


@app.get("/")
def root():
    return {
        "project": "BLACKBOX",
        "status": "online"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/events", response_model=EventResponse)
def create_event(
    event: EventCreate,
    db: Session = Depends(get_db)
):
    new_event = Event(**event.model_dump())

    db.add(new_event)
    db.commit()
    db.refresh(new_event)

    return new_event


@app.get("/events")
def get_events(db: Session = Depends(get_db)):
    return db.query(Event).order_by(Event.id.desc()).all()
