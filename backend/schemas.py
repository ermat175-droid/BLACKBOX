from datetime import datetime
from pydantic import BaseModel


class EventCreate(BaseModel):
    source: str
    event_type: str
    timestamp: datetime
    severity: str
    data: dict


class EventResponse(EventCreate):
    id: int

    class Config:
        from_attributes = True
