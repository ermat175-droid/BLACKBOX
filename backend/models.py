from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base


class Event(Base):
    """A normalized event.

    Key fields are duplicated into indexed columns so that detection and
    correlation can query them directly (e.g. "find the parent of PID 1100").
    The full canonical event lives in `normalized`, and the untouched input
    is kept in `raw_data` as evidence.
    """

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[str] = mapped_column(String(64), unique=True)

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True
    )
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    event_type: Mapped[str] = mapped_column(String(100), index=True)
    source: Mapped[str] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(20))
    hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    scenario_id: Mapped[str | None] = mapped_column(String(100), index=True)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False)

    process_name: Mapped[str | None] = mapped_column(String(255), index=True)
    pid: Mapped[int | None] = mapped_column(Integer, index=True)
    parent_pid: Mapped[int | None] = mapped_column(Integer, index=True)

    destination_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    destination_port: Mapped[int | None] = mapped_column(Integer)

    http_method: Mapped[str | None] = mapped_column(String(10))
    http_path: Mapped[str | None] = mapped_column(String(2048), index=True)
    http_status: Mapped[int | None] = mapped_column(Integer)

    normalized: Mapped[dict] = mapped_column(JSON)
    raw_data: Mapped[dict] = mapped_column(JSON)
