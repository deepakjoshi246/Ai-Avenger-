from sqlmodel import SQLModel, Field
from typing import Optional
import datetime

class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    status: str = Field(default="running")
    description: Optional[str] = None

class Event(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id")
    timestamp: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    type: str
    payload: str

class Finding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id")
    title: str
    description: str
    severity: str = Field(default="medium")
    evidence_event_ids: str
    status: str = Field(default="open")

class Remediation(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    finding_id: int = Field(foreign_key="finding.id")
    description: str
    applied: bool = Field(default=False)
    applied_at: Optional[datetime.datetime] = None

