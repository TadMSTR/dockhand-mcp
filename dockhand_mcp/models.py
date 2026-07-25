"""Pydantic models for Dockhand API responses."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    timestamp: Optional[str] = None


class Container(BaseModel):
    id: str
    name: str
    image: Optional[str] = None
    status: Optional[str] = None
    state: Optional[str] = None
    created: Optional[str] = None
    uptime: Optional[str] = None
    environment_id: Optional[int] = Field(None, alias="environmentId")
    environment_name: Optional[str] = Field(None, alias="environmentName")

    model_config = {"populate_by_name": True, "extra": "allow"}


class Stack(BaseModel):
    name: str
    status: Optional[str] = None
    container_count: Optional[int] = Field(None, alias="containerCount")
    environment_id: Optional[int] = Field(None, alias="environmentId")
    environment_name: Optional[str] = Field(None, alias="environmentName")

    model_config = {"populate_by_name": True, "extra": "allow"}


class JobResponse(BaseModel):
    job_id: str = Field(alias="jobId")

    model_config = {"populate_by_name": True}


class ActivityEvent(BaseModel):
    id: Optional[int] = None
    container_id: Optional[str] = Field(None, alias="containerId")
    container_name: Optional[str] = Field(None, alias="containerName")
    image: Optional[str] = None
    action: Optional[str] = None
    timestamp: Optional[str] = None
    environment_name: Optional[str] = Field(None, alias="environmentName")

    model_config = {"populate_by_name": True, "extra": "allow"}


class ActivityResponse(BaseModel):
    events: list[ActivityEvent] = []
    total: int = 0
    limit: int = 20
    offset: int = 0
