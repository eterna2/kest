import enum
from typing import Any, Dict, Generic, List, Optional, TypeVar

import uuid_utils
from pydantic import BaseModel, ConfigDict, Field


class KestNodeType(str, enum.Enum):
    SYSTEM = "system"
    DATA = "data"
    SANITIZER = "sanitizer"
    CRITIC = "critic"
    SNAPSHOT = "snapshot"


class KestCognition(BaseModel):
    model_profile: Optional[str] = None
    generation_config: Optional[Dict[str, Any]] = None
    system_prompt_hash: Optional[str] = None
    context_refs: List[str] = Field(default_factory=list)
    confidence_score: Optional[float] = None


class KestEntry(BaseModel):
    model_config = ConfigDict(strict=False)

    entry_id: str = Field(default_factory=lambda: str(uuid_utils.uuid7()))
    parent_entry_ids: List[str] = Field(default_factory=list)
    node_type: KestNodeType = Field(default=KestNodeType.SYSTEM)
    node_id: str
    timestamp_ms: int
    input_state_hash: str
    content_hash: str
    environment: Dict[str, str] = Field(default_factory=dict)
    labels: Dict[str, str] = Field(default_factory=dict)
    added_taint: List[str] = Field(default_factory=list)
    accumulated_taint: List[str] = Field(default_factory=list)
    trust_score: float = Field(default=1.0)
    cognition: Optional[KestCognition] = None


class PassportOriginPolicies(BaseModel):
    curated_refs: List[str] = Field(default_factory=list)
    inline_rules: Optional[str] = None


class PassportOrigin(BaseModel):
    user_id: str
    session_id: str
    policies: PassportOriginPolicies = Field(default_factory=PassportOriginPolicies)


class KestPassport(BaseModel):
    origin: PassportOrigin
    history: Dict[str, KestEntry] = Field(default_factory=dict)


T = TypeVar("T")


class KestData(BaseModel, Generic[T]):
    data: T
    passport: Optional[KestPassport] = None
