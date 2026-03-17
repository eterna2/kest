from typing import Dict, Generic, List, Optional, TypeVar

from pydantic import BaseModel, ConfigDict, Field


class KestEntry(BaseModel):
    model_config = ConfigDict(strict=False)

    entry_id: str
    parent_entry_ids: List[str]
    node_id: str
    timestamp_ms: int
    input_state_hash: str
    content_hash: str
    environment: Dict[str, str] = Field(default_factory=dict)
    labels: Dict[str, str] = Field(default_factory=dict)
    added_taint: List[str] = Field(default_factory=list)
    accumulated_taint: List[str] = Field(default_factory=list)
    trust_score: float = Field(default=1.0)


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
    signature: str
    public_key_id: str


T = TypeVar("T")


class KestData(BaseModel, Generic[T]):
    data: T
    passport: Optional[KestPassport] = None
