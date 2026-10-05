"""Shared result types and reason codes. Defined by the API contract (docs/api-contract.md, section 8)."""
from dataclasses import dataclass

# Reason codes (section 4 of the contract)
VALID = "valid"
MALFORMED = "malformed"
UNKNOWN_KEY = "unknown_key"
INVALID_SIGNATURE = "invalid_signature"
EXPIRED = "expired"
REPLAYED = "replayed"

# Reason code -> HTTP status
HTTP_STATUS = {
    VALID: 200,
    MALFORMED: 400,
    UNKNOWN_KEY: 401,
    INVALID_SIGNATURE: 401,
    EXPIRED: 400,
    REPLAYED: 409,
}


@dataclass(frozen=True)
class CheckResult:
    ok: bool
    reason: str  # VALID if ok, else one of the reason codes above


@dataclass(frozen=True)
class Decision:
    accepted: bool
    reason: str
    http_status: int
    event_id: str | None = None
    key_id: str | None = None