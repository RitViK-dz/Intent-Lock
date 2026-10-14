"""Pydantic data models for IntentLock request schemas and responses.

Currency Rule: All monetary amounts are stored strictly as integer cents (never floats).
"""

from pydantic import BaseModel, Field


class CreateIntentRequest(BaseModel):
    """Payload submitted by an AI agent to propose a purchase action."""

    agent_id: str = Field(..., min_length=1, max_length=100, description="Identifier of the proposing agent")
    merchant_id: str = Field(..., min_length=1, max_length=100, description="Merchant identifier for the store")
    item: str = Field(..., min_length=1, max_length=200, description="Exact item description/SKU")
    amount_cents: int = Field(..., gt=0, description="Spending amount strictly in integer cents")
    payee_id: str = Field(..., min_length=1, max_length=100, description="Destination payee account")
    summary: str = Field(..., min_length=1, max_length=500, description="Human-readable explanation of the action")


class CreateIntentResponse(BaseModel):
    """Response returned upon successful creation of a pending intent."""

    intent_id: str
    status: str


class IntentResponse(BaseModel):
    """Full detail representation of an intent record."""

    id: str
    agent_id: str
    merchant_id: str
    item: str
    amount_cents: int
    payee_id: str
    summary: str
    status: str
    created_at: int
    decided_at: int | None = None


class ApproveIntentResponse(BaseModel):
    """Response returned when an intent is approved and an authorization token is minted."""

    token: str
    expires_at: int


class RejectIntentResponse(BaseModel):
    """Response returned when an intent is explicitly rejected."""

    intent_id: str
    status: str
