"""Demo API router for executing simulated agent attack scenarios."""

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.testclient import TestClient

from agent_sim.scenarios import list_scenarios, get_scenario
from agent_sim.naive_agent import run_scenario
from app.models import RunDemoRequest, RunDemoResponse

router = APIRouter(prefix="/api/demo", tags=["demo"])


@router.get(
    "/scenarios",
    summary="List pre-configured prompt injection attack scenarios",
)
def get_scenarios() -> list[dict]:
    """Return all available demonstration scenarios (S0 to S5)."""
    return list_scenarios()


@router.post(
    "/run",
    response_model=RunDemoResponse,
    summary="Execute a simulated attack scenario in protected or unprotected mode",
)
def execute_scenario(demo_req: RunDemoRequest, request: Request) -> RunDemoResponse:
    """Run an automated attack simulation demonstrating the before/after protection of IntentLock.

    auto_approve=true simulates the human clicking Approve on the ORIGINAL task,
    calling the real /api/intents/{id}/approve endpoint without bypassing verification.
    """
    scenario = get_scenario(demo_req.scenario_id)
    if not scenario:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scenario '{demo_req.scenario_id}' not found",
        )

    # Use internal TestClient using current FastAPI app to dispatch without circular imports
    client = TestClient(request.app)

    result = run_scenario(
        scenario_id=demo_req.scenario_id,
        protected=demo_req.protected,
        auto_approve=demo_req.auto_approve,
        client=client,
    )

    return RunDemoResponse(
        trace=result["trace"],
        outcome=result["outcome"],
        orders_created=result["orders_created"],
        reason=result.get("reason"),
    )
