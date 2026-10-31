"""Integration test for pausing and resuming a saved custom workflow."""

import uuid

import pytest
from fastapi.testclient import TestClient

import app as agentguard


@pytest.fixture
def admin_client():
    agentguard.init_db()
    email = f"workflow-resume-{uuid.uuid4().hex}@example.com"

    with agentguard.db() as conn:
        cursor = conn.execute(
            """INSERT INTO users(name,email,password_hash,role,status,created_at)
               VALUES(?,?,?,?,?,?)""",
            (
                "Workflow Resume Test Admin",
                email,
                agentguard.hash_password("TestPassword123!"),
                "admin",
                "active",
                agentguard.now(),
            ),
        )
        user = {
            "id": cursor.lastrowid,
            "name": "Workflow Resume Test Admin",
            "email": email,
            "role": "admin",
            "status": "active",
        }

    agentguard.app.dependency_overrides[agentguard.current_user] = lambda: user
    agentguard.app.dependency_overrides[agentguard.admin_user] = lambda: user

    try:
        with TestClient(agentguard.app) as client:
            yield client
    finally:
        agentguard.app.dependency_overrides.pop(agentguard.current_user, None)
        agentguard.app.dependency_overrides.pop(agentguard.admin_user, None)


def test_custom_workflow_pauses_then_resumes_after_approval(admin_client):
    steps = [
        {
            "id": "fetch-order",
            "type": "tool_call",
            "name": "Fetch simulated order",
            "config": {"tool": "simulated_order_lookup"},
        },
        {
            "id": "manager-approval",
            "type": "approval",
            "name": "Manager approval",
            "config": {"required_for": "High-risk simulated action"},
        },
        {
            "id": "verify-order",
            "type": "validation",
            "name": "Verify order after approval",
            "config": {"required_fields": ["order_id", "status"]},
        },
    ]

    create_response = admin_client.post(
        "/api/workflows",
        json={
            "name": "Approval Resume Integration Test",
            "description": "Temporary automated test workflow",
            "steps": steps,
        },
    )
    assert create_response.status_code == 200, create_response.text
    workflow_id = create_response.json()["id"]

    activate_response = admin_client.patch(
        f"/api/workflows/{workflow_id}",
        json={"status": "active"},
    )
    assert activate_response.status_code == 200, activate_response.text

    execute_response = admin_client.post(
        f"/api/workflows/{workflow_id}/execute"
    )
    assert execute_response.status_code == 200, execute_response.text
    execution = execute_response.json()

    assert execution["status"] == "awaiting_approval"
    assert execution["approval_required"] is True

    run_id = execution["run_id"]
    with agentguard.db() as conn:
        approval = conn.execute(
            """SELECT id, status FROM approvals
               WHERE run_id=? ORDER BY id DESC LIMIT 1""",
            (run_id,),
        ).fetchone()

    assert approval is not None
    assert approval["status"] == "pending"

    decision_response = admin_client.post(
        f"/api/approvals/{approval['id']}/decision",
        json={
            "decision": "approved",
            "note": "Approved by automated integration test",
        },
    )
    assert decision_response.status_code == 200, decision_response.text
    decision = decision_response.json()

    assert decision["status"] == "verified"
    assert decision["approval_required"] is False

    with agentguard.db() as conn:
        run = conn.execute(
            "SELECT status, metrics, trace, resume_step FROM runs WHERE id=?",
            (run_id,),
        ).fetchone()
        saved_approval = conn.execute(
            "SELECT status FROM approvals WHERE id=?",
            (approval["id"],),
        ).fetchone()
        resume_audit = conn.execute(
            """SELECT id FROM audit
               WHERE event='workflow.resumed' AND detail LIKE ?
               ORDER BY id DESC LIMIT 1""",
            (f"%Run #{run_id}%",),
        ).fetchone()

    assert run["status"] == "verified"
    assert run["resume_step"] == len(steps)
    assert saved_approval["status"] == "approved"
    assert resume_audit is not None

    metrics = agentguard.json.loads(run["metrics"])
    trace = agentguard.json.loads(run["trace"])
    assert metrics["tool_calls"] == 1
    assert metrics["validations_passed"] == 1
    assert any("Resuming workflow" in item["message"] for item in trace)
    assert any(item["step"] == "Independent verifier" and item["state"] == "success" for item in trace)
