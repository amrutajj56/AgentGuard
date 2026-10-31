
import uuid

import pytest
from fastapi.testclient import TestClient

import app as agentguard


@pytest.fixture(scope="module")
def client():
    agentguard.init_db()

    email = f"approval-test-{uuid.uuid4().hex}@example.com"

    with agentguard.db() as c:
        cur = c.execute(
            """
            INSERT INTO users(
                name, email, password_hash, role, status, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "Approval Test Admin",
                email,
                agentguard.hash_password("TestPassword123!"),
                "admin",
                "active",
                agentguard.now()
            )
        )
        user_id = cur.lastrowid

    test_user = {
        "id": user_id,
        "name": "Approval Test Admin",
        "email": email,
        "role": "admin",
        "status": "active"
    }

    agentguard.app.dependency_overrides[
        agentguard.current_user
    ] = lambda: test_user

    agentguard.app.dependency_overrides[
        agentguard.admin_user
    ] = lambda: test_user

    with TestClient(agentguard.app) as test_client:
        yield test_client

    agentguard.app.dependency_overrides.clear()


def find_approval_scenario():
    scenarios = agentguard.SCENARIOS

    if isinstance(scenarios, dict):
        scenario_names = list(scenarios.keys())
    else:
        scenario_names = list(scenarios)

    for scenario in scenario_names:
        result = agentguard.execute_workflow(
            scenario,
            "Test high-risk refund approval",
            True
        )

        if result[4]:
            return scenario

    pytest.fail(
        "No guarded scenario generated an approval request. "
        "Check the SCENARIOS configuration."
    )


def create_pending_approval(client):
    scenario = find_approval_scenario()

    response = client.post(
        "/api/runs",
        json={
            "scenario": scenario,
            "task": "Test high-risk refund approval",
            "guarded": True
        }
    )

    assert response.status_code == 200, response.text

    run_data = response.json()

    assert run_data["approval_required"] is True

    with agentguard.db() as c:
        approval = c.execute(
            """
            SELECT id, run_id, status
            FROM approvals
            WHERE run_id=?
            ORDER BY id DESC
            LIMIT 1
            """,
            (run_data["id"],)
        ).fetchone()

    assert approval is not None
    assert approval["status"] == "pending"

    return dict(approval)


def get_run(run_id):
    with agentguard.db() as c:
        row = c.execute(
            "SELECT * FROM runs WHERE id=?",
            (run_id,)
        ).fetchone()

    assert row is not None
    return dict(row)


def test_admin_can_approve_pending_request(client):
    approval = create_pending_approval(client)

    response = client.post(
        f"/api/approvals/{approval['id']}/decision",
        json={
            "decision": "approved",
            "note": "Approved during automated test"
        }
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "verified"

    run = get_run(approval["run_id"])
    assert run["status"] == "verified"

    with agentguard.db() as c:
        saved_approval = c.execute(
            "SELECT status FROM approvals WHERE id=?",
            (approval["id"],)
        ).fetchone()

        audit_entry = c.execute(
            """
            SELECT event FROM audit
            WHERE event='approval.approved'
            AND detail LIKE ?
            ORDER BY id DESC LIMIT 1
            """,
            (f"%{approval['id']}%",)
        ).fetchone()

    assert saved_approval["status"] == "approved"
    assert audit_entry is not None


def test_admin_can_reject_pending_request(client):
    approval = create_pending_approval(client)

    response = client.post(
        f"/api/approvals/{approval['id']}/decision",
        json={
            "decision": "rejected",
            "note": "Rejected during automated test"
        }
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "blocked"

    run = get_run(approval["run_id"])
    assert run["status"] == "blocked"

    with agentguard.db() as c:
        saved_approval = c.execute(
            "SELECT status FROM approvals WHERE id=?",
            (approval["id"],)
        ).fetchone()

        audit_entry = c.execute(
            """
            SELECT event FROM audit
            WHERE event='approval.rejected'
            AND detail LIKE ?
            ORDER BY id DESC LIMIT 1
            """,
            (f"%{approval['id']}%",)
        ).fetchone()

    assert saved_approval["status"] == "rejected"
    assert audit_entry is not None


def test_duplicate_approval_decision_is_rejected(client):
    approval = create_pending_approval(client)

    first_response = client.post(
        f"/api/approvals/{approval['id']}/decision",
        json={
            "decision": "approved",
            "note": "First decision"
        }
    )

    assert first_response.status_code == 200

    second_response = client.post(
        f"/api/approvals/{approval['id']}/decision",
        json={
            "decision": "rejected",
            "note": "Duplicate decision"
        }
    )

    assert second_response.status_code == 409


def test_invalid_decision_is_rejected(client):
    approval = create_pending_approval(client)

    response = client.post(
        f"/api/approvals/{approval['id']}/decision",
        json={
            "decision": "maybe",
            "note": "Invalid decision test"
        }
    )

    assert response.status_code == 400

    run = get_run(approval["run_id"])
    assert run["status"] == "awaiting_approval"
