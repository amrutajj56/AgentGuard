
import pytest
from fastapi import HTTPException

from app import (
    validate_workflow_steps,
    execute_custom_workflow_steps,
)


def test_valid_workflow_steps():
    steps = [
        {
            "id": "step1",
            "type": "tool_call",
            "name": "Fetch Order",
            "config": {"tool": "order_lookup"},
        },
        {
            "id": "step2",
            "type": "validation",
            "name": "Validate Order",
            "config": {"required_fields": ["order_id", "status"]},
        },
    ]

    validate_workflow_steps(steps)


def test_unsupported_step_type_is_rejected():
    steps = [
        {"type": "unknown_action", "config": {}}
    ]

    with pytest.raises(HTTPException) as error:
        validate_workflow_steps(steps)

    assert error.value.status_code == 400


def test_malformed_validation_config_is_rejected():
    steps = [
        {
            "type": "validation",
            "config": {"required_fields": "order_id"},
        }
    ]

    with pytest.raises(HTTPException) as error:
        validate_workflow_steps(steps)

    assert error.value.status_code == 400


def test_malformed_approval_config_is_rejected():
    steps = [
        {
            "type": "approval",
            "config": {"required_for": 123},
        }
    ]

    with pytest.raises(HTTPException) as error:
        validate_workflow_steps(steps)

    assert error.value.status_code == 400


def test_workflow_step_limit_is_enforced():
    steps = [
        {"type": "tool_call", "config": {}}
        for _ in range(31)
    ]

    with pytest.raises(HTTPException) as error:
        validate_workflow_steps(steps)

    assert error.value.status_code == 400


def test_tool_call_and_validation_execute():
    steps = [
        {
            "id": "step1",
            "type": "tool_call",
            "name": "Fetch Order",
            "config": {"tool": "order_lookup"},
        },
        {
            "id": "step2",
            "type": "validation",
            "name": "Validate Order",
            "config": {"required_fields": ["order_id", "status"]},
        },
    ]

    status, result, metrics, trace, approval, resume_step, state = (
        execute_custom_workflow_steps(steps, "Automated Test")
    )

    assert status == "verified"
    assert metrics["tool_calls"] == 1
    assert metrics["validations_passed"] == 1
    assert metrics["validations_failed"] == 0
    assert approval is None


def test_approval_step_pauses_workflow():
    steps = [
        {
            "id": "step1",
            "type": "tool_call",
            "name": "Fetch Order",
            "config": {"tool": "order_lookup"},
        },
        {
            "id": "step2",
            "type": "approval",
            "name": "Human Approval",
            "config": {},
        },
        {
            "id": "step3",
            "type": "validation",
            "name": "Post Approval Check",
            "config": {"required_fields": ["order_id", "status"]},
        },
    ]

    status, result, metrics, trace, approval, resume_step, state = (
        execute_custom_workflow_steps(steps, "Approval Test")
    )

    assert status == "awaiting_approval"
    assert approval is not None
    assert resume_step == 2
    assert metrics["approval_gates"] == 1
