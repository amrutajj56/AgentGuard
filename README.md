# AgentGuard — Local-first hackathon build

AgentGuard is a runnable prototype of a reliability and governance layer for tool-using AI workflows. It demonstrates workflow validation, simulated tool execution, bounded scenario handling, human approval gates, execution traces, and independent verification of a simulated final state.

> **Prototype boundary:** this build uses deterministic simulated tools and synthetic data. It does not connect to real customer systems, process payments/refunds, or execute arbitrary external tools. Some broader product areas are roadmap/demo concepts rather than fully implemented backend modules. Do not present them as production-ready features.

## Quick start — Windows

1. Install Python 3.10 or newer (Python 3.13 is supported by the tested setup).
2. Extract the ZIP.
3. Open the extracted `AgentGuard` folder.
4. Double-click `setup_windows.bat` once.
5. Double-click `run_windows.bat` to start the app.
6. Open <http://127.0.0.1:8000>.

### Admin account

The initial admin account is seeded from `AGENTGUARD_ADMIN_EMAIL` and
`AGENTGUARD_ADMIN_PASSWORD` when the database is first initialized.
Set unique credentials through environment variables before deployment.
Changing these variables after an account already exists does not reset
that account's password.

### PowerShell alternative

Run these commands from the folder containing `app.py`:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:AGENTGUARD_SECRET="replace-with-a-long-random-local-secret"
$env:AGENTGUARD_ADMIN_EMAIL="admin@agentguard.local"
$env:AGENTGUARD_ADMIN_PASSWORD="ChangeThis-Now-123!"
.\.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

If PowerShell blocks virtual-environment activation, these commands avoid activation entirely.

## Run automated tests

Double-click `test_windows.bat`, or run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests -v
```

The packaged test suite covers:

- Homepage and health endpoint smoke checks.
- Workflow step validation and malformed configuration rejection.
- Workflow step-count limits.
- Simulated tool-call and validation execution.
- Approval pause behavior.
- Standard approval, rejection, invalid decision and duplicate decision handling.
- Custom workflow execution pausing at an approval gate, resuming after approval, and reaching the independent simulated-state verifier.

The build was checked with **14 passing tests** in the packaging environment. Run the tests again on your machine after extraction; dependency and platform differences can affect results.

## Implemented in this build

- FastAPI backend and SQLite persistence.
- Password hashing, session-cookie authentication, registration and admin/user role checks.
- Admin-created accounts and user status management.
- Dashboard and run history.
- Agent create/list/detail/update APIs.
- Workflow create/list/detail/update APIs, workflow activation and execution.
- Workflow step validation (`tool_call`, `validation`, `approval`) and a maximum of 30 steps.
- Deterministic simulated tool calls and final-state verification.
- Approval queue, approve/reject decisions, and custom-workflow resume from the saved step.
- Execution traces and metrics persisted with runs.
- Audit log and CSV run export.
- Original synthetic fault-injection dataset at `datasets/agentguard_fault_injection_v1.json`.

## Planned or illustrative areas

The wider product vision includes advanced prompt-injection and data-leak detection, live monitoring/alerts, a full policy engine, benchmark dashboards, incident management, compliance reports, API keys, external integrations, webhooks, team workspaces, and cost analytics. These are not all implemented as functioning backend modules in this ZIP. The Policy Settings screen is explicitly illustrative and is not persisted or dynamically applied.

The included dataset contains ten synthetic test specifications. Some cases (for example prompt injection, permissions, sensitive-data handling, duplicate side effects) are roadmap test cases and are not all wired into the current runtime simulator. Dataset expected outcomes are specifications, not measured experimental results.

## Project structure

```text
AgentGuard/
  app.py
  requirements.txt
  static/index.html
  datasets/agentguard_fault_injection_v1.json
  tests/
    test_smoke.py
    test_workflows.py
    test_approval_lifecycle.py
    test_custom_workflow_resume.py
  .vscode/
  setup_windows.bat
  run_windows.bat
  test_windows.bat
```

## Local data and safety

- SQLite database: `agentguard.db` (created automatically on first start).
- Do not commit or share your live database; it may contain account and execution data.
- Keep the server bound to `127.0.0.1`; do not expose this development server to the public internet.
- Set a strong `AGENTGUARD_SECRET` and a strong admin password before any shared demo.
- This is an educational hackathon prototype, not a security-certified production service.
- Use actual measurements from your own runs in presentations; do not claim synthetic expected outcomes are benchmark results.

## Free/local-first stack

Python, FastAPI, SQLite, Pydantic, vanilla HTML/CSS/JavaScript and pytest. The core demo requires no paid API key or hosted service. Internet is needed only to install Python packages initially.
