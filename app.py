import os, sqlite3, secrets, hashlib, hmac, time, json, csv, io
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.getenv("AGENTGUARD_DB", os.path.join(BASE, "agentguard.db"))
SECRET = os.getenv("AGENTGUARD_SECRET", "DEV-ONLY-change-this-secret-before-deploying")
ADMIN_EMAIL = os.getenv("AGENTGUARD_ADMIN_EMAIL", "admin@agentguard.local").lower()
ADMIN_PASSWORD = os.getenv("AGENTGUARD_ADMIN_PASSWORD", "ChangeMe123!")
COOKIE = "ag_session"

app = FastAPI(title="AgentGuard", version="1.0.0")
app.mount("/static", StaticFiles(directory=os.path.join(BASE, "static")), name="static")

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def db():
    os.makedirs(os.path.dirname(DB) or ".", exist_ok=True)
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con

def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return salt.hex() + "$" + digest.hex()

def check_password(password, stored):
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 310000).hex()
        return hmac.compare_digest(actual, digest_hex)
    except Exception:
        return False

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
          status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions(
          token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          expires_at INTEGER NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS runs(
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
          scenario TEXT NOT NULL, task TEXT NOT NULL, guarded INTEGER NOT NULL,
          status TEXT NOT NULL, result TEXT NOT NULL, metrics TEXT NOT NULL,
          trace TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS approvals(
          id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER NOT NULL REFERENCES runs(id),
          requested_by INTEGER NOT NULL REFERENCES users(id), action TEXT NOT NULL,
          reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
          decided_by INTEGER REFERENCES users(id), decision_note TEXT DEFAULT '',
          created_at TEXT NOT NULL, decided_at TEXT
        );
        CREATE TABLE IF NOT EXISTS audit(
          id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER REFERENCES users(id),
          event TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL
        );
                CREATE TABLE IF NOT EXISTS agents(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          owner_id INTEGER NOT NULL REFERENCES users(id),
          name TEXT NOT NULL,
          description TEXT NOT NULL DEFAULT '',
          version TEXT NOT NULL DEFAULT '1.0.0',
          capabilities TEXT NOT NULL DEFAULT '[]',
          status TEXT NOT NULL DEFAULT 'active',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
                CREATE TABLE IF NOT EXISTS workflows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            agent_id INTEGER,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            steps TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL DEFAULT 'draft',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(owner_id) REFERENCES users(id),
            FOREIGN KEY(agent_id) REFERENCES agents(id)
        );
        """)
        row = c.execute("SELECT id FROM users WHERE email=?", (ADMIN_EMAIL,)).fetchone()
        
        # Safely migrate existing runs databases.
        run_columns = [
            column["name"]
            for column in c.execute("PRAGMA table_info(runs)").fetchall()
        ]

        if "workflow_id" not in run_columns:
            c.execute("""
                ALTER TABLE runs
                ADD COLUMN workflow_id INTEGER REFERENCES workflows(id)
            """)

        # Refresh column information after migration.
        run_columns = [
            column["name"]
            for column in c.execute("PRAGMA table_info(runs)").fetchall()
        ]

        if "resume_step" not in run_columns:
            c.execute("""
                ALTER TABLE runs
                ADD COLUMN resume_step INTEGER NOT NULL DEFAULT 0
            """)

        if "workflow_data" not in run_columns:
            c.execute("""
                ALTER TABLE runs
                ADD COLUMN workflow_data TEXT NOT NULL DEFAULT '{}'
            """)

        if not row:
            c.execute("INSERT INTO users(name,email,password_hash,role,status,created_at) VALUES(?,?,?,?,?,?)",
                      ("System Admin", ADMIN_EMAIL, hash_password(ADMIN_PASSWORD), "admin", "active", now()))

init_db()

def audit(actor, event, detail):
    with db() as c:
        c.execute("INSERT INTO audit(actor_id,event,detail,created_at) VALUES(?,?,?,?)",
                  (actor, event, detail[:1000], now()))

def token_digest(token):
    return hashlib.sha256((SECRET + token).encode()).hexdigest()

def current_user(request: Request):
    token = request.cookies.get(COOKIE)
    if not token:
        raise HTTPException(401, "Please sign in")
    with db() as c:
        row = c.execute("""SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
                           WHERE s.token_hash=? AND s.expires_at>?""",
                        (token_digest(token), int(time.time()))).fetchone()
    if not row:
        raise HTTPException(401, "Session expired. Please sign in again.")
    if row["status"] != "active":
        raise HTTPException(403, "Account is not active")
    return dict(row)

def admin_user(user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Admin access required")
    return user

class Credentials(BaseModel):
    email: str
    password: str

class Register(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    email: str
    password: str = Field(min_length=10, max_length=128)

class CreateUser(Register):
    role: str = "user"

class RunRequest(BaseModel):
    scenario: str
    task: str = Field(min_length=3, max_length=500)
    guarded: bool = True

class Decision(BaseModel):
    decision: str
    note: str = ""

class AgentCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    description: str = Field(default="", max_length=1000)
    version: str = Field(default="1.0.0", max_length=30)
    capabilities: list[str] = Field(default_factory=list)

ALLOWED_WORKFLOW_STEP_TYPES = {
    "tool_call",
    "validation",
    "approval"
}


def validate_workflow_steps(steps):
    if not isinstance(steps, list):
        raise HTTPException(400, "Workflow steps must be a list.")

    if len(steps) > 30:
        raise HTTPException(400, "Maximum 30 workflow steps allowed.")

    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            raise HTTPException(
                400,
                f"Workflow step {index + 1} must be an object."
            )

        step_type = step.get("type")

        if not isinstance(step_type, str) or step_type not in ALLOWED_WORKFLOW_STEP_TYPES:
            raise HTTPException(
                400,
                f"Unsupported workflow step type: {step_type}"
            )

        config = step.get("config", {})

        if not isinstance(config, dict):
            raise HTTPException(
                400,
                f"Config for step {index + 1} must be an object."
            )

        if step_type == "validation":
            required_fields = config.get(
                "required_fields",
                ["order_id", "status"]
            )

            if not isinstance(required_fields, list) or not all(
                isinstance(field, str) and field.strip()
                for field in required_fields
            ):
                raise HTTPException(
                    400,
                    f"Validation step {index + 1} must have a list of non-empty required_fields."
                )

        if step_type == "approval":
            required_for = config.get("required_for")

            if required_for is not None and not isinstance(required_for, str):
                raise HTTPException(
                    400,
                    f"Approval step {index + 1} has an invalid required_for value."
                )

class WorkflowCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    description: str = Field(default="", max_length=1000)
    agent_id: Optional[int] = None
    steps: list[dict] = Field(default_factory=list)


class WorkflowUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=100)
    description: Optional[str] = Field(default=None, max_length=1000)
    agent_id: Optional[int] = None
    steps: Optional[list[dict]] = None
    status: Optional[str] = None

class AgentUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=100)
    description: Optional[str] = Field(default=None, max_length=1000)
    version: Optional[str] = Field(default=None, max_length=30)
    capabilities: Optional[list[str]] = None
    status: Optional[str] = None

def issue_session(user_id, response):
    token = secrets.token_urlsafe(40)
    with db() as c:
        c.execute("INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)",
                  (token_digest(token), user_id, int(time.time()) + 60*60*12, now()))
    response.set_cookie(COOKIE, token, httponly=True, samesite="lax",
                        secure=os.getenv("COOKIE_SECURE", "0") == "1", max_age=60*60*12, path="/")

@app.get("/", response_class=HTMLResponse)
def home():
    with open(os.path.join(BASE, "static", "index.html"), encoding="utf-8") as f:
        return f.read()

@app.post("/api/register")
def register(payload: Register):
    email = payload.email.strip().lower()
    if "@" not in email or len(email) > 160:
        raise HTTPException(400, "Enter a valid email address")
    try:
        with db() as c:
            c.execute("INSERT INTO users(name,email,password_hash,role,status,created_at) VALUES(?,?,?,?,?,?)",
                      (payload.name.strip(), email, hash_password(payload.password), "user", "pending", now()))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "An account with this email already exists")
    audit(None, "user.registration", email)
    return {"message": "Registration submitted. An administrator must approve your account."}

@app.post("/api/login")
def login(payload: Credentials, response: Response):
    email = payload.email.strip().lower()
    with db() as c:
        user = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user or not check_password(payload.password, user["password_hash"]):
        raise HTTPException(401, "Invalid email or password")
    if user["status"] != "active":
        raise HTTPException(403, "Your account is pending approval or has been disabled")
    issue_session(user["id"], response)
    audit(user["id"], "auth.login", "Successful login")
    return {"user": {"id": user["id"], "name": user["name"], "email": user["email"], "role": user["role"]}}

@app.post("/api/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(COOKIE)
    if token:
        with db() as c:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (token_digest(token),))
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}

@app.get("/api/me")
def me(user=Depends(current_user)):
    return {k:user[k] for k in ("id","name","email","role","status","created_at")}

@app.get("/api/dashboard")
def dashboard(user=Depends(current_user)):
    with db() as c:
        if user["role"] == "admin":
            total_users = c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
            pending_users = c.execute("SELECT COUNT(*) n FROM users WHERE status='pending'").fetchone()["n"]
            total_runs = c.execute("SELECT COUNT(*) n FROM runs").fetchone()["n"]
            rows = c.execute("SELECT status,COUNT(*) n FROM runs GROUP BY status").fetchall()
            pending_approvals = c.execute("SELECT COUNT(*) n FROM approvals WHERE status='pending'").fetchone()["n"]
            recent = c.execute("""SELECT r.*,u.name owner FROM runs r JOIN users u ON u.id=r.user_id
                                  ORDER BY r.id DESC LIMIT 8""").fetchall()
        else:
            total_users, pending_users = 1, 0
            total_runs = c.execute("SELECT COUNT(*) n FROM runs WHERE user_id=?", (user["id"],)).fetchone()["n"]
            rows = c.execute("SELECT status,COUNT(*) n FROM runs WHERE user_id=? GROUP BY status", (user["id"],)).fetchall()
            pending_approvals = c.execute("SELECT COUNT(*) n FROM approvals WHERE requested_by=? AND status='pending'", (user["id"],)).fetchone()["n"]
            recent = c.execute("SELECT r.*,u.name owner FROM runs r JOIN users u ON u.id=r.user_id WHERE r.user_id=? ORDER BY r.id DESC LIMIT 8", (user["id"],)).fetchall()
    counts = {r["status"]:r["n"] for r in rows}
    return {"total_users":total_users,"pending_users":pending_users,"total_runs":total_runs,
            "successful":counts.get("verified",0),"failed":counts.get("failed",0),
            "pending_approvals":pending_approvals,
            "recent":[run_public(r) for r in recent]}

def run_public(r):
    return {"id":r["id"],"user_id":r["user_id"],"owner":r["owner"] if "owner" in r.keys() else "",
            "scenario":r["scenario"],"task":r["task"],"guarded":bool(r["guarded"]),
            "status":r["status"],"result":r["result"],"metrics":json.loads(r["metrics"]),
            "created_at":r["created_at"]}

SCENARIOS = ["normal","malformed","stale","timeout","high_risk"]
def workflow_public(row):
    return {
        "id": row["id"],
        "owner_id": row["owner_id"],
        "agent_id": row["agent_id"],
        "name": row["name"],
        "description": row["description"],
        "steps": json.loads(row["steps"]),
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"]
    }


@app.post("/api/workflows")
def create_workflow(payload: WorkflowCreate, user=Depends(current_user)):
    validate_workflow_steps(payload.steps)
    if payload.agent_id is not None:
        with db() as c:
            agent = c.execute(
                "SELECT id FROM agents WHERE id=? AND owner_id=?",
                (payload.agent_id, user["id"])
            ).fetchone()
        if not agent:
            raise HTTPException(404, "Agent not found")

    timestamp = now()

    with db() as c:
        cur = c.execute(
            """INSERT INTO workflows
            (owner_id, agent_id, name, description, steps, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                user["id"],
                payload.agent_id,
                payload.name.strip(),
                payload.description,
                json.dumps(payload.steps),
                "draft",
                timestamp,
                timestamp
            )
        )
        workflow_id = cur.lastrowid
        row = c.execute(
            "SELECT * FROM workflows WHERE id=?",
            (workflow_id,)
        ).fetchone()

    audit(user["id"], "workflow.created", f"Workflow #{workflow_id}")
    return workflow_public(row)


@app.get("/api/workflows")
def list_workflows(user=Depends(current_user)):
    with db() as c:
        if user["role"] == "admin":
            rows = c.execute(
                "SELECT * FROM workflows ORDER BY id DESC"
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM workflows WHERE owner_id=? ORDER BY id DESC",
                (user["id"],)
            ).fetchall()

    return [workflow_public(row) for row in rows]


@app.get("/api/workflows/{workflow_id}")
def get_workflow(workflow_id: int, user=Depends(current_user)):
    with db() as c:
        row = c.execute(
            "SELECT * FROM workflows WHERE id=?",
            (workflow_id,)
        ).fetchone()

    if not row or (
        user["role"] != "admin" and row["owner_id"] != user["id"]
    ):
        raise HTTPException(404, "Workflow not found")

    return workflow_public(row)


@app.patch("/api/workflows/{workflow_id}")
def update_workflow(
    workflow_id: int,
    payload: WorkflowUpdate,
    user=Depends(current_user)
):
    changes = payload.model_dump(exclude_unset=True)

    if not changes:
        raise HTTPException(400, "No fields provided for update")

    allowed_statuses = ("draft", "active", "paused", "archived")

    if "status" in changes and changes["status"] not in allowed_statuses:
        raise HTTPException(400, "Invalid workflow status")

    with db() as c:
        row = c.execute(
            "SELECT * FROM workflows WHERE id=?",
            (workflow_id,)
        ).fetchone()

        if not row or (
            user["role"] != "admin" and row["owner_id"] != user["id"]
        ):
            raise HTTPException(404, "Workflow not found")
        # Validate new steps, or existing steps when activating.
        if "steps" in changes or changes.get("status") == "active":
            effective_steps = changes.get(
                "steps",
                json.loads(row["steps"])
            )
            validate_workflow_steps(effective_steps)

        if changes.get("agent_id") is not None:
            agent = c.execute(
                "SELECT id FROM agents WHERE id=? AND owner_id=?",
                (changes["agent_id"], row["owner_id"])
            ).fetchone()

            if not agent:
                raise HTTPException(404, "Agent not found")

        fields = []
        values = []

        for key, value in changes.items():
            if key == "steps":
                value = json.dumps(value)
            elif key == "name":
                value = value.strip()

            fields.append(f"{key}=?")
            values.append(value)

        fields.append("updated_at=?")
        values.append(now())
        values.append(workflow_id)

        c.execute(
            f"UPDATE workflows SET {', '.join(fields)} WHERE id=?",
            values
        )

        updated = c.execute(
            "SELECT * FROM workflows WHERE id=?",
            (workflow_id,)
        ).fetchone()

    audit(user["id"], "workflow.updated", f"Workflow #{workflow_id}")
    return workflow_public(updated)
def agent_public(row):
    return {
        "id": row["id"],
        "owner_id": row["owner_id"],
        "name": row["name"],
        "description": row["description"],
        "version": row["version"],
        "capabilities": json.loads(row["capabilities"]),
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"]
    }


@app.post("/api/agents")
def create_agent(payload: AgentCreate, user=Depends(current_user)):
    capabilities = list(dict.fromkeys(
        item.strip() for item in payload.capabilities
        if item.strip()
    ))

    if len(capabilities) > 30:
        raise HTTPException(400, "Maximum 30 capabilities allowed")

    with db() as c:
        cur = c.execute("""
            INSERT INTO agents(
                owner_id, name, description, version,
                capabilities, status, created_at, updated_at
            )
            VALUES(?,?,?,?,?,?,?,?)
        """, (
            user["id"], payload.name.strip(),
            payload.description.strip(), payload.version.strip(),
            json.dumps(capabilities), "active", now(), now()
        ))

        row = c.execute(
            "SELECT * FROM agents WHERE id=?",
            (cur.lastrowid,)
        ).fetchone()

    audit(user["id"], "agent.created", f"Agent #{cur.lastrowid}")
    return agent_public(row)


@app.get("/api/agents")
def list_agents(user=Depends(current_user)):
    with db() as c:
        if user["role"] == "admin":
            rows = c.execute(
                "SELECT * FROM agents ORDER BY id DESC"
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM agents WHERE owner_id=? ORDER BY id DESC",
                (user["id"],)
            ).fetchall()

    return [agent_public(row) for row in rows]


@app.get("/api/agents/{agent_id}")
def get_agent(agent_id: int, user=Depends(current_user)):
    with db() as c:
        row = c.execute(
            "SELECT * FROM agents WHERE id=?",
            (agent_id,)
        ).fetchone()

    if not row:
        raise HTTPException(404, "Agent not found")

    if user["role"] != "admin" and row["owner_id"] != user["id"]:
        raise HTTPException(403, "You cannot access this agent")

    return agent_public(row)


@app.patch("/api/agents/{agent_id}")
def update_agent(
    agent_id: int,
    payload: AgentUpdate,
    user=Depends(current_user)
):
    changes = payload.model_dump(exclude_unset=True)

    if not changes:
        raise HTTPException(400, "No changes provided")

    if "status" in changes and changes["status"] not in ("active", "paused"):
        raise HTTPException(400, "Status must be active or paused")

    if "capabilities" in changes:
        if changes["capabilities"] is None:
            raise HTTPException(400, "Capabilities cannot be null")

        capabilities = list(dict.fromkeys(
            item.strip() for item in changes["capabilities"]
            if item.strip()
        ))

        if len(capabilities) > 30:
            raise HTTPException(400, "Maximum 30 capabilities allowed")

        changes["capabilities"] = json.dumps(capabilities)

    for field in ("name", "description", "version"):
        if field in changes:
            if changes[field] is None:
                raise HTTPException(400, f"{field} cannot be null")
            changes[field] = changes[field].strip()

    with db() as c:
        row = c.execute(
            "SELECT * FROM agents WHERE id=?",
            (agent_id,)
        ).fetchone()

        if not row:
            raise HTTPException(404, "Agent not found")

        if user["role"] != "admin" and row["owner_id"] != user["id"]:
            raise HTTPException(403, "You cannot edit this agent")

        updates = ", ".join(f"{field}=?" for field in changes)
        values = list(changes.values())

        c.execute(
            f"UPDATE agents SET {updates}, updated_at=? WHERE id=?",
            values + [now(), agent_id]
        )

        updated = c.execute(
            "SELECT * FROM agents WHERE id=?",
            (agent_id,)
        ).fetchone()

    audit(user["id"], "agent.updated", f"Agent #{agent_id}")
    return agent_public(updated)

def execute_workflow(scenario, task, guarded):
    trace = []
    metrics = {"injected_faults":0,"detected_faults":0,"recovery_attempts":0,
               "verified_recoveries":0,"blocked_unsafe_actions":0,"tool_calls":0}
    approval = None
    def log(step, message, state="info"):
        trace.append({"time":datetime.now().strftime("%H:%M:%S"),"step":step,"message":message,"state":state})
    log("Orchestrator", "Accepted task: " + task)
    log("Policy engine", "Guarded execution enabled" if guarded else "Guard disabled — baseline run",
        "success" if guarded else "warning")
    log("Tool call", "Calling simulated order service")
    metrics["tool_calls"] += 1
    if scenario == "normal":
        log("Tool response", "Order ORD-1042 returned: status=delivered, amount=₹3,200", "success")
        log("Verifier", "Independent state check passed: order record matches expected state", "success")
        status, result = "verified", "Task completed and independently verified."
    elif scenario == "malformed":
        metrics["injected_faults"] += 1
        log("Fault injector", "Injected malformed response: required field 'order_status' missing", "warning")
        if guarded:
            metrics["detected_faults"] += 1
            log("Schema validator", "Rejected response: missing required field order_status", "error")
            metrics["recovery_attempts"] += 1
            log("Recovery controller", "Refreshing order data (safe read-only retry)", "warning")
            metrics["tool_calls"] += 1
            metrics["verified_recoveries"] += 1
            log("Verifier", "Fresh response validated; final state independently confirmed", "success")
            status, result = "verified", "Malformed response detected; safe refresh recovered the workflow."
        else:
            log("Agent", "Continued with incomplete data and reported success without verification", "error")
            status, result = "failed", "Baseline exposed a false-success risk; outcome was not verified."
    elif scenario == "stale":
        metrics["injected_faults"] += 1
        log("Fault injector", "Injected stale order version (version 3; current version 4)", "warning")
        if guarded:
            metrics["detected_faults"] += 1
            log("Freshness validator", "Rejected stale response using version/timestamp rule", "error")
            metrics["recovery_attempts"] += 1
            log("Recovery controller", "Refreshing read-only order state", "warning")
            metrics["tool_calls"] += 1
            metrics["verified_recoveries"] += 1
            log("Verifier", "Current version 4 confirmed independently", "success")
            status, result = "verified", "Stale data detected and refreshed successfully."
        else:
            log("Agent", "Used stale version 3 and returned an unverified result", "error")
            status, result = "failed", "Baseline used stale data; final state could not be trusted."
    elif scenario == "timeout":
        metrics["injected_faults"] += 1
        log("Fault injector", "Injected tool timeout on first read request", "warning")
        if guarded:
            metrics["detected_faults"] += 1
            log("Timeout monitor", "Tool exceeded configured 2-second demo threshold", "error")
            metrics["recovery_attempts"] += 1
            log("Recovery controller", "Retry 1/2 with same read-only idempotency key", "warning")
            metrics["tool_calls"] += 1
            metrics["verified_recoveries"] += 1
            log("Verifier", "Retry response received and state verified", "success")
            status, result = "verified", "Transient timeout recovered within the retry budget."
        else:
            log("Agent", "No recovery policy; workflow terminated without verification", "error")
            status, result = "failed", "Baseline failed after tool timeout."
    else:
        metrics["injected_faults"] += 1
        log("Risk engine", "Refund request detected: ₹8,500 exceeds configured ₹5,000 threshold", "warning")
        if guarded:
            metrics["detected_faults"] += 1
            metrics["blocked_unsafe_actions"] += 1
            log("Policy gate", "Paused before side effect; human approval required", "error")
            status, result = "awaiting_approval", "High-risk refund paused. No refund was executed."
            approval = {"action":"Simulated refund of ₹8,500 for order ORD-1042",
                        "reason":"Amount exceeds the configured ₹5,000 approval threshold."}
        else:
            log("Agent", "Baseline attempted a high-risk action without an approval gate", "error")
            status, result = "failed", "Unsafe-action policy violation detected in baseline simulation."
    if guarded and status == "verified":
        log("Audit", "Execution trace and verification evidence recorded", "success")
    return status, result, metrics, trace, approval
    

def execute_custom_workflow_steps(
    steps,
    workflow_name,
    start_index=0,
    latest_data=None,
    metrics=None,
    trace=None
):
    latest_data = latest_data or {}
    trace = trace or []

    if metrics is None:
        metrics = {
            "steps_total": len(steps),
            "steps_completed": 0,
            "tool_calls": 0,
            "validations_passed": 0,
            "validations_failed": 0,
            "approval_gates": 0
        }

    def log(step, message, state="info"):
        trace.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "step": step,
            "message": message,
            "state": state
        })

    if start_index == 0:
        log("Orchestrator", f"Starting workflow: {workflow_name}", "success")
    else:
        log(
            "Orchestrator",
            f"Resuming workflow: {workflow_name} from step {start_index + 1}",
            "success"
        )

    for index in range(start_index, len(steps)):
        step = steps[index]
        step_type = step.get("type")
        step_name = step.get("name") or f"Step {index + 1}"
        config = step.get("config") or {}

        log("Workflow engine", f"Executing {step_name}")

        if step_type == "tool_call":
            tool_name = config.get("tool", "simulated_order_lookup")

            log("Simulated tool", f"Calling {tool_name}")
            metrics["tool_calls"] += 1

            # Demo-only tool response. No external service is called.
            latest_data = {
                "order_id": "ORD-1042",
                "status": "delivered",
                "amount": 3200,
                "version": 4
            }

            log(
                "Tool response",
                f"Received simulated order data: {latest_data}",
                "success"
            )

        elif step_type == "validation":
            required_fields = config.get(
                "required_fields",
                ["order_id", "status"]
            )

            if not isinstance(required_fields, list) or not all(
                isinstance(field, str) for field in required_fields
            ):
                log("Validator", "Invalid validation configuration", "error")
                metrics["validations_failed"] += 1

                state = {
                    "latest_data": latest_data,
                    "steps": steps
                }

                return (
                    "failed",
                    "Invalid validation configuration.",
                    metrics,
                    trace,
                    None,
                    index,
                    state
                )

            missing_fields = [
                field for field in required_fields
                if field not in latest_data
            ]

            if missing_fields:
                log(
                    "Validator",
                    f"Missing required fields: {missing_fields}",
                    "error"
                )
                metrics["validations_failed"] += 1

                state = {
                    "latest_data": latest_data,
                    "steps": steps
                }

                return (
                    "failed",
                    "Workflow stopped because validation failed.",
                    metrics,
                    trace,
                    None,
                    index,
                    state
                )

            metrics["validations_passed"] += 1

            log(
                "Validator",
                f"Required fields validated: {required_fields}",
                "success"
            )

        elif step_type == "approval":
            metrics["approval_gates"] += 1

            approval = {
                "action": f"Approval required for workflow: {workflow_name}",
                "reason": config.get(
                    "required_for",
                    "Workflow contains a human approval step."
                )
            }

            log(
                "Approval gate",
                "Execution paused. Waiting for administrator approval.",
                "warning"
            )

            state = {
                "latest_data": latest_data,
                "steps": steps
            }

            return (
                "awaiting_approval",
                "Workflow paused at a human approval step.",
                metrics,
                trace,
                approval,
                index + 1,
                state
            )

        else:
            log(
                "Workflow engine",
                f"Unsupported step type: {step_type}",
                "error"
            )

            state = {
                "latest_data": latest_data,
                "steps": steps
            }

            return (
                "failed",
                f"Unsupported workflow step: {step_type}",
                metrics,
                trace,
                None,
                index,
                state
            )

        metrics["steps_completed"] += 1

    # Independent verification of the simulated final state.
    has_tool_call = any(
        step.get("type") == "tool_call" for step in steps
    )

    if has_tool_call and not (
        latest_data.get("order_id") and latest_data.get("status")
    ):
        log(
            "Independent verifier",
            "Final state verification failed.",
            "error"
        )

        state = {
            "latest_data": latest_data,
            "steps": steps
        }

        return (
            "failed",
            "Final simulated state could not be verified.",
            metrics,
            trace,
            None,
            len(steps),
            state
        )

    log(
        "Independent verifier",
        "All configured steps completed. Simulated final state independently checked.",
        "success"
    )

    state = {
        "latest_data": latest_data,
        "steps": steps
    }

    return (
        "verified",
        "Workflow completed and simulated final state verified.",
        metrics,
        trace,
        None,
        len(steps),
        state
    )


@app.post("/api/workflows/{workflow_id}/execute")
def execute_saved_workflow(
    workflow_id: int,
    user=Depends(current_user)
):
    with db() as c:
        workflow = c.execute(
            "SELECT * FROM workflows WHERE id=?",
            (workflow_id,)
        ).fetchone()

        if not workflow or (
            user["role"] != "admin"
            and workflow["owner_id"] != user["id"]
        ):
            raise HTTPException(404, "Workflow not found")

        if workflow["status"] != "active":
            raise HTTPException(
                400,
                "Only active workflows can be executed."
            )

        if workflow["agent_id"] is not None:
            agent = c.execute(
                "SELECT status FROM agents WHERE id=? AND owner_id=?",
                (workflow["agent_id"], workflow["owner_id"])
            ).fetchone()

            if not agent or agent["status"] != "active":
                raise HTTPException(
                    400,
                    "The assigned agent is missing or inactive."
                )

        steps = json.loads(workflow["steps"])

    if not steps:
        raise HTTPException(400, "Workflow has no execution steps.")

    if len(steps) > 30:
        raise HTTPException(400, "Maximum 30 workflow steps allowed.")

    allowed_types = {"tool_call", "validation", "approval"}

    for step in steps:
        if not isinstance(step, dict):
            raise HTTPException(400, "Invalid workflow step.")

        if step.get("type") not in allowed_types:
            raise HTTPException(
                400,
                f"Unsupported workflow step type: {step.get('type')}"
            )

        if not isinstance(step.get("config") or {}, dict):
            raise HTTPException(400, "Step config must be an object.")

    (
        status,
        result,
        metrics,
        trace,
        approval,
        resume_step,
        workflow_state
    ) = execute_custom_workflow_steps(
        steps,
        workflow["name"]
    )

    with db() as c:
        cur = c.execute(
            """
            INSERT INTO runs(
                user_id, workflow_id, scenario, task, guarded,
                status, result, metrics, trace, created_at,
                resume_step, workflow_data
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user["id"],
                workflow_id,
                "custom_workflow",
                workflow["name"],
                1,
                status,
                result,
                json.dumps(metrics),
                json.dumps(trace),
                now(),
                resume_step,
                json.dumps(workflow_state)
            )
        )

        run_id = cur.lastrowid

        if approval:
            c.execute(
                """
                INSERT INTO approvals(
                    run_id, requested_by, action, reason, status, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    user["id"],
                    approval["action"],
                    approval["reason"],
                    "pending",
                    now()
                )
            )

    audit(
        user["id"],
        "workflow.executed",
        f"Workflow #{workflow_id}, Run #{run_id}: {status}"
    )

    return {
        "run_id": run_id,
        "workflow_id": workflow_id,
        "workflow_name": workflow["name"],
        "status": status,
        "result": result,
        "metrics": metrics,
        "trace": trace,
        "approval_required": bool(approval)
    }


@app.post("/api/runs")
def create_run(payload: RunRequest, user=Depends(current_user)):
    if payload.scenario not in SCENARIOS:
        raise HTTPException(400, "Unknown scenario")
    status, result, metrics, trace, approval = execute_workflow(payload.scenario, payload.task, payload.guarded)
    with db() as c:
        cur = c.execute("""INSERT INTO runs(user_id,scenario,task,guarded,status,result,metrics,trace,created_at)
                           VALUES(?,?,?,?,?,?,?,?,?)""",
                        (user["id"],payload.scenario,payload.task,int(payload.guarded),status,result,
                         json.dumps(metrics),json.dumps(trace),now()))
        run_id = cur.lastrowid
        if approval:
            c.execute("""INSERT INTO approvals(run_id,requested_by,action,reason,status,created_at)
                         VALUES(?,?,?,?,?,?)""",
                      (run_id,user["id"],approval["action"],approval["reason"],"pending",now()))
    audit(user["id"], "run.created", f"Run #{run_id}: {payload.scenario}, {status}")
    return {"id":run_id,"status":status,"result":result,"metrics":metrics,"trace":trace,"approval_required":bool(approval)}

@app.get("/api/runs")
def list_runs(user=Depends(current_user)):
    with db() as c:
        if user["role"] == "admin":
            rows = c.execute("SELECT r.*,u.name owner FROM runs r JOIN users u ON u.id=r.user_id ORDER BY r.id DESC LIMIT 200").fetchall()
        else:
            rows = c.execute("SELECT r.*,u.name owner FROM runs r JOIN users u ON u.id=r.user_id WHERE r.user_id=? ORDER BY r.id DESC LIMIT 200",(user["id"],)).fetchall()
    return [run_public(r) for r in rows]

@app.get("/api/runs/{run_id}")
def get_run(run_id:int,user=Depends(current_user)):
    with db() as c:
        r = c.execute("SELECT r.*,u.name owner FROM runs r JOIN users u ON u.id=r.user_id WHERE r.id=?",(run_id,)).fetchone()
    if not r or (user["role"]!="admin" and r["user_id"]!=user["id"]):
        raise HTTPException(404,"Run not found")
    out = run_public(r); out["trace"] = json.loads(r["trace"])
    return out

@app.get("/api/approvals")
def approvals(user=Depends(current_user)):
    with db() as c:
        if user["role"]=="admin":
            rows=c.execute("""SELECT a.*,u.name requester,r.scenario FROM approvals a JOIN users u ON u.id=a.requested_by
                              JOIN runs r ON r.id=a.run_id ORDER BY a.id DESC""").fetchall()
        else:
            rows=c.execute("""SELECT a.*,u.name requester,r.scenario FROM approvals a JOIN users u ON u.id=a.requested_by
                              JOIN runs r ON r.id=a.run_id WHERE a.requested_by=? ORDER BY a.id DESC""",(user["id"],)).fetchall()
    return [dict(x) for x in rows]


@app.post("/api/approvals/{approval_id}/decision")
def decide(
    approval_id: int,
    payload: Decision,
    user=Depends(admin_user)
):
    if payload.decision not in ("approved", "rejected"):
        raise HTTPException(
            400,
            "Decision must be approved or rejected"
        )

    with db() as c:
        row = c.execute("""
            SELECT
                a.*,
                r.scenario,
                r.workflow_id,
                r.metrics AS run_metrics,
                r.trace AS run_trace,
                r.resume_step,
                r.workflow_data
            FROM approvals a
            JOIN runs r ON r.id = a.run_id
            WHERE a.id=?
        """, (approval_id,)).fetchone()

        if not row:
            raise HTTPException(404, "Approval not found")

        if row["status"] != "pending":
            raise HTTPException(409, "Approval already decided")

        c.execute(
            """
            UPDATE approvals
            SET status=?, decided_by=?, decision_note=?, decided_at=?
            WHERE id=?
            """,
            (
                payload.decision,
                user["id"],
                payload.note[:500],
                now(),
                approval_id
            )
        )

        # Rejection stops execution immediately.
        if payload.decision == "rejected":
            c.execute(
                """
                UPDATE runs
                SET status=?, result=?
                WHERE id=?
                """,
                (
                    "blocked",
                    "Admin rejected the action. No external transaction was performed.",
                    row["run_id"]
                )
            )

            c.execute(
    "INSERT INTO audit(actor_id,event,detail,created_at) VALUES(?,?,?,?)",
    (
        user["id"],
        "approval.rejected",
        f"Approval #{approval_id}"[:1000],
        now()
    )
)

            return {
                "ok": True,
                "status": "blocked",
                "message": "Workflow rejected and blocked."
            }

        # Resume custom workflows after approval.
        if row["scenario"] == "custom_workflow":

            saved_state = json.loads(
                row["workflow_data"] or "{}"
            )

            steps = saved_state.get("steps")

            # Fallback for older runs without a saved workflow snapshot.
            if not isinstance(steps, list):
                workflow = c.execute(
                    "SELECT steps FROM workflows WHERE id=?",
                    (row["workflow_id"],)
                ).fetchone()

                if not workflow:
                    raise HTTPException(
                        404,
                        "Original workflow not found."
                    )

                steps = json.loads(workflow["steps"])

            latest_data = saved_state.get("latest_data", {})

            if not isinstance(latest_data, dict):
                latest_data = {}

            metrics = json.loads(row["run_metrics"])
            trace = json.loads(row["run_trace"])

            start_index = int(row["resume_step"] or 0)

            if start_index < 0 or start_index > len(steps):
                raise HTTPException(
                    400,
                    "Invalid saved workflow resume position."
                )

            (
                new_status,
                new_result,
                new_metrics,
                new_trace,
                next_approval,
                next_resume_step,
                new_workflow_state
            ) = execute_custom_workflow_steps(
                steps,
                "Resumed workflow",
                start_index=start_index,
                latest_data=latest_data,
                metrics=metrics,
                trace=trace
            )

            c.execute(
                """
                UPDATE runs
                SET status=?,
                    result=?,
                    metrics=?,
                    trace=?,
                    resume_step=?,
                    workflow_data=?
                WHERE id=?
                """,
                (
                    new_status,
                    new_result,
                    json.dumps(new_metrics),
                    json.dumps(new_trace),
                    next_resume_step,
                    json.dumps(new_workflow_state),
                    row["run_id"]
                )
            )

            # If another approval gate is reached, create a new request.
            if next_approval:
                c.execute(
                    """
                    INSERT INTO approvals(
                        run_id, requested_by, action, reason, status, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        row["run_id"],
                        row["requested_by"],
                        next_approval["action"],
                        next_approval["reason"],
                        "pending",
                        now()
                    )
                )

            c.execute(
    "INSERT INTO audit(actor_id,event,detail,created_at) VALUES(?,?,?,?)",
    (
        user["id"],
        "workflow.resumed",
        f"Run #{row['run_id']}: {new_status}"[:1000],
        now()
    )
)

            return {
                "ok": True,
                "status": new_status,
                "message": new_result,
                "metrics": new_metrics,
                "approval_required": bool(next_approval)
            }

        # Preserve the existing Agent Testing Lab behavior.
        c.execute(
            """
            UPDATE runs
            SET status=?, result=?
            WHERE id=?
            """,
            (
                "verified",
                "Admin approved the simulated action; no refund was executed.",
                row["run_id"]
            )
        )

        
        c.execute(
            """
            INSERT INTO audit(actor_id,event,detail,created_at)
            VALUES(?,?,?,?)
            """,
            (
                user["id"],
                "approval.approved",
                f"Approval #{approval_id}"[:1000],
                now()
            )
        )


        return {
            "ok": True,
            "status": "verified",
            "message": "Decision recorded. No external transaction was performed."
        }

@app.get("/api/admin/users")
def users(user=Depends(admin_user)):
    with db() as c:
        rows=c.execute("SELECT id,name,email,role,status,created_at FROM users ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]

@app.post("/api/admin/users")
def create_user(payload:CreateUser,user=Depends(admin_user)):
    if payload.role not in ("user","admin"):
        raise HTTPException(400,"Role must be user or admin")
    email=payload.email.strip().lower()
    try:
        with db() as c:
            cur=c.execute("INSERT INTO users(name,email,password_hash,role,status,created_at) VALUES(?,?,?,?,?,?)",
                          (payload.name.strip(),email,hash_password(payload.password),payload.role,"active",now()))
    except sqlite3.IntegrityError:
        raise HTTPException(409,"Email already exists")
    audit(user["id"],"admin.user_created",email)
    return {"id":cur.lastrowid,"message":"Account created"}

@app.patch("/api/admin/users/{user_id}")
def update_user(user_id:int, payload:dict, user=Depends(admin_user)):
    status=payload.get("status")
    if status not in ("active","pending","disabled"): raise HTTPException(400,"Invalid status")
    if user_id==user["id"] and status!="active": raise HTTPException(400,"You cannot disable your own account")
    with db() as c:
        target=c.execute("SELECT id FROM users WHERE id=?",(user_id,)).fetchone()
        if not target: raise HTTPException(404,"User not found")
        c.execute("UPDATE users SET status=? WHERE id=?",(status,user_id))
        if status!="active": c.execute("DELETE FROM sessions WHERE user_id=?",(user_id,))
    audit(user["id"],"admin.user_status",f"User {user_id} -> {status}")
    return {"ok":True}

@app.get("/api/admin/audit")
def audit_logs(user=Depends(admin_user)):
    with db() as c:
        rows=c.execute("""SELECT a.*,u.name actor FROM audit a LEFT JOIN users u ON u.id=a.actor_id
                          ORDER BY a.id DESC LIMIT 300""").fetchall()
    return [dict(r) for r in rows]

@app.get("/api/export/runs.csv")
def export_runs(user=Depends(current_user)):
    with db() as c:
        if user["role"]=="admin":
            rows=c.execute("SELECT r.*,u.name owner FROM runs r JOIN users u ON u.id=r.user_id ORDER BY r.id DESC").fetchall()
        else:
            rows=c.execute("SELECT r.*,u.name owner FROM runs r JOIN users u ON u.id=r.user_id WHERE r.user_id=? ORDER BY r.id DESC",(user["id"],)).fetchall()
    out=io.StringIO(); w=csv.writer(out)
    w.writerow(["run_id","owner","scenario","task","guarded","status","result","created_at"])
    for r in rows: w.writerow([r["id"],r["owner"],r["scenario"],r["task"],bool(r["guarded"]),r["status"],r["result"],r["created_at"]])
    return StreamingResponse(iter([out.getvalue()]),media_type="text/csv",
        headers={"Content-Disposition":"attachment; filename=agentguard-runs.csv"})

@app.get("/api/health")
def health():
    with db() as c: c.execute("SELECT 1")
    return {"status":"healthy","database":"connected","mode":"simulated-tools"}
