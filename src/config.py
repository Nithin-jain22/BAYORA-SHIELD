"""Central configuration for Bayora-Shield.

Every path, port and tunable value used across the platform lives here so the
rest of the codebase never hard-codes environment-specific details.
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data"
RUNTIME_DIR = DATA_DIR / "runtime"
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)

AUDIT_LOG_PATH = RUNTIME_DIR / "audit_log.jsonl"
EVIDENCE_QUEUE_PATH = RUNTIME_DIR / "evidence_queue.json"
RETIRED_EVIDENCE_PATH = RUNTIME_DIR / "retired_evidence.jsonl"
DEFENSE_UPDATES_PATH = RUNTIME_DIR / "defense_updates.json"
DEFENSE_STORE_PATH = RUNTIME_DIR / "defense_store.json"
EVALUATION_RUNS_DIR = RUNTIME_DIR / "evaluation_runs"
SANDBOX_DATA_DIR = RUNTIME_DIR / "sandbox"
ATTACK_JOURNAL_PATH = RUNTIME_DIR / "attack_journal.jsonl"
REPORTS_DIR = RUNTIME_DIR / "reports"
QUARANTINE_DIR = RUNTIME_DIR / "quarantine"
SANDBOX_STATE_PATH = RUNTIME_DIR / "sandbox_state.json"

for _dir in (
    EVALUATION_RUNS_DIR,
    SANDBOX_DATA_DIR,
    REPORTS_DIR,
    QUARANTINE_DIR,
):
    _dir.mkdir(parents=True, exist_ok=True)

# Model / runtime
MODEL = "llama3.2:1b"
SANDBOX_PORT = 11435
DIRECT_OLLAMA_URL = "http://localhost:11434/api/chat"

# Docker sandbox
DOCKER_IMAGE = "ollama/ollama:latest"
DOCKER_CONTAINER_NAME = "bayora-shield-llm"

# Gateway policy
MAX_PROMPT_LENGTH = 4096
MAX_RESPONSE_LENGTH = 8192
RATE_LIMIT_REQUESTS = 30
RATE_LIMIT_WINDOW = 60
CIRCUIT_BREAKER_THRESHOLD = 5
CIRCUIT_BREAKER_TIMEOUT = 30

# Defence application
ML_BLOCK_THRESHOLD = 0.55
