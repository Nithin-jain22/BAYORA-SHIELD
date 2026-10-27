# BAYORA-SHIELD
### Secure Adversarial AI Safety Testing & Evaluation Infrastructure

**Secure the environment. Trust the evaluation.**

BAYORA-SHIELD is a security-first platform for adversarial LLM safety evaluation. It focuses on **evaluation integrity** by isolating Red Team and Blue Team environments, preventing premature attack-payload disclosure, controlling model interactions, and maintaining a tamper-evident audit trail.

The platform combines multi-layer defenses, sandboxed local model execution, autonomous threat intelligence ingestion, sanitized evidence sharing, and cryptographically linked audit logs to support trustworthy AI safety testing.

## Key Features

- **Red Team / Blue Team Isolation:** Separates adversarial testing from defensive remediation and restricts attack-payload exposure.
- **Live Threat Intelligence:** Integrates the [TinyFish Web Agent](https://agent.tinyfish.ai/) to ingest emerging adversarial test cases, with cached fallbacks for offline use.
- **Multi-Layer Defense:** Combines rule-based filtering, ML classification, gateway enforcement, and output sanitization.
- **Model Sandbox:** Supports local LLM inference through Ollama with Docker-based runtime isolation.
- **Sanitized Evidence:** Shares behavioral signals and relevant failure evidence with defenders without unnecessarily exposing original attack payloads.
- **Tamper-Evident Auditing:** Uses SHA-256 hash chaining to detect unauthorized modifications to audit records.
- **Interactive Dashboard:** Provides Streamlit and React interfaces for testing, remediation, evaluation, reporting, and security auditing.

## Architecture

```text
       ┌────────────────────────┐
       │ TinyFish Web Agent     │
       │ Threat Intelligence    │
       └───────────┬────────────┘
                   ▼
┌─────────────┐  ┌──────────────────────┐
│  RED TEAM   │─▶️│     CONTROL PLANE    │
│ Attack Sets │  │ L1: Rule Filter      │
│ Custom Tests│  │ L2: ML Classifier    │
└─────────────┘  │ L3: Model Gateway    │
                 └──────────┬───────────┘
                            ▼
                 ┌──────────────────────┐
                 │    MODEL SANDBOX     │
                 │ Ollama / Llama 3.2   │
                 │ Ephemeral Sessions   │
                 └──────────┬───────────┘
                            ▼
                 ┌──────────────────────┐
                 │  EVALUATION PLANE    │
                 │ L4: Output Guard     │
                 │ Response Assessor    │
                 └──────────┬───────────┘
                            ▼
              ┌─────────────┴─────────────┐
              ▼                           ▼
     ┌─────────────────┐       ┌──────────────────┐
     │   BLUE TEAM     │       │  SECURITY PLANE  │
     │ Sanitized       │       │ SHA-256 Audit    │
     │ Evidence        │       │ Chain & Verifier │
     └─────────────────┘       └──────────────────┘
```

## Defense Pipeline

| Layer | Component | Purpose |
|---|---|---|
| L1 | Rule-Based Filter | Regex checks, known jailbreak signatures, heuristic sanitization, and deny-list scanning. |
| L2 | ML Classifier | Detects suspicious intent, instruction overrides, persona framing, and authority exploits. |
| L3 | Model Gateway | Enforces authentication, rate limits, circuit breakers, and session controls. |
| L4 | Output Guard | Detects and sanitizes sensitive output and unauthorized instruction disclosure. |

## Evaluation Outcomes

| Outcome | Meaning | Classification |
|---|---|---|
| `blocked` | Request stopped by L1 or L2. | Defended |
| `filtered` | Output sanitized by L4. | Defended |
| `refused` | Model base alignment refused the adversarial prompt. | Defended |
| `complied` | Assessor identified a potential safety failure. | Vulnerability |
| `uncertain` | Result requires manual review. | Inconclusive |
| `error` | Gateway or runtime failure. | Failure |

These outcomes distinguish model safety behavior from infrastructure enforcement and evaluation failures.

## Technology Stack

- **Backend:** Python 3.10+, FastAPI, Streamlit
- **Frontend:** React, TypeScript, Tailwind CSS
- **Model Runtime:** Ollama, Llama 3.2 1B
- **Isolation:** Docker
- **Threat Intelligence:** TinyFish Autonomous Web Agent
- **Audit Logging:** SHA-256 Cryptographic Hash Chain, JSONL
- **Testing:** Pytest, shell-based security tests

## Project Structure

```text
BAYORA-SHIELD/
├── app.py                             # Interactive Streamlit application
├── scripts/
│   ├── start.sh                       # Build React app + launch FastAPI on :8000
│   ├── dev.sh                         # FastAPI (:8000) + Vite HMR (:5173) dev stack
│   ├── test_network_isolation.sh      # Docker network segmentation verification
│   └── tamper_audit_demo.sh           # Demonstrates hash-chain break on record mutation
├── frontend/                          # React + TypeScript + Tailwind UI
│   └── src/
│       ├── pages/                     # Command Center, Red, Blue, Repair, Evaluation, Reports, Audit
│       └── components/                # Layer traces, charts, metrics cards
├── docker/
│   └── docker-compose.yml             # Isolated container definitions
├── data/
│   ├── attacks/                       # Curated baseline attack dataset
│   └── runtime/                       # Cryptographic audit logs, reports, and quarantine backups
├── src/
│   ├── api/server.py                  # FastAPI REST endpoints
│   ├── config.py                      # Active model configuration and system ports
│   ├── core/
│   │   ├── tinyfish.py                # TinyFish Autonomous Web Agent client
│   │   ├── defense.py                 # L1 regex and pattern filters
│   │   ├── ml_classifier.py           # L2 semantic vector classifier
│   │   ├── llm.py                     # L3 client model gateway caller
│   │   ├── output_filter.py           # L4 response sanitizer
│   │   ├── response_assessor.py       # Semantic compliance & refusal detector
│   │   └── timeutil.py                # Timezone-aware local host timestamp manager
│   ├── infrastructure/
│   │   ├── sandbox.py                 # Docker runtime manager & process jail
│   │   ├── sandbox_health.py          # Isolation health inspector
│   │   ├── gateway.py                 # Policy gateway, authentication, and rate limits
│   │   └── security_plane.py          # Cryptographic audit logger & hash-chain verifier
│   └── orchestration/                 # Pipelines, red/blue workflows, evidence sanitization
└── tests/                             # Unit, smoke, and regression tests

```

## Getting Started

### Prerequisites

- Python 3.10+
- Git
- [Ollama](https://ollama.com/)
- Docker Desktop or Docker Engine (for sandboxed execution)
- Node.js 18+ (for the React frontend)
- TinyFish API key (optional)

### 1. Clone the Repository

```bash
git clone https://github.com/Nithin-jain22/BOYARA-SHIELD.git
cd BOYARA-SHIELD

```

### 2. Set Up Python

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Pull the Evaluation Model

```bash
ollama pull llama3.2:1b
```

The model can be configured in `src/config.py`, provided the selected model is supported by the runtime.

### 4. Configure TinyFish (Optional)

```bash
export TINYFISH_API_KEY="your_tinyfish_api_key_here"
```

Cached payloads can be used for offline demonstrations where supported.

## Running the Application

**Streamlit console**

```bash
streamlit run app.py
```

Open [http://localhost:8501](http://localhost:8501).

**Full-stack application**

```bash
./scripts/start.sh
```

- Application: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- API documentation: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

For development with frontend hot reloading:

```bash
./scripts/dev.sh
```

## Security Verification

**1. Tamper-Evident Audit Verification**

```bash
bash scripts/tamper_audit_demo.sh
```

Run the audit-chain verification in the application before and after the demonstration. The script intentionally modifies audit data, so use a disposable test environment.

**2. Network Isolation Test**

```bash
bash scripts/test_network_isolation.sh
```

**3. Automated Test Suite**

```bash
pytest -q
```

These checks help validate audit integrity, network restrictions, and application behavior. Actual security guarantees depend on the implementation and deployment configuration.

## Threat Model & Residual Risks

| Threat Vector | Addressed By | Residual Risk & Planned Roadmap |
|---|---|---|
| Premature Payload Leakage | Isolated workspaces; blind retests; Model Gateway mediation | Internal control plane tampering (Roadmap: Multi-party cryptographic signing) |
| Defensive Reverse-Engineering | Sanitized evidence release; defensive rules decoupled from Red view | Black-box behavioral inference over many runs (Roadmap: Rate limits & randomized fuzzing) |
| Session Contamination | Ephemeral session IDs; explicit memory/context reset per test | Persistent KV-cache exploits (Roadmap: MicroVM recreation per run) |
| Audit Log Tampering | SHA-256 hash chaining | Privileged root attacker rewriting entire chain (Roadmap: External append-only ledger anchoring) |
| Container Escape | Docker --cap-drop ALL, non-root user, --security-opt no-new-privileges | Shared host-kernel vulnerabilities (Roadmap: Transition from Docker to Firecracker microVMs) |

**Security note:** Docker provides useful isolation but is not equivalent to a separate virtual machine. Hash chaining detects inconsistent modifications but does not prevent full-chain rewriting without an independently protected integrity anchor.

## License

Licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for details.

---

**BAYORA-SHIELD — Secure the environment. Trust the evaluation.**
