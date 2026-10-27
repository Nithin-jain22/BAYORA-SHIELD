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

| Outcome | Meaning |
|---|---|
| `blocked` | Request stopped by L1 or L2. |
| `filtered` | Output sanitized by L4. |
| `refused` | Model refused the adversarial instruction. |
| `complied` | Assessor identified a potential safety failure. |
| `uncertain` | Result requires manual review. |
| `error` | Gateway or runtime failure. |

These outcomes distinguish model safety behavior from infrastructure enforcement and evaluation failures.

## Technology Stack

- **Backend:** Python, FastAPI, Streamlit
- **Frontend:** React, TypeScript, Tailwind CSS
- **Model Runtime:** Ollama, Llama 3.2 1B
- **Isolation:** Docker
- **Threat Intelligence:** TinyFish Web Agent
- **Audit Logging:** SHA-256, JSONL
- **Testing:** Pytest and shell-based security tests

## Project Structure

```text
BAYORA-SHIELD/
├── app.py
├── scripts/
│   ├── start.sh
│   ├── dev.sh
│   ├── test_network_isolation.sh
│   └── tamper_audit_demo.sh
├── frontend/
│   └── src/
│       ├── pages/
│       └── components/
├── docker/
│   └── docker-compose.yml
├── data/
│   ├── attacks/
│   └── runtime/
├── src/
│   ├── api/server.py
│   ├── config.py
│   ├── core/
│   ├── infrastructure/
│   └── orchestration/
└── tests/
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

**Audit integrity**

```bash
bash scripts/tamper_audit_demo.sh
```

Run the audit-chain verification in the application before and after the demonstration. The script intentionally modifies audit data, so use a disposable test environment.

**Network isolation**

```bash
bash scripts/test_network_isolation.sh
```

**Automated tests**

```bash
pytest -q
```

These checks help validate audit integrity, network restrictions, and application behavior. Actual security guarantees depend on the implementation and deployment configuration.

## Threat Model

| Threat | Mitigation | Residual Risk |
|---|---|---|
| Premature payload leakage | Workspace separation and sanitized evidence | Privileged access or control-plane compromise |
| Policy reverse engineering | Blind testing and restricted evidence | Statistical inference across repeated runs |
| Session contamination | Context resets and ephemeral sessions | Persistent runtime or model-server state |
| Audit tampering | SHA-256 hash chaining | A privileged attacker could rewrite the entire chain |
| Container escape | Restricted capabilities and non-root execution | Host-kernel vulnerabilities |

**Security note:** Docker provides useful isolation but is not equivalent to a separate virtual machine. Hash chaining detects inconsistent modifications but does not prevent full-chain rewriting without an independently protected integrity anchor.

## License

Licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for details.

---

**BAYORA-SHIELD — Secure the environment. Trust the evaluation.**
