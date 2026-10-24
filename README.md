# 🛡️ Bayora-Shield

**Secure adversarial AI testing infrastructure**

> Secure the environment. Trust the evaluation.

Bayora-Shield tests whether a local LLM's safety defences can be bypassed — and,
just as importantly, whether the *environment* that produces those findings can
be trusted. A red team attacks the model, confirmed bypasses are released to a
blue team as **sanitised evidence**, and the blue team hardens the defences and
**retests** to verify each fix.

The primary interface is a React application served by a FastAPI control plane.
The original Streamlit interface is retained as a legacy fallback.

---

## The workflow

```
Red Team                     Control Plane                 Blue Team
─────────                    ─────────────                 ─────────
attack prompt ──► L1 rules ──► L2 ML ──► L3 hardened ──► L4 output filter
                                                │
                             response assessment
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
                 blocked        refused        complied
                 filtered       uncertain      (only this is
                    │              │           a bypass)
                defence win    review only         │
                                                   ▼
                                      sanitised evidence released
                                                   │
                                            analyse → fix → retest
                                                   │
                                      verdict: FIXED / STILL VULNERABLE
```

### Outcome semantics

| Outcome | Meaning | Counts as |
| --- | --- | --- |
| `blocked` | L1 rules or L2 classifier stopped the prompt | Defended |
| `filtered` | L4 output filter replaced a leaking response | Defended |
| `refused` | The model itself declined / stayed on policy | Defended |
| `complied` | Response assessment confirmed a real bypass | **Finding** |
| `uncertain` | No clear refusal or compliance; manual review | Inconclusive |
| `safe_completion` | Benign prompt received a normal answer | Inconclusive / no signal |
| `empty` / `error` | No usable response or gateway failure | Inconclusive |

Only `complied` releases evidence and increments the bypass rate. Refusals are
never mislabelled as bypasses. Every bypass view shows the actual model response
that constituted the failure.

* **Red team** sees the model response and its own history. It never sees blue
  team analysis or defence internals.
* **Blue team** never sees the raw attack prompt — only masked evidence,
  behavioural signals, the layers that were cleared, and the model's failure
  output. Retests replay the withheld payload through the control plane.
* **Sandbox repair** gives the blue team an explicit manual restoration
  workspace for the environment itself: runtime, container isolation, network
  scope, gateway state, audit chain, defence store and runtime artifacts.
* Every action is written to a **SHA-256 hash-chained audit log**. Destructive
  repairs require confirmation and create quarantine backups.

---

## Project layout

```text
.
├── app.py                        # legacy Streamlit entry point
├── scripts/
│   ├── start.sh                  # build React + serve everything on :8000
│   └── dev.sh                    # FastAPI :8000 + Vite HMR :5173
├── frontend/
│   └── src/
│       ├── pages/                # Overview, Red, Blue, Repair, Evaluation, Reports, Audit
│       ├── components/           # layout, primitives, charts, layer trace
│       └── lib/                  # API client, timestamps, outcome metadata
├── docker/
│   └── docker-compose.yml        # optional isolated Model Sandbox container
├── data/runtime/                 # audit log, attack journal, evidence, reports, quarantine
├── src/
│   ├── api/server.py             # FastAPI endpoints + static React serving
│   ├── config.py                 # paths / ports / model
│   ├── core/
│   │   ├── defense.py            # L1 rule filter
│   │   ├── ml_classifier.py      # L2 classifier
│   │   ├── llm.py                # L3 hardened system prompt
│   │   ├── output_filter.py      # L4 output filter
│   │   ├── response_assessor.py  # refusal / compliance / uncertain verdicts
│   │   ├── conditions.py         # exact prompt-condition fingerprints
│   │   ├── updater.py            # persisted continuous defence updates
│   │   └── attacks.py            # curated obvious + evasive payloads
│   ├── infrastructure/
│   │   ├── sandbox.py            # Docker + process sandbox
│   │   ├── sandbox_health.py     # per-layer health checks + audited repairs
│   │   ├── gateway.py            # rate limit + circuit breaker
│   │   └── security_plane.py     # tamper-evident audit log
│   └── orchestration/
│       ├── pipeline.py           # shared attack/retest pipeline
│       ├── journal.py            # append-only attack-condition journal
│       ├── control_plane.py      # isolation + remediation workflow
│       ├── red_team.py
│       ├── blue_team.py
│       ├── evidence.py           # evidence sanitisation
│       ├── evaluation_plane.py   # versioned runs and trend metrics
│       └── reporting.py          # JSON / Markdown / HTML / PDF reports
└── tests/
```

---

## Requirements

* Python 3.10+
* Node.js 18+ and npm (for the React frontend)
* [Ollama](https://ollama.com) running locally with the client model:
  ```bash
  ollama pull qwen3:8b
  ```
* Docker is **optional**. When a Docker daemon is not running, the platform
  automatically uses a process sandbox. When Docker is available, start the
  sandbox to use the isolated container backend.

## Run

```bash
pip install -r requirements.txt
./scripts/start.sh
```

The launcher installs frontend dependencies if needed, builds the React app, and
serves it with FastAPI:

* Application: <http://127.0.0.1:8000>
* API docs: <http://127.0.0.1:8000/docs>

Then click **Start sandbox** in the sidebar and use the workspaces:

1. **Command center** — posture, attack trends, outcome mix, correlated bypass
   conditions, audit-chain status and recent verdicts.
2. **Red team** — fire curated or custom attacks, run the evasive set, and read
   the model response, assessment and per-layer trace for every attempt.
3. **Blue team** — analyse sanitised findings, apply L1/L2/L4 fixes and retest.
   A vulnerable retest shows the actual model response as evidence.
4. **Sandbox repair** — inspect every isolation layer and run explicit,
   audited repairs. Destructive actions are confirmed and backed up.
5. **Evaluation** — snapshot a session or the journal and compare versioned runs.
6. **Reports** — generate and download JSON, Markdown, printable HTML or PDF.
7. **Security audit** — explore the hash-chained event log in local time with
   canonical UTC timestamps preserved.

### Development mode

```bash
./scripts/dev.sh
```

This starts FastAPI on `:8000` and Vite with hot module replacement on `:5173`.

### Legacy Streamlit interface

```bash
streamlit run app.py
```

The legacy app shares the same pipeline, evidence queue, attack journal and audit
log. It is useful as a fallback but does not include the new React report and
repair experience.

---

## Timestamps

Runtime timestamps are timezone-aware. APIs and reports carry both:

* `timestamp_iso` — canonical UTC with `+00:00`
* `timestamp_local` — the host's local offset

The React UI renders local time and exposes the canonical UTC value on hover or
in the audit-event detail dialog.

## Reports

Reports are stored under `data/runtime/reports/<report_id>/` in four formats:

* `report.json` — complete machine-readable evidence package
* `report.md` — human-readable audit narrative
* `report.html` — self-contained, print-ready report
* `report.pdf` — compact PDF generated with ReportLab

Reports mask raw payload text to preserve red/blue isolation. Exact fingerprints,
structural conditions, layer traces, timestamps, response assessments and the
model response that proved each bypass are preserved. Remediation history,
sandbox health and audit-chain status are included.

## Optional: run the isolated Model Sandbox in Docker

```bash
docker compose -f docker/docker-compose.yml up -d
docker ps   # bayora-shield-llm should now be listed
```

The app detects the Docker daemon automatically and prefers the container backend
when it is available. The container reuses the host `~/.ollama` model store, so
`qwen3:8b` does not need to be downloaded twice. It is capped at 6 GB / 6 CPUs
(raise Docker Desktop's VM memory above 6 GB, or the model load may be
OOM-killed).

If isolation flags drift, the **Sandbox repair** workspace can recreate the
container, validate the defence store, reset the gateway, quarantine runtime
artifacts and re-verify the audit chain.

## Tests

```bash
python3 tests/test_core.py
python3 tests/test_app_smoke.py
cd frontend && npm run build
```

The core tests cover refusal-versus-bypass classification, timestamp handling,
benign short responses, journal breach fields and all report formats. The smoke
test renders every Streamlit workspace.

## Command line

```bash
python -m src.core.simulator    # run all example attacks through the layers
```

## Notes on isolation

The process sandbox isolates the model process, binds it to a dedicated loopback
port and reuses the host model store. The Docker backend adds a read-only
filesystem, dropped capabilities and memory/CPU/PID limits. Full network egress
denial requires host firewall rules and is listed as future work.
