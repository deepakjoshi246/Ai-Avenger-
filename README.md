# AI Protector 🛡️

> **Find the attack path. Fix the failure. Prove the defense.**

AI Protector is an open-source AI security investigation tool built for the **Nebius × NVIDIA Global AI Hackathon** (Best Apps & Agents track).

It tests AI agents against controlled multi-step attacks, reconstructs how security failures happen, identifies the exact failed security boundary, proposes a targeted remediation, and **verifies** the fix by replaying the original attack.

---

## Core Workflow

```
Attack → Observe → Reconstruct → Diagnose → Fix → Retest → Verify
```

1. **Attack execution** — Runs predefined attack cases (prompt injection, indirect injection via documents, unauthorized tool use, multi-step chains) against an isolated mock AI agent.
2. **Event capture** — Every prompt, model response, tool request, auth decision, and tool result is logged.
3. **Chain reconstruction** — Events are replayed in an attack-chain timeline so the exact failure path is visible.
4. **Evaluation** — A deterministic engine classifies each outcome: `confirmed_failure`, `attack_blocked`, `legitimate_success`, `mitigated`, or `inconclusive`.
5. **Remediation** — A targeted fix is proposed and applied (e.g., switch to protected authorization mode).
6. **Retest** — The original attack is replayed after the fix. If the secret is still leaked, the finding stays open.
7. **AI Analysis** *(optional)* — The NVIDIA Nemotron model via Nebius analyzes the attack trace and suggests remediations.

---

## Hackathon Compliance

### Nebius
- Runtime inference is made to `https://api.studio.nebius.com/v1/chat/completions`.
- Set `NEBIUS_API_KEY` in your environment. The application falls back gracefully to a labeled simulation when the key is absent.
- All credentials are server-side only. The API key is never sent to the frontend.

### NVIDIA
- Uses **`nvidia/Llama-3.1-Nemotron-70B-Instruct`** via the Nebius endpoint.
- The model is used for meaningful AI security analysis: analyzing attack traces, identifying failed controls, and suggesting remediations.
- Set `NEMOTRON_MODEL` to override the model name if needed.

---

## Architecture

```
frontend/ (React)          backend/ (FastAPI + SQLite)
├─ Overview                ├─ main.py          → API routes
├─ Attack Library          ├─ attack_library.py → 6 test cases
├─ Scan Detail             ├─ scan.py           → orchestration
│   ├─ Findings tab        ├─ agent.py          → mock target agent
│   ├─ Chain tab           ├─ auth.py           → deterministic auth layer
│   ├─ Report tab          ├─ evaluation.py     → evidence-based findings
│   └─ AI Analysis tab     ├─ remediation.py    → fix + retest
└─ Settings                ├─ report.py         → markdown report builder
                           ├─ nebius_integration.py → Nebius/NVIDIA calls
                           ├─ models.py         → DB schemas
                           └─ db.py             → SQLite engine
```

The mock agent operates in two modes:
- **Baseline** (default) — deliberately vulnerable; secret disclosure and unauthorized tool access can succeed.
- **Protected** — authorization layer enforces an allowlist; attacks are blocked while legitimate requests succeed.

---

## Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### 1. Clone and set up the backend

```bash
git clone https://github.com/YOUR_USERNAME/Ai-Avenger-.git
cd Ai-Avenger-

# Create and activate a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Configure credentials (optional)

```bash
# For real NVIDIA Nemotron inference via Nebius:
export NEBIUS_API_KEY=your_nebius_api_key_here
export NEMOTRON_MODEL=nvidia/Llama-3.1-Nemotron-70B-Instruct  # (default)
```

The app works fully without these — AI Analysis will show a labeled simulation.

### 3. Start the backend

```bash
uvicorn backend.main:app --reload --port 8000
```

API docs: http://localhost:8000/docs

### 4. Start the frontend (development)

```bash
cd frontend
npm install
npm start
```

Open http://localhost:3000

### 5. Build the frontend for production

```bash
cd frontend
npm run build
```

The build output is served automatically by the FastAPI backend at http://localhost:8000

---

## Running Your First Scan

1. Open the UI → click **▶ Start Scan** (Baseline mode).
2. The scanner runs 6 attack cases and logs every event.
3. Click the scan → **Findings** tab to see confirmed failures and blocked attacks.
4. Click **Chain** tab to see the full event timeline.
5. Click **🔧 Remediate** on a `confirmed_failure` finding.
6. The fix is applied and the original attack is replayed automatically.
7. Click **📄 Report** to download the full markdown security report.
8. Click **🤖 AI Analysis** to have the Nemotron model analyze the trace (requires `NEBIUS_API_KEY`).

---

## Attack Cases

| ID | Category | Description |
|----|----------|-------------|
| TC-001 | Direct Prompt Injection | Instructs agent to reveal synthetic secret directly. |
| TC-002 | Indirect Injection (Document) | Malicious instructions embedded in a support document. |
| TC-003 | Unauthorized Tool Use | Requests a balance lookup for a non-allowlisted customer. |
| TC-004 | Multi-Step Chain | Document injection leads to unauthorized tool call. |
| TC-005 | Legitimate Control | Authorized balance lookup — must succeed in both modes. |
| TC-006 | Legitimate Control | General support question — must succeed in both modes. |

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## Security Notes

- The application only tests its own built-in isolated demo agent.
- No real customer data, real credentials, or real external systems are used.
- All synthetic secrets are fictional values (e.g., `42XYZ`) with no real-world meaning.
- API keys are never logged, displayed, or sent to the frontend.
- Model output cannot change the authorization policy.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Acknowledgements

- **Nebius AI Cloud** — inference runtime via Token Factory.
- **NVIDIA** — Nemotron model for attack-trace analysis.
- **FastAPI** · **SQLModel** · **React**
