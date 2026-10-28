# AI Protector — 3-Minute Demo Script
# YouTube demonstration walkthrough for the Nebius × NVIDIA Hackathon

---

## Recording Checklist (before you hit record)
- [ ] Backend is running: `uvicorn backend.main:app --reload --port 8000`
- [ ] Frontend dev server running: `cd frontend && npm start` (or use the built version at port 8000)
- [ ] Browser is open at http://localhost:3000 (or :8000)
- [ ] Database is fresh: delete `ai_protector.db` first so there are no leftover scans
- [ ] Screen resolution set to 1920×1080 or 1280×720
- [ ] Audio narration ready (or add captions in post)

---

## Script (≈ 3 minutes)

### [0:00 – 0:20] Hook — the problem
> "This is a customer-support AI agent. It can look up customer records.
> It looks safe — until you give it an untrusted document."

Show the landing page with the tagline visible.

---

### [0:20 – 0:50] Step 1 — Baseline scan (the vulnerability)
1. Click **▶ Start Scan** with **Baseline (vulnerable)** mode selected.
2. The scan runs automatically. Watch the status change to `completed`.
3. Click the scan → **Findings** tab.

**Say:** _"AI Protector ran 6 test cases — including a direct prompt injection
and a document-injection multi-step chain. In baseline mode, two critical failures
are confirmed: the agent leaked a synthetic secret, and it executed an unauthorized
tool call."_

Point to the 🔴 `confirmed_failure` findings with `critical` / `high` severity badges.

---

### [0:50 – 1:20] Step 2 — Attack-chain investigation
1. Click the **Chain** tab.
2. Scroll through the event timeline.

**Say:** _"Every single event is recorded — the prompt, the model's response,
the tool request, the authorization decision, and the tool result.
We can see exactly which event in the chain caused the failure, not just a score."_

Point to the `auth_decision ✅ ALLOWED` row for the unauthorized tool call in TC-003.

---

### [1:20 – 1:50] Step 3 — Remediation
1. Go back to **Findings** tab.
2. Click **🔧 Remediate** on the `Unauthorized Tool Executed Successfully` finding.
3. A moment later the status changes to `🟡 mitigated`.

**Say:** _"AI Protector proposed a specific fix — switch the authorization layer
to protected mode, which enforces a per-email allowlist independent of what the model says.
It applied the fix automatically, then replayed the original attack.
The tool call was blocked. The finding is mitigated."_

---

### [1:50 – 2:20] Step 4 — Regression test (protected scan)
1. Go back to Overview.
2. Start a new scan with **Protected mode**.
3. Click that scan → **Findings** tab.

**Say:** _"Now in protected mode, attacks are blocked — but do legitimate requests
still work? Yes. TC-005 and TC-006 — the benign control cases — show ✅ legitimate_success.
No false positives, no regressions."_

---

### [2:20 – 2:45] Step 5 — AI analysis & report
1. Click **🤖 AI Analysis** (shows simulated label if no API key, real Nemotron if key is set).
2. Click **📄 Report** to show the markdown report.

**Say:** _"The NVIDIA Nemotron model, accessed via Nebius Token Factory, analyzed
the attack trace and explained the failure in plain language.
The report includes the full attack-chain timeline, evidence references, severity rationale,
and the before-and-after comparison — downloadable as markdown."_

---

### [2:45 – 3:00] Closing
> "AI Protector: Find the attack path. Fix the failure. Prove the defense.
> Open-source, reproducible, and honest about what it can and can't do.
> Built for the Nebius × NVIDIA Hackathon — Best Apps & Agents track."

Show the GitHub URL on screen.

---

## Recording Tips
- Use OBS Studio (free) or Loom for screen capture.
- Keep the browser window maximized.
- Narrate in real time or add a voiceover in post.
- Trim dead air between steps.
- Upload as unlisted on YouTube, then paste the link in the submission.
