# AI Security Learning Tool

Consumer-facing AI security learning and testing tool for ordinary AI users.

## Quick start

```bash
cd /home/forge/Work/ai-security-learning-tool
python -m pip install -e .
ai-security-lab
```

The default provider is an offline scripted demonstration. It uses synthetic
fixtures and performs no real email, plugin installation, payment, deletion,
credential access, or external-target activity.

## Human learning loop

1. Open **LEARN** and select a scenario.
2. Read the attack, trust boundary, exact payload, and current reality label.
3. Run the controlled attack and inspect model output, tool requests, evaluator
   evidence, and independent control decisions.
4. Record your own attack verdict.
5. Apply the defense and retest the same scenario.
6. Record your defense verdict and learning notes.
7. Save the review locally in `~/.ai-security-lab/progress.json`.

Reality labels are deliberately strict: SCRIPTED DEMO, BOUNDED LAB, ENFORCED
CONTROL, and INCONCLUSIVE are not interchangeable.

## Structure

- `src/engine/` — UI-independent security/exercise engine
- `src/providers/` — Model provider adapters (local, hosted, custom, demo)
- `src/sandbox/` — Controlled execution environment
- `src/scenarios/` — Data-driven scenario definitions (10 core + EXPLORE)
- `src/ui/` — TUI presentation layer (Textual)
- `src/scan/` — AI Safety Scan mode
- `workbook/` — Markdown learning content (inline in app, also reference)
- `fixtures/` — Synthetic test data

## Three areas

- **LEARN** — 10 core attack/defense scenarios with explicit human verification
- **SCAN** — Bounded AI safety assessment, pass/fail/evidence, no single score
- **EXPLORE** — Additional scenarios beyond the core 10

## Provider-agnostic

Users choose their AI provider: Ollama (local), OpenAI, custom endpoint, or demo mode (no model needed).

## Safety

No real credentials, no real network egress, no real system access. Synthetic data only. Canary-based containment detection.
