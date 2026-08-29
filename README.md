# Hybrid Multi-Layer Prompt Injection Defense

**Research prototype · Version 4.0.0**  
**Title (working):** *A Hybrid Lexical–Semantic Pipeline for Prompt-Injection Detection with Intent-Preserving Mitigation*

This repository implements and evaluates a **multi-layer defense** against prompt injection, jailbreaks, and related policy-bypass attacks. The system combines classical TF-IDF machine learning, signature patterns, train-only exemplar retrieval, gated semantic classification, an ambiguity judge, and heuristic safe-prompt rewriting for blocked traffic.

The README is written for **research reporting** (method, results, ablations, integrity) and for **reproducing** the experiments and demo.

---

## Abstract

Large language model (LLM) applications remain vulnerable to prompt injection and jailbreak attacks that attempt to override system instructions, extract hidden policy, or coerce tool/command execution. Pure lexical detectors (e.g., TF-IDF classifiers) are fast and strong on known phrasing, but they degrade under paraphrase and semantic reformulation. Pure transformer detectors improve semantic coverage but are costlier and harder to explain.

This work proposes a **hybrid gated pipeline**:

1. **Normalize** light obfuscation.  
2. **Layer 1** — high-precision rule / entropy prefilter.  
3. **Layer 2** — TF-IDF multi-model classifiers (logistic, Random Forest, XGBoost, SVM).  
4. **Layer 3** — weighted ensemble with confidence and ambiguity signals.  
5. **Gated upgrades** when the case is hard or suspicious:  
   - **Layer 2b** — semantic detector (HuggingFace DeBERTa prompt-injection model, with heuristic fallback).  
   - **Attack-bank retrieval** — TF-IDF cosine over train-only exemplars.  
   - **Layer 4** — ambiguity judge (heuristic by default; optional LLM).  
6. **Layer 5** — intent extraction and **heuristic** safe alternative generation for blocked prompts (mitigation, not only detection).

Evaluation uses a **held-out labeled test set** (primary claim) and **component ablations**. Pattern-bank self-tests are treated as secondary signature recall, not as the main accuracy claim.

---

## Table of contents

1. [Research questions](#1-research-questions)  
2. [Contributions](#2-contributions)  
3. [Threat model](#3-threat-model)  
4. [System architecture](#4-system-architecture)  
5. [Layer design rationale](#5-layer-design-rationale)  
6. [Hybrid lexical + semantic model](#6-hybrid-lexical--semantic-model)  
7. [Data: patterns, attack bank, splits](#7-data-patterns-attack-bank-splits)  
8. [Layer 5 mitigation](#8-layer-5-mitigation)  
9. [Experimental setup](#9-experimental-setup)  
10. [Results](#10-results)  
11. [Ablation analysis](#11-ablation-analysis)  
12. [Integrity & reproducibility rules](#12-integrity--reproducibility-rules)  
13. [How to run (demo & eval)](#13-how-to-run-demo--eval)  
14. [Configuration](#14-configuration)  
15. [Repository layout](#15-repository-layout)  
16. [Limitations & ethics](#16-limitations--ethics)  
17. [Suggested paper narrative](#17-suggested-paper-narrative)  
18. [License / attribution](#18-license--attribution)

---

## 1. Research questions

| ID | Question |
|----|----------|
| **RQ1** | Can a hybrid lexical + semantic pipeline detect prompt injection on held-out data with usable precision/recall for interactive chat? |
| **RQ2** | How much do semantic Layer 2b, exemplar retrieval, and the Layer 4 judge each contribute versus a classical TF-IDF ensemble alone? |
| **RQ3** | Can blocked attacks be turned into **intent-preserving safe alternatives** without relying on an LLM rewriter by default? |
| **RQ4** | How should evaluation avoid inflated claims from signature self-tests and retrieval leakage? |

---

## 2. Contributions

1. **End-to-end hybrid defense** combining rules, TF-IDF ensemble, gated semantics, train-only retrieval, and an ambiguity judge.  
2. **Cost-aware gating:** expensive / semantic components run mainly on ambiguous or low-confidence cases.  
3. **Train-safe attack bank** for retrieval (`scripts/build_attack_bank.py` never mines `test.jsonl`).  
4. **Paper-oriented evaluation harness** (`scripts/Check_Accuracy.py`) with modes: `heldout`, `ablation`, `patterns`.  
5. **Mitigation layer (Layer 5)** that produces heuristic educational / intent-aware safe prompts for UX after a block.  
6. **Runnable research demo:** FastAPI detector + Node chat UI.

---

## 3. Threat model

**In scope**

- Direct instruction override / jailbreak  
- System or data extraction attempts  
- Tool / command injection via natural language  
- Story-based and multi-turn framing attacks  
- Light obfuscation (encoding, delimiter hijack, etc.)

**Out of scope (current prototype)**

- Fully adaptive adversaries optimizing against this exact detector online  
- Multimodal injection (images, documents)  
- Guaranteed zero false positives on creative benign writing  

**Defense goals**

- High recall on attacks (prefer catching injections)  
- Controlled false-positive rate on benign prompts  
- Explainable signals when possible (patterns, retrieval hits, layer sources)  
- Safe next step for users after a block (Layer 5)

---

## 4. System architecture

```
User prompt
    │
    ▼
 TextNormalizer  (light de-obfuscation)
    │
    ▼
 Layer 1 Prefilter  →  Layer 2 TF-IDF models  →  Layer 3 Ensemble
 (rules / entropy)      (logistic / RF / XGB / SVM)   (vote + confidence)
    │
    ├─ if ambiguous / low confidence / suspicious ─┐
    │                                              │
    ▼                                              ▼
 Layer 2b Semantic          Attack Retrieval          Layer 4 Judge
 (DeBERTa or heuristics)    (train-only bank)         (heuristic / optional LLM)
    │                              │                         │
    └──────────────────────────────┴─────────────────────────┘
                                   │
                                   ▼
                        final is_malicious + risk + attack type
                                   │
                 ┌─────────────────┴─────────────────┐
                 ▼                                   ▼
           SAFE → chat LLM                    BLOCKED → Layer 5
                                              intent + heuristic safe alternative
```

### Decision fusion (simplified)

1. Start from Layer 3 ensemble risk / label.  
2. If Layer 2b indicates malicious → raise risk / force malicious.  
3. If attack-bank retrieval hits → raise risk / force malicious.  
4. If still ambiguous or low confidence → **Layer 4** judge.  
5. Attack typing uses `attack_typer` plus model / retrieval signals.  
6. Blocked traffic enters Layer 5 mitigation for chat UX.

**Important:** Layer 4 **is used**. It is gated (`ambiguous_only: true` by default), so it does not run on every prompt—only on hard cases.

---

## 5. Layer design rationale

| Component | Role | Why it exists |
|-----------|------|----------------|
| **Normalizer** | Decode light obfuscation | Attackers hide payloads; cheap cleanup before scoring |
| **Layer 1** | Rules + entropy / special-char heuristics | Fast, explainable, high-precision obvious attacks |
| **Layer 2** | TF-IDF classical ML | Learns lexical statistics from labeled data; low latency |
| **Layer 3** | Weighted ensemble | Reduces single-model error; exposes confidence / ambiguity for gating |
| **Layer 2b** | Semantic classifier | Catches paraphrase / meaning TF-IDF misses |
| **Retrieval** | Exemplar memory | “Have we seen a similar known attack?” |
| **Layer 4** | Ambiguity judge | Resolves borderline cases before chat |
| **Layer 5** | Mitigation | Detection alone is incomplete for product UX |

---

## 6. Hybrid lexical + semantic model

### Lexical stream (TF-IDF)

Asks: *“Have I seen these tokens / n-grams in attacks before?”*  
Strengths: speed, stability on known phrasing, cheap ensemble voting.  
Weakness: paraphrase and novel wording with the same hostile intent.

### Semantic stream (Layer 2b)

Asks: *“Does this **mean** like an injection?”*  
Default model: `protectai/deberta-v3-base-prompt-injection-v2` (lazy-loaded).  
If transformers are unavailable offline, the system falls back to **heuristic semantic cues** and records `backend: heuristic`.

### Hybrid practice used here

Keep TF-IDF as the always-on backbone; **gate** semantics, retrieval, and judging for ambiguous / low-confidence traffic. This matches a practical research thesis: *do not replace classical ML—extend it where it fails.*

---

## 7. Data: patterns, attack bank, splits

### Labeled splits

- `data/processed/train.jsonl` — training / bank mining  
- `data/processed/val.jsonl` — validation  
- `data/processed/test.jsonl` — **held-out primary evaluation**

### Pattern bank

Hundreds of hand-authored signature phrases compiled in the pipeline (jailbreak, system extraction, tool injection, etc.).

- Research role: **explainable signature component** and attack typing aid.  
- Evaluation role: `--mode patterns` measures signature recall only.  
- **Do not** use pattern self-tests as the paper’s main accuracy claim (circular inflation risk).

### Attack bank (`data/attack_bank.json`)

- Current build size: **326** exemplars (train-safe).  
- Built by:

```powershell
python scripts/build_attack_bank.py --per-type 35 --max-total 450
```

- Curated seeds + samples from **train only**.  
- **Never** mines `test.jsonl` (prevents retrieval leakage into held-out scores).

---

## 8. Layer 5 mitigation

After a block:

1. **Intent extractor** strips attack wrappers (`ignore previous instructions`, `execute system command`, …).  
2. If a legitimate goal remains → rewrite into a normal informational question.  
3. If the prompt is a pure attack → emit a **heuristic educational** alternative tied to keywords (e.g. process listing → OS process-management explanation).  
4. Default config: `layers.layer5.use_llm_rewrite: false` (local heuristics, not LLM rewrite).  
5. Clear safe follow-ups (e.g. “what is a system command?”) can be answered directly by the chat LLM.

Mitigation is part of the research story: **detect → explain → offer a safe path**.

---

## 9. Experimental setup

| Item | Setting |
|------|---------|
| Primary eval | Held-out `test.jsonl` via `Check_Accuracy.py --mode heldout` |
| Ablations | `full`, `classical_only`, `no_layer2b`, `no_retrieval`, `no_layer4` |
| Metrics | Accuracy, Precision, Recall, F1, FPR, FNR, latency mean / p95 |
| Decision audit | Per-source histogram (`layer3_ensemble`, `layer2b_*`, `retrieval`, `layer4_*`, …) |
| Config | `configs/config.yaml` |
| Models | `models/detector/*.pkl` + optional HF DeBERTa |

### Reproduce

```powershell
# Primary claim
python scripts/Check_Accuracy.py --mode heldout --limit 3000

# Ablation table
python scripts/Check_Accuracy.py --mode ablation --limit 2000

# Signature recall only (appendix)
python scripts/Check_Accuracy.py --mode patterns --rounds 3 --strong
```

Reports land in `logs/` as `.json` and `.md`.

---

## 10. Results

### 10.1 Held-out test set (paper-primary)

Snapshot from `logs/check_accuracy_heldout.md`  
Generated (UTC): **2026-08-27** · **N = 3000** (1500 attack / 1500 benign)

| Metric | Value |
|--------|------:|
| Accuracy | **0.9373** |
| Precision | **0.9110** |
| Recall | **0.9693** |
| F1 | **0.9393** |
| FPR | **0.0947** |
| FNR | **0.0307** |
| Latency mean | **145.56 ms** |
| Latency p95 | **281.92 ms** |

Confusion matrix: TP 1454 · TN 1358 · FP 142 · FN 46.

**Decision-source mix (held-out run):**

| Source | Count |
|--------|------:|
| `layer3_ensemble` | 2428 |
| `layer4_heuristic` | 448 |
| `pattern_score` | 64 |
| `layer2b_transformer` | 56 |
| `retrieval` | 4 |

Interpretation: most decisions come from the classical ensemble; Layer 4 still fires on a large ambiguous slice; semantic and retrieval upgrades contribute on fewer but harder cases.

### 10.2 Ablation study (held-out)

Snapshot from `logs/check_accuracy_ablation.md`  
Generated (UTC): **2026-08-27**

| Ablation | Accuracy | Precision | Recall | F1 | FPR | Latency ms |
|----------|---------:|----------:|-------:|---:|----:|-----------:|
| **full** | 0.9325 | 0.9061 | 0.9650 | 0.9346 | 0.1000 | 108.0 |
| classical_only | 0.9335 | 0.9656 | 0.8990 | 0.9311 | 0.0320 | 83.3 |
| no_layer2b | 0.9320 | 0.9408 | 0.9220 | 0.9313 | 0.0580 | 117.4 |
| no_retrieval | 0.9405 | 0.9199 | 0.9650 | 0.9419 | 0.0840 | 151.6 |
| no_layer4 | 0.9305 | 0.9065 | 0.9600 | 0.9325 | 0.0990 | 165.0 |

### Reading the trade-off

- **Classical-only** raises precision and lowers FPR, but **drops recall** (0.899 vs ~0.96+).  
- **Full hybrid** favors **recall** (fewer missed attacks)—preferred when missing an injection is costlier than an occasional false block.  
- Removing Layer 2b reduces recall relative to full.  
- Retrieval / Layer 4 effects are smaller on aggregate F1 in this snapshot but still matter for borderline cases and auditability (see decision sources).  
- Always report **FPR and recall together**; optimizing only accuracy can hide unsafe misses.

*Re-run commands above to refresh tables after model or bank changes.*

---

## 11. Ablation analysis

| Ablation | Enabled stack | Scientific question |
|----------|---------------|---------------------|
| `full` | L1+L2+L3+2b+retrieval+L4 | Full hybrid system |
| `classical_only` | L1+L2+L3 | Is TF-IDF ensemble enough alone? |
| `no_layer2b` | full − semantic | Does semantics help recall on paraphrase-like cases? |
| `no_retrieval` | full − attack bank | Does exemplar memory help? |
| `no_layer4` | full − judge | Does ambiguity judging matter? |

Implemented via `pipeline.apply_ablation(...)` inside the eval script.

---

## 12. Integrity & reproducibility rules

1. **Primary metric = held-out labeled test**, not pattern-bank self-tests.  
2. **Attack bank is train-only** — never build from `test.jsonl`.  
3. Disclose Layer 2b backend: `transformer` vs `heuristic` fallback.  
4. Report FPR / FNR and latency, not only accuracy.  
5. Publish decision-source histograms for transparency.  
6. Do not claim universal robustness against adaptive attackers.  
7. Keep API keys in `.env` (never commit secrets).

---

## 13. How to run (demo & eval)

### Requirements

- Python 3.10+ (tested with 3.13)  
- Node.js 18+  
- Trained classical models in `models/detector/`  
- Optional: HuggingFace access for Layer 2b (heuristic fallback if offline)

### Install

```powershell
cd C:\Users\Arsep95F\Desktop\Prompt
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

cd web
npm install
cd ..
```

### Environment (`.env`)

```env
OPENROUTER_API_KEY=your_key_here
OPENROUTER_MODEL=openai/gpt-4o-mini
GROQ_API_KEY=your_fallback_key_here
PYTHON_API=http://localhost:8000
NODE_PORT=3001
```

### Launch demo

```powershell
.\start.bat
```

Or two terminals:

```powershell
python run_api.py
```

```powershell
cd web
npm start
```

- API: http://localhost:8000  
- OpenAPI docs: http://localhost:8000/docs  
- Web UI: http://localhost:3001  

### Core API surface

- `POST /detect-conversational` — detect + Layer 5 conversational state  
- `GET /health` — readiness and feature flags  

Node UI calls the Python detector; safe prompts go to OpenRouter (Groq fallback).

---

## 14. Configuration

Primary file: `configs/config.yaml`

| Key | Meaning |
|-----|---------|
| `feature_flags.phase2_transformer` | Enable Layer 2b path |
| `feature_flags.phase3_llm_judge` | Enable Layer 4 path |
| `feature_flags.phase4_retrieval_normalization` | Enable retrieval + normalizer |
| `layers.layer2b.use_transformers` | Load HF DeBERTa (else heuristic cues) |
| `layers.layer2b.gate_confidence_below` | Run 2b if ensemble confidence &lt; threshold |
| `layers.layer2b.run_on_ambiguous` | Run 2b when Layer 3 marks ambiguous |
| `layers.retrieval.*` | Attack-bank retrieval |
| `layers.layer4.enabled` | Judge on/off |
| `layers.layer4.ambiguous_only` | Judge only hard cases |
| `layers.layer4.use_real_llm` | `false` = heuristic judge (default) |
| `layers.layer5.use_llm_rewrite` | `false` = heuristic safe prompts only |
| `logging.decisions_file` | JSONL decision log for analysis |

---

## 15. Repository layout

```
Prompt/
├── configs/config.yaml           # Flags & layer hyperparameters
├── data/
│   ├── attack_bank.json          # Retrieval exemplars (train-safe)
│   └── processed/                # train / val / test.jsonl
├── models/detector/              # TF-IDF vectorizer + classical models
├── scripts/
│   ├── Check_Accuracy.py         # heldout / ablation / patterns
│   └── build_attack_bank.py      # expand bank from train only
├── src/
│   ├── api/app.py                # FastAPI service
│   ├── layers/                   # L1–L5, 2b, retrieval, typer, normalizer
│   ├── pipeline/pipeline.py      # Orchestration + ablations
│   └── utils/                    # config, decision logger
├── web/                          # Animated Node UI + LLM chat proxy
├── logs/                         # Eval reports + runtime logs
├── run_api.py
├── start.bat
└── README.md
```

---

## 16. Limitations & ethics

- No detector is perfect against adaptive adversaries.  
- Classical-only mode under-recalls relative to the full hybrid stack.  
- Full hybrid raises recall but also FPR versus classical-only—product thresholds must be tuned.  
- Transformer download may fail offline → heuristic semantic fallback.  
- Layer 5 heuristics can over-generalize educational rewrites.  
- This project is for **defense research and safe UX**, not for authoring attacks.  
- Do not productionize without monitoring live FPR and user impact.

---

## 17. Suggested paper narrative

1. **Problem:** Prompt injection breaks LLM apps; lexical-only detectors miss paraphrases.  
2. **Method:** Hybrid gated pipeline (TF-IDF ensemble + semantics + retrieval + judge) + Layer 5 mitigation.  
3. **Eval protocol:** Held-out primary metrics; ablations; train-only retrieval bank; pattern tests as appendix only.  
4. **Results:** Held-out F1 ≈ **0.94**, recall ≈ **0.97**, with documented FPR and latency; ablations show classical-only trades recall for precision.  
5. **Discussion:** Prefer recall-oriented hybrid for security chat gateways; disclose gating and fallbacks.  
6. **Future work:** Stronger adversarial test suites, calibrated thresholds, optional real LLM judge A/B, richer Layer 5 fidelity metrics.

### Contribution statement (citation-ready)

This work implements a **hybrid prompt-injection defense** that combines (i) lexical classical learning, (ii) signature patterns, (iii) train-only exemplar retrieval, (iv) gated semantic detection, (v) ambiguity judging, and (vi) intent-preserving heuristic mitigation—evaluated with held-out metrics and ablations that separate signature recall from generalization.

---

## 18. License / attribution

- Local model weights and large JSONL datasets may be excluded from git (see `.gitignore`).  
- Semantic detector attribution: HuggingFace model card for  
  [`protectai/deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) (Apache-2.0).  
- Do not commit API keys or production secrets.

---

*Last research snapshot embedded above: held-out & ablation logs dated 2026-08-27. Re-run `scripts/Check_Accuracy.py` after any material change to models, banks, or gates.*
