# A Hybrid Lexical–Semantic Pipeline for Prompt-Injection Detection with Intent-Preserving Mitigation

**Author:** Shams-ul Arefin  
**Affiliation:** Independent Research / Open-Source Prototype  
**Version:** 4.0.0  
**Repository:** [Prompt-Attack-Monitoring-and-Controlling](https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling)  
**Preferred citation:** see [`CITATION.cff`](author/CITATION.cff) and [`author/ATTRIBUTION.md`](author/ATTRIBUTION.md)

---

## Abstract

Prompt injection has become a first-class security risk for Large Language Model (LLM) applications: untrusted natural-language input can override system instructions, exfiltrate secrets, invoke tools, or jailbreak safety policies. Existing defenses are often either brittle signature filters, costly end-to-end LLM judges, or single-model classifiers that trade precision for recall. This paper presents a **gated hybrid lexical–semantic pipeline** that combines (i) rule-based prefiltering and text normalization, (ii) TF–IDF classical detectors fused by a weighted ensemble, (iii) a gated DeBERTa semantic upgrade, (iv) train-only attack-bank retrieval, (v) an ambiguity-only judge with corroboration constraints, and (vi) **intent-preserving mitigation** that rewrites blocked prompts into a single safe user request rather than hard-dropping the interaction. On a frozen held-out test set of **N = 40,402** labeled prompts, the full system achieves **accuracy 0.9583**, **precision 0.9706**, **recall 0.9469**, **F1 0.9586**, **AUC-ROC 0.9665**, and **FPR 0.0299**, with mean latency **10.68 ms**. Ablation shows that classical layers alone are high-precision but miss more attacks (recall 0.8714), while the hybrid stack recovers recall with a controlled false-positive budget. The software prototype, evaluation scripts, and configuration are released for reproducible research.

### Index Terms

Prompt injection, jailbreak detection, LLM security, hybrid NLP, ensemble learning, DeBERTa, intent-preserving mitigation, ablation study.

---

## I. Introduction

Large Language Models are increasingly embedded in assistants, agents, RAG pipelines, and enterprise copilots. Because models treat natural language as both *data* and *control*, adversaries can craft inputs that blur that boundary—an attack class now ranked among the top risks for LLM applications [1], [2], [3]. Real deployments have already leaked system prompts and behavioral constraints through injection [4].

Two practical gaps remain. First, **single-layer detectors** (rules, classical ML, or one transformer) struggle under distribution shift: obfuscation, story jailbreaks, multi-turn framing, and tool-oriented payloads. Second, many systems **only detect and block**, discarding legitimate user goals wrapped inside adversarial scaffolding. Production UX and safety both benefit when a blocked injection is converted into a clarified, policy-compliant request.

This work contributes:

1. A **five-layer gated architecture** (plus normalization/retrieval) that escalates expensive semantic components only when the classical ensemble is uncertain.
2. A **precision-oriented decision policy** (risk/agreement floors, disabled DeBERTa force-block, corroboration-gated judge) tuned for low false-positive rate on held-out traffic.
3. An **intent-preserving Layer-5 rewriter** that extracts a legitimate goal and emits one safe natural prompt.
4. A **paper-primary evaluation protocol** on frozen `test.jsonl` (N = 40,402) with train-only retrieval memory (no test leakage) and component ablations.

---

## II. Related Work

### A. Taxonomies, Surveys, and Threat Models

Duarte *et al.* provide a systematic IEEE Access review of prompt-injection trends, taxonomies, evaluation protocols, and defenses, covering direct overrides, multi-turn manipulations, structured indirect injection, and tool-assisted attacks [1]. Correia *et al.* survey LLM defenses against injection and jailbreaking and extend NIST adversarial-ML taxonomy with additional defense categories and an effectiveness catalog [2]. Chu proposes the Layered Attack Surface Model (LASM) for *agentic* systems, arguing that controls do not transfer across architectural layers or temporal scales [3]. Arshad develops a STRIDE-oriented threat model for enterprise and RAG settings and argues that classical input validation is insufficient for non-deterministic interfaces [5]. Sarvakar synthesizes attack theory, techniques, and secure-AI system design principles [6].

### B. Detection Frameworks and Empirical Defenses

Prakash *et al.* propose a hybrid real-time detector combining heuristic pre-filtering, semantic transformer embeddings, and behavioral pattern recognition, reporting strong balanced metrics on their evaluation set [7]. Hadiprakoso presents an adaptive multi-layer framework for detecting and mitigating prompt injection [8]. Alshammari and Alsaleh integrate gateway telemetry with Elastic SIEM rules and a One-Class SVM, emphasizing SOC visibility for multi-turn campaigns [9]. Adharsh *et al.* outline a model-agnostic detection framework oriented to LLM-based security assistants and dataset design [10]. Dzhaliuk *et al.* comparatively evaluate traditional ML, fine-tuned encoders, specialized injection detectors, and LLM-as-classifier setups on a large labeled corpus, highlighting deployment trade-offs between accuracy and cost [11].

### C. Application-Layer Hardening and Adaptive Evaluation

Deep *et al.* stress-test nine defense configurations with an adaptive attacker over tens of thousands of rounds and find that model-self-protection eventually fails, while application-level output filtering held in their setting [4]. Chen *et al.* study test-time defenses based on a small number of *DefensiveTokens* against injection when systems consume external data [12]. Viana proposes SPEF, a four-layer black-box Secure Prompt Engineering Framework, reporting large Attack Success Rate reductions under controlled adversarial corpora [13].

### D. Positioning of This Work

Relative to surveys [1], [2], [3] and single-stack detectors [7], [9], [11], this repository implements a **production-shaped hybrid**: classical TF–IDF ensemble for the common case, gated semantic upgrade, train-only retrieval, ambiguity-only judging, and **mitigation that preserves benign intent**. Unlike SPEF-style prompt engineering alone [13] or token-only test-time defenses [12], our primary artifact is an offline/online **detection + rewrite pipeline** with held-out metrics and ablations under a fixed test contract.

---

## III. Problem Formulation and Threat Model

### A. Problem

Given user (or retrieved) text \(x\), decide action \(a \in \{\mathrm{ALLOW}, \mathrm{FLAG}, \mathrm{REVIEW}, \mathrm{BLOCK}\}\) and, if blocked, produce a mitigated prompt \(x'\) that retains legitimate intent while removing injection wrappers.

### B. Adversary Capabilities

We consider adversaries who can:

- Issue **direct** overrides (“ignore previous instructions”, role swaps, DAN-style jailbreaks).
- Attempt **system/data/tool extraction** and delimiter/context hijacks.
- Use **obfuscation** (leet, zero-width, Base64/URL encodings).
- Frame attacks as **stories**, emotional manipulation, or multi-turn context poisoning.
- Embed **indirect** instructions in content that may later enter the model context (RAG/agent settings), following threat discussions in [3], [5], [6].

We assume the defender controls a gateway in front of the LLM (application-layer enforcement), consistent with arguments that security boundaries should not rely solely on the attacked model [4].

### C. Design Goals

- **High recall** on diverse injection families without catastrophic FPR on benign creative/code text.
- **Low latency** for interactive chat (tens of milliseconds classically; gated transformer only when needed).
- **No test leakage** into retrieval memory.
- **Graceful mitigation**: blocked users receive a safe rewritten request, not only a refusal.

---

## IV. Proposed Method

### A. System Overview

The system is a **5-layer pipeline with Phase 1–5 upgrades** (config `configs/config.yaml`, v4.0.0):

| Stage | Component | Role |
|---|---|---|
| 0 | Text normalizer | Leet / zero-width / Base64 / URL cleanup |
| 1 | Lexical prefilter | High-precision rules, entropy & special-char cues |
| 2 | Classical detectors | TF–IDF (15k features, 1–3 grams) + Logistic, RF, XGBoost, SVM |
| 3 | Ensemble fusion | Weighted probability fusion + precision gate |
| 2b | Semantic upgrade (gated) | `protectai/deberta-v3-base-prompt-injection-v2` when L3 is uncertain |
| R | Attack retrieval | TF–IDF cosine vs **train-only** `data/attack_bank.json` |
| 4 | Ambiguity judge | Heuristic (default) or optional LLM; BLOCK only with corroboration |
| 5 | Intent-preserving rewrite | Extract goal → emit one safe natural prompt |

### B. Layer Details

**Layer 1 (Prefilter).** Rule families include system override, jailbreak, system/data extraction, tool injection, delimiter hijack, and Base64 cues, plus entropy/special-character thresholds for obfuscation signals.

**Layer 2–3 (Classical ensemble).** Four TF–IDF classifiers are fused with weights favoring logistic and SVM (1.3 each) over XGBoost (0.4) and random forest (0.3). Operating point: decision threshold **0.52**; ambiguous if confidence/agreement fall below **0.45**. A **precision gate** requires `block_min_risk ≥ 0.70` and `block_min_agreement ≥ 0.70` (with `strong_risk = 0.82`) before weak ensemble evidence can hard-block.

**Layer 2b (Gated DeBERTa).** Runs when Layer-3 confidence is below **0.40** or the case is marked ambiguous (threshold **0.78**). **Force-block from DeBERTa is disabled** in the paper configuration (`enable_force_block: false`) because earlier probes showed force-blocks dominated false positives on benign story/code text; soft-merge still informs scoring on ambiguous cases.

**Retrieval.** Cosine similarity against a train-built attack bank (hit threshold **0.65**, force-block only at **≥ 0.85** near-duplicates).

**Layer 4 (Judge).** Default `use_real_llm: false` uses a heuristic judge on ambiguous traffic only. A BLOCK requires ensemble / 2b / retrieval corroboration (`require_ensemble_corroboration: true`). Attack-type labels never force-block by themselves.

**Layer 5 (Mitigation).** Intent extraction strips wrappers (jailbreak personas, “ignore instructions”, etc.) and an intent-preserving rewriter produces one natural safe prompt (template/heuristic path; optional LLM rewrite off in the reported config).

### C. Decision Policy

Normalized text flows L1 → L2 → L3 → retrieval → gated 2b → optional L4 → type labeling (metadata) → precision gate → final action → Layer-5 rewrite on block. Decision logging writes to `logs/decisions.jsonl` for auditability.

---

## V. Experimental Setup

### A. Dataset

Processed corpus statistics (`data/processed/stats.json`):

| Split | Size | Notes |
|---|---:|---|
| Train | 189,214 | Malicious 96,315 / Benign 92,899 |
| Val | 40,402 | Frozen |
| Test | 40,402 | Frozen paper-primary |
| Total | 270,018 | Mix: jayavibhav + moltbook + team; extras dropped |

Split ratios 0.7 / 0.15 / 0.15, seed 42, group-id aware splitting. Attack-bank retrieval is built from **train only**.

### B. Metrics and Protocol

Paper-primary mode evaluates labeled `data/processed/test.jsonl` end-to-end (`scripts/Check_Accuracy.py`, mode `heldout`). We report accuracy, precision, recall, F1, AUC-ROC, FPR/FNR, confusion counts, latency, decision-source mix, and per-attack-type detection rates. Ablations on the **same** held-out set:

- `full` — all layers  
- `classical_only` — L1+L2+L3 only  
- `no_layer2b` / `no_retrieval` / `no_layer4` — disable one upgrade each  

### C. Implementation Notes for Reported Runs

- Layer 2b backend: transformer (`protectai/deberta-v3-base-prompt-injection-v2`).
- Layer 4 in reported numbers: **heuristic** (`layer4_heuristic`), not live GPT.
- Hardware auto-plan available via `eval.auto_hw` for reproducible offline jobs.

---

## VI. Results

### A. Held-out Detection Performance (Paper-Primary)

**Table I.** Detection performance on the held-out labeled test set (N = 40,402; 20,622 positive / 19,780 negative). Generated UTC `2026-09-07`.

| Metric | Value |
|---|---:|
| Accuracy | 0.9583 |
| Precision | 0.9706 |
| Recall | 0.9469 |
| F1 | 0.9586 |
| AUC-ROC | 0.9665 |
| FPR | 0.0299 |
| FNR | 0.0531 |
| Specificity | 0.9701 |
| Latency mean (ms) | 10.68 |
| Latency p95 (ms) | 15.72 |

Confusion matrix: **TP 19,528 · TN 19,188 · FP 592 · FN 1,094**.

**Table II.** Decision-source mix on held-out traffic.

| Source | Count | Share |
|---|---:|---:|
| `layer3_ensemble` | 39,439 | 97.6% |
| `layer4_heuristic` | 921 | 2.3% |
| `retrieval` | 42 | 0.1% |

Most decisions remain on the classical ensemble; semantic/judge paths are selectively escalated.

**Table III.** Per-attack-type detection rate (attacks only).

| Attack type | Total | Detected | Rate |
|---|---:|---:|---:|
| system_extraction | 503 | 501 | 0.9960 |
| data_extraction | 6635 | 6540 | 0.9857 |
| direct_injection | 4292 | 4223 | 0.9839 |
| tool_injection | 289 | 275 | 0.9516 |
| obfuscation | 17 | 16 | 0.9412 |
| context_poisoning | 440 | 409 | 0.9295 |
| multi_turn | 1020 | 944 | 0.9255 |
| jailbreak | 1468 | 1330 | 0.9060 |
| unknown | 5958 | 5290 | 0.8879 |

### B. Ablation Study

**Table IV.** Component ablation on the same held-out set.

| Ablation | Acc | Prec | Rec | F1 | AUC | FPR | Lat (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|
| **full** | 0.9583 | 0.9706 | 0.9469 | **0.9586** | 0.9665 | 0.0299 | 11.17 |
| classical_only | 0.9307 | **0.9918** | 0.8714 | 0.9277 | **0.9932** | **0.0075** | 5.85 |
| no_layer2b | 0.9204 | 0.9930 | 0.8500 | 0.9160 | 0.9930 | 0.0063 | 6.54 |
| no_retrieval | 0.9583 | 0.9706 | 0.9469 | 0.9586 | 0.9666 | 0.0299 | 12.32 |
| no_layer4 | 0.9576 | 0.9794 | 0.9366 | 0.9575 | 0.9686 | 0.0205 | 15.33 |

**Findings.**

1. **Hybrid `full` favors recall** (0.9469) versus classical-only (0.8714), at a moderate FPR of 2.99%.  
2. **Classical-only maximizes precision / minimizes FPR** (FPR 0.75%) but misses more attacks—useful as a high-precision operating point.  
3. **Retrieval ablation ≈ full** at current thresholds (near-duplicate force-block is rare: 42 retrieval finals).  
4. **Removing Layer 2b hurts** more than classical-only (F1 0.9160), indicating the gated semantic path and remaining stack interact; L4 heuristic alone does not substitute for 2b.  
5. **Layer 4** slightly improves recall versus `no_layer4` (0.9469 vs 0.9366) with a small FPR increase.

---

## VII. Discussion

Results align with broader literature that favors **layered, application-controlled defenses** over model-only self-protection [4], [7], [8]. The ablation trade-off matches a recurring theme in comparative ML studies [11]: classical detectors are efficient and precise; semantic components buy recall on harder tails (jailbreaks, unknown-tagged attacks).

**Limitations.** (i) Reported Layer-4 path is heuristic, not a live frontier LLM judge. (ii) Obfuscation support in the test slice is small (n = 17). (iii) `unknown` types remain the weakest family (0.8879). (iv) Retrieval adds little at the chosen force-block threshold—bank quality/thresholding is future work. (v) Agent-native threats across memory/tool/multi-agent layers [3] are only partially covered by a prompt gateway.

**Ethics.** The repository is a defensive research prototype. Attack-bank and datasets are for detection evaluation; do not use artifacts to develop offensive exploits against third-party systems.

---

## VIII. Conclusion

We presented a gated hybrid lexical–semantic prompt-injection defense with intent-preserving mitigation. On a frozen held-out set of 40,402 prompts, the system reaches **F1 0.9586** and **FPR 0.0299** at ~11 ms mean latency, with ablations clarifying the precision–recall roles of classical versus hybrid components. Future work includes stronger retrieval banks, calibrated live LLM judging under corroboration constraints, expanded obfuscation/multi-turn evaluation, and tighter integration with agent-stack controls suggested by layered attack-surface models [3].

---

## References

[1] J. D. Duarte *et al.*, “A Systematic Review of Prompt Injection Attacks on Large Language Models: Trends, Taxonomy, Evaluation, Defenses, and Opportunities,” *IEEE Access*, 2026, doi: 10.1109/ACCESS.2026.3656849.

[2] P. H. Barcha Correia *et al.*, “A Systematic Literature Review on LLM Defenses Against Prompt Injection and Jailbreaking: Expanding NIST Taxonomy,” arXiv:2601.22240, 2026.

[3] K. Chu, “A Systematic Survey of Security Threats and Defenses in LLM-Based AI Agents: A Layered Attack Surface Framework,” arXiv:2604.23338, 2026.

[4] P. Deep *et al.*, “Evaluation of Prompt Injection Defenses in Large Language Models,” Swept AI / University of Michigan, Apr. 2026. (arXiv:2604.23887)

[5] B. Arshad, “Prompt Injection Attacks Against Large Language Models: A Comprehensive Threat Model and Mitigation Framework,” Birmingham City University, technical report.

[6] K. Sarvakar, “Prompt Injection Attacks: Theory, Techniques, Defense, and Secure AI Systems,” SSRN 6816879, 2026.

[7] C. Prakash, M. Lind, and E. De La Cruz, “Hybrid Real-time Framework for Detecting Adaptive Prompt Injection Attacks in Large Language Models,” *Journal of Computing Theories and Applications*, doi: 10.62411/jcta.15254.

[8] R. B. Hadiprakoso, “Adaptive Multi-Layer Framework for Detecting and Mitigating Prompt Injection Attacks in Large Language Models,” *Journal of Information Systems Engineering and Business Intelligence*, vol. 11, no. 3, pp. 473–487, Oct. 2025, doi: 10.20473/jisebi.11.3.473-487.

[9] A. A. Alshammari and O. I. Alsaleh, “Detecting Prompt Injection Attacks in Generative AI Systems: A Hybrid SIEM and One-Class SVM Framework,” *Electronics*, vol. 15, art. 2242, 2026.

[10] Adharsh C. S., Sanjith Rana H. S., K. V, and U. V, “Prompt Injection Detection in LLM-Based Security Assistants: A Dataset and Framework,” *IJAMRED*, vol. 2, no. 2, 2026.

[11] N. Dzhaliuk *et al.*, “Comparative evaluation of machine learning methods for protecting LLMs from prompt injection attacks,” *International Journal of Information Security*, vol. 25, art. 109, 2026, doi: 10.1007/s10207-026-01264-8.

[12] S. Chen, Y. Wang, N. Carlini, C. Sitawarin, and D. Wagner, “Defending Against Prompt Injection With a Few DefensiveTokens,” ACM CCS-related manuscript (ACM DL id 3733799.3762982).

[13] G. L. Viana, “Secure Prompt Engineering: A Practical Framework for Mitigating Prompt Injection and Data Leakage in LLM-based Systems (SPEF),” SSRN 6956641, 2026.

[14] S. Arefin, “A Hybrid Lexical–Semantic Pipeline for Prompt-Injection Detection with Intent-Preserving Mitigation,” Version 4.0.0 [Computer software], 2026. https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling

---

## Appendix A — Repository Quick Start

```bash
# Python API
python -m venv .venv
# Windows: .\.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env   # set secrets locally; never commit .env
python run_api.py

# Web UI
cd web && npm install && npm start

# Admin console
cd admin && npm install && npm start
```

Windows helpers: `Start.bat`, `StartAdmin.bat`.

### Reproduce paper-primary metrics

```bash
python scripts/Check_Accuracy.py --mode heldout
python scripts/Check_Accuracy.py --mode ablation
```

Artifacts used in this README: `logs/paper/check_accuracy_heldout/` and `logs/paper/check_accuracy_ablation/` (local eval outputs; gitignored).

### Key paths

| Path | Purpose |
|---|---|
| `configs/config.yaml` | Pipeline thresholds and feature flags |
| `src/pipeline/pipeline.py` | End-to-end orchestration |
| `data/attack_bank.json` | Train-only retrieval bank |
| `author/` | LICENSE, NOTICE, AUTHORS, CITATION |
| `docs/ALWAYS_ON_API.md` | Deployment / keep-alive notes |

---

## Appendix B — How to Cite

```bibtex
@software{arefin2026hybrid,
  author  = {Arefin, Shams-ul},
  title   = {A Hybrid Lexical--Semantic Pipeline for Prompt-Injection Detection with Intent-Preserving Mitigation},
  version = {4.0.0},
  year    = {2026},
  url     = {https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling}
}
```
