# Three Linear SVMs for Prompt-Injection Defense, with Safe Prompt Mitigation

---

## 1. Title Page

| Field | Detail |
|---|---|
| **Title** | Three Linear SVMs for Prompt-Injection Defense, with Safe Prompt Mitigation |
| **Author** | Shams-ul Arefin |
| **Affiliation** | Independent research / software artifact |
| **GitHub** | [@arefin95f](https://github.com/arefin95f) |
| **Repository** | https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling |
| **Document type** | Research report and system documentation |
| **Citation style** | IEEE |
| **Version under study** | System configuration `v4.1.0` (`configs/config.yaml`) |
| **Primary evaluation** | Held-out run `logs/admin_evals/heldout_467296f4` (16 September 2026) |
| **Primary topics** | Prompt-injection defense · Jailbreak detection · LLM security · Safe prompt mitigation · Application-layer AI gateway |

**Formatting note (Word / PDF export).** Use Times New Roman, 12 pt; 1.5 or double line spacing; numbered pages; retain the numbered section headings below.

---

## 2. Abstract

Large language models (LLMs) treat natural language as both data and control. Prompt injection, jailbreaking, instruction override, and related adversarial prompting attacks exploit that dual role to bypass safety policies, extract system prompts, leak private context, or coerce unsafe tool use. This report presents an application-layer **prompt-injection defense** gateway: a lightweight AI firewall that classifies untrusted prompts before they reach the model and, when a request is blocked, applies **safe prompt mitigation** by suggesting one safer alternative prompt.

The live detector is a weighted ensemble of three linear support-vector machines (SVMs). The first model uses word-level TF–IDF features after English stopword removal. The second retains stopwords, because short function words such as “not”, “do”, and “you” frequently carry injection cues. The third uses character *n*-grams so that misspelled, encoded, or lightly obfuscated wording still matches. Under configuration `v4.1.0`, the allow-or-block decision is the blend score compared with a fixed threshold of **0.515** (weights **0.12 / 0.38 / 0.50**, selected on the validation split only), with `blend_only: true`. An exact team-bank match may still force a block. Semantic judges, retrieval banks, and precision gates do not participate in the live decision.

Training used **240,641** labeled examples drawn from Jayavibhav, CyberEC, and S-Labs corpora. Evaluation used a frozen held-out test set of **68,446** prompts. On that set the live blend attained accuracy **0.9820**, precision **0.9876**, recall **0.9759**, F1-score **0.9817**, AUC-ROC **0.9981**, and false-positive rate **0.0120**, at a mean latency of **3.76 ms** per prompt. Every decision was attributed to the three-SVM blend. Safe-prompt quality was not scored and is not claimed as an empirical result. All figures in this report refer to the same decision rule unless stated otherwise.

**Index Terms**—Prompt injection defense, jailbreak detection, adversarial prompts, LLM security, LLM safety, AI red teaming, instruction override, system prompt extraction, indirect prompt injection, application-layer AI gateway, prompt filtering, linear SVM ensemble, TF–IDF, character *n*-grams, text classification, safe prompt mitigation, safe prompt rewriting, ablation study.

---

## 3. Table of Contents

1. [Title Page](#1-title-page)  
2. [Abstract](#2-abstract)  
3. [Table of Contents](#3-table-of-contents)  
4. [Introduction](#4-introduction)  
5. [Literature Review](#5-literature-review)  
6. [Research Methodology](#6-research-methodology)  
7. [System Architecture](#7-system-architecture)  
8. [Results and Analysis](#8-results-and-analysis)  
9. [Discussion](#9-discussion)  
10. [Conclusion and Recommendations](#10-conclusion-and-recommendations)  
11. [References](#11-references)  
12. [Appendices](#12-appendices)

---

## 4. Introduction

### 4.1 Background and Motivation

Prompt injection defense, jailbreak detection, and broader LLM security have become primary concerns for production AI systems [1]–[3]. Unlike classical input validation, the attack surface is linguistic: untrusted user text, retrieved documents (including indirect prompt injection in RAG pipelines), or tool outputs can be interpreted as instructions. Published taxonomies and corpora now support systematic measurement of detection and defense methods [1], [2], [11]. At the same time, application designers require an AI gateway that is accurate enough to trust and fast enough to place in front of interactive chat [7], [11].

### 4.2 Problem Statement

An LLM application cannot reliably separate trusted system instructions from untrusted user or retrieved text. An adversary may therefore perform instruction override, system prompt extraction, data exfiltration, jailbreaking, or unsafe tool invocation [4]–[6]. Ordinary sanitization is a weak fit for an open language interface [5]. Many defenses either block benign technical questions or refuse the entire request and discard a legitimate user goal wrapped inside attack wording [1], [7], [8].

### 4.3 Research Aim and Objectives

**Aim.**  
To design, implement, and evaluate an application-layer **prompt-injection defense** based on a three-SVM blend, with **safe prompt mitigation** after a block.

**Specific objectives.**

1. Train three linear SVMs on complementary text views and fuse them with fixed, validation-selected weights.  
2. Keep later or optional stages off the decision path when they reduce held-out performance (`blend_only: true`).  
3. Attach safe prompt mitigation after a block—suggesting one safer alternative prompt—without treating mitigation quality as a measured outcome.  
4. Score the live decision on a frozen held-out test set and report contribution evidence for the blend components and normalizer on that same file (ablation).  
5. Expose the detector through a FastAPI service, a public chat UI, and a research admin console for reproducible evaluation.

### 4.4 Scope and Boundaries

This report measures **offline prompt-injection detection** on labeled prompt text and describes the post-block safe prompt mitigation module. It does **not** report adaptive attack success rates, human ratings of safe-prompt quality, or a leaderboard comparison against external detectors on this test file. Those experiments were not conducted.

### 4.5 Organization of the Report

Section 5 reviews related literature. Section 6 presents the research design, data, and metrics. Section 7 documents the live system architecture. Section 8 reports held-out and ablation results. Section 9 interprets those findings and states limitations. Section 10 concludes and offers recommendations. References and appendices follow.

---

## 5. Literature Review

### 5.1 Taxonomies, Surveys, and Threat Models

Duarte *et al.* review prompt-injection attacks, taxonomies, evaluation methods, and defenses across direct, multi-turn, structured, and tool-assisted threats [1]. Correia *et al.* survey defenses against injection and jailbreaking and extend the NIST adversarial-learning taxonomy [2]. Chu argues that controls do not transfer uniformly across architectural layers of agent systems [3]. Arshad develops a STRIDE-oriented threat model for LLM and retrieval settings [5]. Sarvakar synthesizes attack techniques and secure-system principles [6].

### 5.2 Detection Frameworks

Prakash *et al.* combine heuristic prefiltering, embeddings, and behavioral cues [7]. Hadiprakoso describes an adaptive multi-layer detector [8]. Alshammari and Alsaleh pair gateway telemetry with one-class SVM scoring [9]. Dzhaliuk *et al.* compare classical models, encoders, specialized injection detectors, and LLM-as-classifier setups, and emphasize the accuracy–cost trade-off [11].

### 5.3 Application-Layer Hardening

Deep *et al.* conclude that a security boundary should be enforced in application code rather than left to the model under attack [4]. Chen *et al.* study test-time defensive tokens for systems that consume external data [12]. Viana proposes a layered prompt-engineering framework for black-box APIs [13].

### 5.4 Research Gap

Layered defenses are well motivated [1], [2], [7], [8], and application-side enforcement is preferable to model-only self-protection [4]. Two practical gaps remain. First, many systems stop at a binary allow-or-block outcome and do not provide **safe prompt mitigation**—a safer alternative the user can accept [1], [8]. Second, many pipelines add semantic or heuristic stages without demonstrating, on the same frozen test file, whether those stages improve or degrade detection [11].

This project addresses those gaps with a named corpus, a frozen test split, a three-SVM blend as the sole live decision mechanism, an ablation study of complementary views, and safe prompt mitigation after blocking. It does not claim to resolve agent-memory or multi-agent threats [3].

---

## 6. Research Methodology

### 6.1 Research Design

The study follows an experimental systems-design approach:

1. Implement the gateway and freeze its decision configuration (`configs/config.yaml`, version `4.1.0`).  
2. Assemble named train, validation, and test splits from published corpora under `data/raw/`.  
3. Train the three linear SVMs (`src/layers/layer2_classifiers.py`).  
4. Select blend weights and the decision threshold on the validation split only.  
5. Score the live blend once on the frozen held-out test set (`scripts/Check_Accuracy.py --mode heldout`).  
6. Run a six-row ablation on the same held-out file (`--mode ablation`).  
7. Report aggregate metrics, the confusion matrix, latency, decision-source attribution, detection rate by attack type, and ablation contrasts.

Detection outcomes are quantitative. **Safe-prompt mitigation quality was not scored** and is therefore not presented as an empirical claim.

### 6.2 Data Sources

Labeled prompts were assembled from named files under `data/raw/{train,val,test}/`, not from a survey instrument.

| Corpus | Representative file |
|---|---|
| Jayavibhav Prompt Injection | `jayavibhav_prompt_injection.jsonl` |
| CyberEC Prompt Injection Dataset 2 | `cyberec_prompt-injection-dataset2.jsonl` |
| S-Labs Prompt Injection | `s-labs_prompt-injection.jsonl` |

Processed rows in `data/processed/{train,val,test}.jsonl` contain at least `text`, `label`, `attack_category`, and `source`. Split integrity statistics are recorded in `data/processed/stats.json`.

### 6.3 Sample Size and Split Protocol

Official publisher splits were retained for CyberEC and S-Labs. For Jayavibhav, which provides no official validation split, 15% of the official train set was carved for validation by `group_id` (seed 42); the official Jayavibhav test set remained frozen. Fingerprint-based deduplication was applied, and training excluded validation and test rows. Exact fingerprint overlap across the final train, validation, and test files is zero (`integrity_exact_overlap` in `stats.json`).

| Split | \(N\) | Malicious | Benign |
|---|---:|---:|---:|
| Train | 240,641 | 119,253 | 121,388 |
| Validation | 42,162 | 20,731 | 21,431 |
| Held-out test | 68,446 | 33,894 | 34,552 |

**Training sources.** Jayavibhav 222,347; S-Labs 11,043; CyberEC 7,251.  
**Validation sources.** Jayavibhav 39,236; S-Labs 1,985; CyberEC 941.  
**Held-out test sources.** Jayavibhav 65,403; S-Labs 2,101; CyberEC 942.

### 6.4 Evaluation Metrics

The following metrics are reported: accuracy, precision, recall, F1-score, AUC-ROC, false-positive rate, false-negative rate, specificity, confusion counts, mean and high-percentile latency, decision-source attribution, detection rate by attack type on the malicious subset, and McNemar-tested ablation contrasts versus the full system.

### 6.5 Analysis Procedure

Section 8 reports the held-out evaluation on `data/processed/test.jsonl` (\(N = 68{,}446\)). Hyperparameters were selected on validation only; the test set was scored once under `blend_only: true`. Ablation modes temporarily alter Layer 3 weights or disable Layer 1, then restore the live configuration.

### 6.6 Ethical Considerations

The work is defensive. This report does not provide exploit recipes against third-party production systems. The admin console is intended for localhost research use and is token-gated.

---

## 7. System Architecture

### 7.1 Live Decision Path

The live decision path is the three-SVM blend. Other modules remain in the repository for normalization, attack-type labeling, safe prompt mitigation, or research tooling; they do not override the blend under the reported configuration (`blend_only: true`).

| Stage | Module | Role in the live system |
|---|---|---|
| 1 | Layer 1 Normalizer (`layer1_normalizer.py`) | Decodes and unfolds obfuscation (e.g., leetspeak, homoglyphs, zero-width characters, Base64, hex, URL encoding, spaced letters). The SVMs score the normalized string. This stage does **not** allow or block. |
| 2 | Layer 2 Classifiers (`layer2_classifiers.py`) | Three linear SVMs: stopword TF–IDF (`svm`), no-stopword TF–IDF (`svm_nostop`), and character *n*-grams (`char_svm`). |
| 3 | Layer 3 Blend (`layer3_blend.py`) | Weighted average of the three risk scores. **This stage produces the allow-or-block decision.** |
| — | Attack typer (`attack_typer.py`) | Assigns an explanatory attack-type label. Labels do **not** decide allow or block. |
| 4 | Layer 4 Safe Prompt Mitigation (`layer4_rewriter.py`) | After a block, proposes one safer alternative prompt the user may accept. This stage does **not** allow or block. Heuristic rewrite is the default; optional LLM rewrite is off (`use_llm_rewrite: false`). |

**Orchestration.** `src/pipeline/pipeline.py` · **Configuration.** `configs/config.yaml` · **Artifacts.** `models/detector/`

### 7.2 Feature Views and Model Specs

Three complementary views are used because English stopword lists can delete injection cues, whereas character *n*-grams remain informative under spelling alteration.

| Model key | Representation | Principal settings |
|---|---|---|
| `svm` | Word TF–IDF, English stopwords removed | `max_features=15000`, word *n*-grams (1, 2) |
| `svm_nostop` | Word TF–IDF, stopwords retained | `max_features=20000`, word *n*-grams (1, 2) |
| `char_svm` | Character TF–IDF (`char_wb`) | `max_features=30000`, character *n*-grams (3, 5) |

Each classifier is a `LinearSVC` with balanced class weights. Risk scores are fused by probability-weighted average, not hard majority vote.

### 7.3 Decision Rule

**Blend weights.** Stopword SVM 0.12; no-stopword SVM 0.38; character SVM 0.50.  
**Decision threshold.** 0.515 — scores strictly above 0.515 are treated as malicious.  
**Blend-only mode.** With `blend_only: true`, agreement / risk precision gates do not reverse a blend block.  
**Override.** An exact team-bank hit (`data/team_overrides.json`) may force BLOCK while leaving the blend score unchanged. On the held-out file reported below, every decision still came from `layer3_blend`.  
**Weights and threshold** were tuned on validation and then frozen for the reported test.

### 7.4 Runtime Surface

| Component | Path | Default endpoint |
|---|---|---|
| FastAPI detector | `run_api.py`, `src/api/app.py` | http://localhost:8000 |
| Public chat UI | `web/` | http://localhost:3001 |
| Research admin console | `admin/` | http://localhost:3002 |
| Windows launchers | `Start.bat`, `StartAdmin.bat` | Starts API + web (or admin) |

Decision logs are written to `logs/decisions.jsonl` when `feature_flags.decision_logging` is enabled. Held-out and ablation reports are written under `logs/admin_evals/`.

---

## 8. Results and Analysis

### 8.1 Held-Out Detection Performance

**Table I.** Live three-SVM blend on the frozen held-out test set (\(N = 68{,}446\)). Validation-selected weights 0.12 / 0.38 / 0.50 at threshold 0.515. Source: `logs/admin_evals/heldout_467296f4`.

| Metric | Value |
|---|---:|
| Accuracy | 0.9820 |
| Precision | 0.9876 |
| Recall | 0.9759 |
| F1-score | 0.9817 |
| AUC-ROC | 0.9981 |
| False-positive rate | 0.0120 |
| False-negative rate | 0.0241 |
| Specificity | 0.9880 |
| Mean latency | 3.76 ms |
| p95 latency | 4.48 ms |

**Confusion matrix.** TP = 33,077; TN = 34,137; FP = 415; FN = 817.

Approximately 1.2% of benign prompts were blocked. Approximately 2.4% of attacks were missed.

### 8.2 Decision-Source Attribution

**Table II.** Decision source on the same 68,446 prompts.

| Decision source | Count | Proportion |
|---|---:|---:|
| Three-SVM blend (`layer3_blend`) | 68,446 | 100% |

The blend decided every row. Any report in which a judge or retrieval module appears as a decision source describes a different system and must not be cited as Table II.

### 8.3 Detection by Attack Type

**Table III.** Detection rate on the malicious subset of the same run, using the runtime attack-type labels produced during evaluation.

| Attack type | Support | Detected | Detection rate |
|---|---:|---:|---:|
| Tool injection | 98 | 98 | 1.0000 |
| Indirect injection | 11 | 11 | 1.0000 |
| Emotional manipulation | 2 | 2 | 1.0000 |
| Story jailbreak | 2 | 2 | 1.0000 |
| Direct override | 834 | 831 | 0.9964 |
| Data extraction | 638 | 635 | 0.9953 |
| Multi-turn | 62 | 61 | 0.9839 |
| System extraction | 115 | 113 | 0.9826 |
| Obfuscation | 49 | 48 | 0.9796 |
| Unknown | 31,458 | 30,688 | 0.9755 |
| Direct injection | 370 | 351 | 0.9486 |
| Jailbreak | 234 | 218 | 0.9316 |
| Context tampering | 10 | 9 | 0.9000 |
| Role impersonation | 11 | 10 | 0.9091 |

Named override / extraction categories are detected at high rates. The large **unknown** slice dominates the malicious subset and remains the principal residual error mass. Several categories have very small support and should not be over-generalized.

### 8.4 Ablation Study

**Table IV.** Ablation on the same held-out file. Source: `logs/admin_evals/ablation_6bed6475`. Rows marked \* differ from the full system at McNemar \(p < 0.05\).

| Configuration | Accuracy | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| Stopword SVM alone | 0.9659 | 0.9749 | 0.9557 | 0.9652\* |
| No-stopword SVM alone | 0.9768 | 0.9829 | 0.9700 | 0.9764\* |
| Character SVM alone | 0.9776 | 0.9830 | 0.9717 | 0.9773\* |
| Equal weights (1/3 each) | 0.9811 | 0.9872 | 0.9746 | 0.9808\* |
| Full system (Layer 1–3) | **0.9820** | **0.9876** | **0.9759** | **0.9817** |
| No normalization (Layer 2–3) | 0.9821 | 0.9881 | 0.9757 | 0.9818 |

Each single view is significantly weaker than the full blend. Equal weights are also significantly weaker than the validation-tuned weights. Disabling the normalizer yields a near-identical aggregate F1 on this particular test file; the live system retains Layer 1 because it is designed for obfuscated production inputs that are under-represented in the held-out slice.

### 8.5 Comparison with a Prior Pipeline Variant

**Table V.** Same repository lineage, different decision rules. The earlier row corresponds to a previous held-out run in which a semantic judge and retrieval were permitted to decide some rows.

| System | Acc. | Prec. | Rec. | F1 | AUC | FPR |
|---|---:|---:|---:|---:|---:|---:|
| Live three-SVM blend (Table I) | 0.9820 | 0.9876 | 0.9759 | 0.9817 | 0.9981 | 0.0120 |
| Prior multi-stage pipeline | 0.9583 | 0.9706 | 0.9469 | 0.9586 | 0.9665 | 0.0299 |

On this repository’s own held-out history, removing non-blend decision stages and retaining the three-SVM path improved aggregate detection relative to that earlier pipeline. This is **not** a claim that the blend dominates every published detector on every dataset.

---

## 9. Discussion

### 9.1 Interpretation of Findings

The literature favors a cheap common path and enforcement outside the model under attack [4], [11]. The measured system matches that design: three linear SVMs, one threshold, mean latency under 4 ms, and no semantic override on the live path. The held-out evidence indicates that this common path can be both accurate and operationally lightweight.

Published F1 scores from other papers are not compared numerically here. Those results used different datasets and splits; placing them beside Table I would not constitute a valid comparison.

### 9.2 Design Choices Relative to Earlier Variants

An earlier project variant fused heterogeneous classical models and allowed semantic, retrieval, and judge stages to alter the final call. On this repository’s prior held-out record that pipeline scored F1 0.9586 (Table V). The live system dropped those decision stages. Table I reports the system that remains.

The ablation (Table IV) supports keeping all three views and the validation-tuned weights. It does not justify restoring semantic decision stages.

### 9.3 Limitations

1. Safe-prompt fluency, fidelity, and user acceptance were not scored.  
2. External public detectors were not re-run on this test file.  
3. Several attack-type categories have very small support.  
4. Training contains source mixtures that do not match the frozen test mixture one-for-one; generalization claims should respect that split.  
5. Only Jayavibhav, CyberEC, and S-Labs files are retained under `data/raw/` for this study.  
6. Threats that reside in agent memory, tool execution, or multi-agent coordination [3] lie outside a prompt gateway.  
7. A team-bank hit can still force a block. It did not appear as a decision source on this test file; deployments with overlapping team examples may diverge from Table I for that reason alone.  
8. Attack-type labels are explanatory annotations from a pattern scorer; they are not an independent detection oracle.

---

## 10. Conclusion and Recommendations

### 10.1 Conclusion

This report presented an application-layer **prompt-injection defense** based on a weighted blend of three linear SVMs, with **safe prompt mitigation** after blocking. On 68,446 frozen held-out prompts, the blend achieved accuracy 0.9820, precision 0.9876, recall 0.9759, F1-score 0.9817, AUC-ROC 0.9981, and false-positive rate 0.0120, at 3.76 ms mean latency. Every decision was attributed to the blend. Ablation shows that each single SVM and equal-weight fusion are significantly weaker than the tuned full system. Safe-prompt quality remains unmeasured and is therefore outside the empirical claims of this study.

### 10.2 Practical Recommendations

1. Deploy the blend as an AI gateway / prompt filter in front of the LLM. It does not replace logging, access control, or secret handling [4], [5].  
2. Do not re-enable semantic, retrieval, or judge decision stages and continue to cite Table I; those configurations constitute a different system.  
3. Treat attack-type labels as explanatory annotations, not as an independent block rule.  
4. Monitor the unknown category in production traffic and fold confirmed mistakes into the training review set.  
5. Keep `blend_only: true` unless a new validation study shows that a precision gate improves the operating point without harming recall.

### 10.3 Future Work

1. Score safe prompt mitigation quality with an explicit rubric and human or model judges.  
2. Re-run strong public detectors on this same frozen test file.  
3. Enlarge low-support attack-type slices, especially context tampering and role impersonation.  
4. Measure the effect of the team-bank override once it fires on held-out text.  
5. Investigate agent-layer threats that a prompt gateway cannot observe [3].

---

## 11. References

[1] J. D. Duarte *et al.*, “A Systematic Review of Prompt Injection Attacks on Large Language Models: Trends, Taxonomy, Evaluation, Defenses, and Opportunities,” *IEEE Access*, 2026, doi: 10.1109/ACCESS.2026.3656849.

[2] P. H. Barcha Correia *et al.*, “A Systematic Literature Review on LLM Defenses Against Prompt Injection and Jailbreaking: Expanding NIST Taxonomy,” arXiv:2601.22240, 2026.

[3] K. Chu, “A Systematic Survey of Security Threats and Defenses in LLM-Based AI Agents: A Layered Attack Surface Framework,” arXiv:2604.23338, 2026.

[4] P. Deep *et al.*, “Evaluation of Prompt Injection Defenses in Large Language Models,” Swept AI and University of Michigan, 2026. (arXiv:2604.23887)

[5] B. Arshad, “Prompt Injection Attacks Against Large Language Models: A Comprehensive Threat Model and Mitigation Framework,” Birmingham City University.

[6] K. Sarvakar, “Prompt Injection Attacks: Theory, Techniques, Defense, and Secure AI Systems,” SSRN 6816879, 2026.

[7] C. Prakash, M. Lind, and E. De La Cruz, “Hybrid Real-time Framework for Detecting Adaptive Prompt Injection Attacks in Large Language Models,” *Journal of Computing Theories and Applications*, doi: 10.62411/jcta.15254.

[8] R. B. Hadiprakoso, “Adaptive Multi-Layer Framework for Detecting and Mitigating Prompt Injection Attacks in Large Language Models,” *Journal of Information Systems Engineering and Business Intelligence*, vol. 11, no. 3, pp. 473–487, Oct. 2025, doi: 10.20473/jisebi.11.3.473-487.

[9] A. A. Alshammari and O. I. Alsaleh, “Detecting Prompt Injection Attacks in Generative AI Systems: A Hybrid SIEM and One-Class SVM Framework,” *Electronics*, vol. 15, art. 2242, 2026.

[10] Adharsh C. S., Sanjith Rana H. S., K. V, and U. V, “Prompt Injection Detection in LLM-Based Security Assistants: A Dataset and Framework,” *IJAMRED*, vol. 2, no. 2, 2026.

[11] N. Dzhaliuk *et al.*, “Comparative evaluation of machine learning methods for protecting LLMs from prompt injection attacks,” *International Journal of Information Security*, vol. 25, art. 109, 2026, doi: 10.1007/s10207-026-01264-8.

[12] S. Chen, Y. Wang, N. Carlini, C. Sitawarin, and D. Wagner, “Defending Against Prompt Injection With a Few DefensiveTokens,” ACM manuscript (ACM DL 3733799.3762982).

[13] G. L. Viana, “Secure Prompt Engineering: A Practical Framework for Mitigating Prompt Injection and Data Leakage in LLM-based Systems (SPEF),” SSRN 6956641, 2026.

[14] S. Arefin, “Three Linear SVMs for Prompt-Injection Defense, with Safe Prompt Mitigation” [Computer software]. Available: https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling

---

## 12. Appendices

### Appendix A — Reproducing the Runtime Stack

**Prerequisites.** Python 3.8+ · Node.js 18+ · trained artifacts under `models/detector/`.

```bash
python -m venv .venv
# Windows:
.\.venv\Scripts\activate
# macOS / Linux:
# source .venv/bin/activate

pip install -e .
# Optional LLM extras:
# pip install -e ".[llm]"

# Optional: create a local .env for chat backend keys (UTF-8).
# Required keys depend on the chosen chat provider in the web UI.

python run_api.py
```

The API listens on http://localhost:8000. Health: http://localhost:8000/health. OpenAPI docs: http://localhost:8000/docs.

```bash
cd web && npm install && npm start
# Chat UI → http://localhost:3001

cd admin && npm install && npm start
# Admin console → http://localhost:3002
```

Windows launchers: `Start.bat` (API + chat UI) and `StartAdmin.bat` (admin).

### Appendix B — Training and Evaluation Commands

Rebuild processed splits from `data/raw/{train,val,test}`:

```bash
python main.py --step process
```

Train the three SVMs:

```bash
python main.py --step train
```

Held-out scoring of the live decision:

```bash
python scripts/Check_Accuracy.py --mode heldout
```

Ablation on the same held-out file:

```bash
python scripts/Check_Accuracy.py --mode ablation
```

Those commands score the decision rule currently encoded in `configs/config.yaml`. With `blend_only: true`, the held-out report corresponds to the blend summarized in Table I.

### Appendix C — Principal Artifact Paths

| Path | Description |
|---|---|
| `configs/config.yaml` | Live weights, threshold, `blend_only`, version `4.1.0` |
| `configs/category_map.yaml` | Canonical attack taxonomy and aliases |
| `src/pipeline/pipeline.py` | Decision orchestration |
| `src/layers/layer1_normalizer.py` | Obfuscation unfolding |
| `src/layers/layer2_classifiers.py` | The three SVMs |
| `src/layers/layer3_blend.py` | Weighted blend |
| `src/layers/layer4_rewriter.py` | Safe prompt mitigation after a block |
| `src/layers/attack_typer.py` | Label-only attack typing |
| `src/api/app.py` | FastAPI service |
| `models/detector/` | Saved SVM and vectorizer artifacts |
| `data/processed/` | Frozen train, validation, and test splits |
| `data/processed/stats.json` | Split protocol and integrity counts |
| `scripts/Check_Accuracy.py` | Held-out and ablation evaluation |
| `logs/admin_evals/` | Paper-ready evaluation packs |
| `web/` | Public chat interface |
| `admin/` | Admin laboratory and reports |

### Appendix D — Live Configuration Snapshot (`v4.1.0`)

```yaml
system:
  name: Prompt Injection Defense System
  version: 4.1.0
  description: 3-SVM blend (val-tuned 0.12/0.38/0.50 @ 0.515) on official Jaya+CyberEC+S-Labs

layers:
  layer3:
    blend_only: true
    decision_threshold: 0.515
    weights:
      svm: 0.12
      svm_nostop: 0.38
      char_svm: 0.5
  layer4:
    enabled: true
    use_llm_rewrite: false
    intent_preserving: true
```

### Appendix E — Software Citation (BibTeX)

```bibtex
@software{arefin_prompt_injection_defense,
  author       = {Arefin, Shams-ul},
  title        = {Three Linear SVMs for Prompt-Injection Defense, with Safe Prompt Mitigation},
  version      = {4.1.0},
  url          = {https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling},
  year         = {2026},
  keywords     = {prompt injection defense, jailbreak detection, LLM security, safe prompt mitigation, linear SVM, TF-IDF, AI gateway}
}
```
