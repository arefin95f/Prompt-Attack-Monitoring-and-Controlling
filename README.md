# Three Linear SVMs for Prompt-Injection Detection, with Intent-Preserving Mitigation

---

## 1. Title Page

| Field | Detail |
|---|---|
| **Title** | Three Linear SVMs for Prompt-Injection Detection, with Intent-Preserving Mitigation |
| **Author** | Shams-ul Arefin |
| **Affiliation** | Independent research / software artifact |
| **GitHub** | [@arefin95f](https://github.com/arefin95f) |
| **Repository** | https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling |
| **Document type** | Research report |
| **Citation style** | IEEE |
| **Version under study** | System configuration `v4.1.0` (`configs/config.yaml`) |

**Formatting note (Word / PDF export).** Use Times New Roman, 12 pt; 1.5 or double line spacing; numbered pages; retain the numbered section headings below.

---

## 2. Abstract

Large language models (LLMs) treat natural language as both data and control. Prompt injection exploits that dual role to override instructions, extract hidden context, or coerce unsafe tool use. This report presents an application-layer gateway that detects such prompts and, when a request is blocked, offers one safer rephrasing of any recoverable legitimate intent.

The live detector is a weighted blend of three linear support-vector machines (SVMs). The first model uses word-level TF–IDF features after English stopword removal. The second retains stopwords, because short function words such as “not”, “do”, and “you” frequently carry injection cues. The third uses character *n*-grams so that misspelled or lightly obfuscated wording still matches. The allow-or-block decision is the blend score compared with a fixed threshold of **0.515** (weights **0.12 / 0.38 / 0.50**, selected on the validation split only). An exact team-bank match may still force a block. Semantic judges, retrieval banks, and precision gates do not participate in the live decision.

Training used **240,641** labeled examples drawn from Jayavibhav, CyberEC, and S-Labs corpora. Evaluation used a frozen held-out test set of **68,446** prompts. On that set the live blend attained accuracy **0.9820**, precision **0.9876**, recall **0.9759**, F1-score **0.9817**, and false-positive rate **0.0120**. Rewrite quality was not scored and is not claimed as an empirical result. All figures in this report refer to the same decision rule unless stated otherwise.

**Index Terms**—Prompt injection, jailbreak detection, LLM security, linear SVM, TF–IDF, character *n*-grams, intent-preserving mitigation.

---

## 3. Table of Contents

1. [Title Page](#1-title-page)  
2. [Abstract](#2-abstract)  
3. [Table of Contents](#3-table-of-contents)  
4. [Introduction](#4-introduction)  
5. [Literature Review](#5-literature-review)  
6. [Research Methodology](#6-research-methodology)  
7. [Results and Analysis](#7-results-and-analysis)  
8. [Discussion](#8-discussion)  
9. [Conclusion and Recommendations](#9-conclusion-and-recommendations)  
10. [References](#10-references)  
11. [Appendices](#11-appendices)

---

## 4. Introduction

### 4.1 Background and Motivation

Prompt injection has become a primary security concern for LLM-backed applications [1]–[3]. Unlike classical input validation, the attack surface is linguistic: untrusted user text, retrieved documents, or tool outputs can be interpreted as instructions. Published taxonomies and corpora now support systematic measurement of detection methods [1], [2], [11]. At the same time, application designers require defenses that are accurate enough to trust and fast enough to place in front of interactive chat [7], [11].

### 4.2 Problem Statement

An LLM application cannot reliably separate trusted system instructions from untrusted user or retrieved text. An adversary may therefore override prior instructions, leak secrets, jailbreak safety policies, or invoke privileged tools [4]–[6]. Ordinary sanitization is a weak fit for an open language interface [5]. Many defenses either block benign technical questions or refuse the entire request and discard a legitimate goal wrapped inside attack wording [1], [7], [8].

### 4.3 Research Aim and Objectives

**Aim.**  
To design, implement, and evaluate an application-layer gateway that detects prompt injection with a three-SVM blend and mitigates blocked prompts by offering one safer request.

**Specific objectives.**

1. Train three linear SVMs on complementary text views and fuse them with fixed, validation-selected weights.  
2. Keep later or optional stages off the decision path when they reduce held-out performance.  
3. Attach an intent-preserving rewrite after a block, without treating rewrite quality as a measured outcome.  
4. Score the live decision on a frozen held-out test set and report contribution evidence for the blend components and normalizer on that same file.

### 4.4 Scope and Boundaries

This report measures **offline detection** on labeled prompt text and describes the post-block rewrite module. It does **not** report adaptive attack success rates, human ratings of rewrite quality, or a leaderboard comparison against external detectors on this test file. Those experiments were not conducted.

### 4.5 Organization of the Report

Section 5 reviews related literature. Section 6 presents the research design, system under study, data, and metrics. Section 7 reports held-out results. Section 8 interprets those findings and states limitations. Section 9 concludes and offers recommendations. References and appendices follow.

---

## 5. Literature Review

### 5.1 Taxonomies, Surveys, and Threat Models

Duarte *et al.* review prompt-injection attacks, taxonomies, evaluation methods, and defenses across direct, multi-turn, structured, and tool-assisted threats [1]. Correia *et al.* survey defenses against injection and jailbreaking and extend the NIST adversarial-learning taxonomy [2]. Chu argues that controls do not transfer uniformly across architectural layers of agent systems [3]. Arshad develops a STRIDE-oriented threat model for LLM and retrieval settings [5]. Sarvakar synthesizes attack techniques and secure-system principles [6].

### 5.2 Detection Frameworks

Prakash *et al.* combine heuristic prefiltering, embeddings, and behavioral cues [7]. Hadiprakoso describes an adaptive multi-layer detector [8]. Alshammari and Alsaleh pair gateway telemetry with one-class SVM scoring [9]. Dzhaliuk *et al.* compare classical models, encoders, specialized injection detectors, and LLM-as-classifier setups, and emphasize the accuracy–cost trade-off [11].

### 5.3 Application-Layer Hardening

Deep *et al.* conclude that a security boundary should be enforced in application code rather than left to the model under attack [4]. Chen *et al.* study test-time defensive tokens for systems that consume external data [12]. Viana proposes a layered prompt-engineering framework for black-box APIs [13].

### 5.4 Research Gap

Layered defenses are well motivated [1], [2], [7], [8], and application-side enforcement is preferable to model-only self-protection [4]. Two practical gaps remain. First, many systems stop at a binary allow-or-block outcome and do not offer a safer reformulation of recoverable intent [1], [8]. Second, many pipelines add semantic or heuristic stages without demonstrating, on the same frozen test file, whether those stages improve or degrade detection [11].

This project addresses those gaps with a named corpus, a frozen test split, a three-SVM blend as the sole live decision mechanism, and a rewrite stage after blocking. It does not claim to resolve agent-memory or multi-agent threats [3].

---

## 6. Research Methodology

### 6.1 Research Design

The study follows an experimental systems-design approach:

1. Implement the gateway and freeze its decision configuration.  
2. Assemble named train, validation, and test splits from published corpora.  
3. Train the three linear SVMs.  
4. Select blend weights and the decision threshold on the validation split only.  
5. Score the live blend once on the frozen held-out test set.  
6. Report aggregate metrics, the confusion matrix, decision-source attribution, and detection rate by attack category.

Detection outcomes are quantitative. **Rewrite quality was not scored** and is therefore not presented as an empirical claim.

### 6.2 System Under Study

The live decision path is the three-SVM blend. Other modules remain in the repository for mitigation or research tooling; they do not override the blend under the reported configuration (`blend_only: true`).

| Stage | Module | Role in the live system |
|---|---|---|
| 1 | Layer 1 Normalizer | Decodes and unfolds obfuscation (e.g., leetspeak, zero-width characters, Base64, URL encoding). The SVMs score the normalized string. This stage does not allow or block. |
| 2 | Layer 2 Classifiers | Three linear SVMs: stopword TF–IDF, no-stopword TF–IDF, and character *n*-grams. |
| 3 | Layer 3 Blend | Weighted average of the three risk scores. This stage produces the allow-or-block decision. |
| 4 | Layer 4 Rewriter | After a block, extracts recoverable intent and emits one safer natural-language request. This stage does not allow or block. |

**Blend weights.** Stopword SVM 0.12; no-stopword SVM 0.38; character SVM 0.50.  
**Decision threshold.** 0.515 — scores strictly above 0.515 are treated as malicious.  
**Override.** An exact team-bank hit may force BLOCK. On the held-out file reported below, that override did not fire.  
**Configuration.** `configs/config.yaml`. Orchestration: `src/pipeline/pipeline.py`.

Three complementary views are used because English stopword lists can delete injection cues, whereas character *n*-grams remain informative under spelling alteration. Weights and threshold were tuned on validation and then frozen for the reported test.

### 6.3 Data Sources

Labeled prompts were assembled from named files under `data/raw/`, not from a survey instrument.

| Corpus | Representative file |
|---|---|
| Jayavibhav Prompt Injection | `jayavibhav_prompt_injection.jsonl` |
| CyberEC Prompt Injection Dataset 2 | `cyberec_prompt-injection-dataset2.jsonl` |
| S-Labs Prompt Injection | `s-labs_prompt-injection.jsonl` |

Processed rows in `data/processed/{train,val,test}.jsonl` contain at least `text`, `label`, `attack_category`, and `source`.

### 6.4 Sample Size and Split Protocol

Official publisher splits were retained for CyberEC and S-Labs. For Jayavibhav, which provides no official validation split, 15% of the official train set was carved for validation by `group_id` (seed 42); the official Jayavibhav test set remained frozen. Fingerprint-based deduplication was applied, and training excluded validation and test rows.

| Split | \(N\) | Malicious | Benign |
|---|---:|---:|---:|
| Train | 240,641 | 119,253 | 121,388 |
| Validation | 42,162 | 20,731 | 21,431 |
| Held-out test | 68,446 | 33,894 | 34,552 |

**Training sources.** Jayavibhav 222,347; S-Labs 11,043; CyberEC 7,251.  
**Validation sources.** Jayavibhav 39,236; S-Labs 1,985; CyberEC 941.  
**Held-out test sources.** Jayavibhav 65,403; S-Labs 2,101; CyberEC 942.

### 6.5 Evaluation Metrics

The following metrics are reported: accuracy, precision, recall, F1-score, AUC-ROC (where available), false-positive rate, false-negative rate, specificity, confusion counts, mean and high-percentile latency, decision-source attribution, and detection rate by attack category on the malicious subset.

### 6.6 Analysis Procedure

Section 7 reports the held-out evaluation on `data/processed/test.jsonl` (\(N = 68{,}446\)). Hyperparameters were selected on validation only; the test set was scored once under `blend_only: true`.

### 6.7 Ethical Considerations

The work is defensive. This report does not provide exploit recipes against third-party production systems.

---

## 7. Results and Analysis

### 7.1 Held-Out Detection Performance

**Table I.** Live three-SVM blend on the frozen held-out test set (\(N = 68{,}446\)). Validation-selected weights 0.12 / 0.38 / 0.50 at threshold 0.515.

| Metric | Value |
|---|---:|
| Accuracy | 0.9820 |
| Precision | 0.9876 |
| Recall | 0.9759 |
| F1-score | 0.9817 |
| False-positive rate | 0.0120 |
| False-negative rate | 0.0241 |
| Specificity | 0.9880 |

**Confusion matrix.** TP = 33,077; TN = 34,137; FP = 415; FN = 817.

Approximately 1.2% of benign prompts were blocked. Approximately 2.4% of attacks were missed.

### 7.2 Decision-Source Attribution

**Table II.** Decision source on the same 68,446 prompts.

| Decision source | Count | Proportion |
|---|---:|---:|
| Three-SVM blend (`layer3_blend`) | 68,446 | 100% |

The blend decided every row. Any report in which a judge or retrieval module appears as a decision source describes a different system and must not be cited as Table II.

### 7.3 Detection by Attack Category

**Table III.** Detection rate on the malicious subset of the same run.

| Attack category | Support | Detected | Detection rate |
|---|---:|---:|---:|
| System extraction | 503 | 503 | 1.0000 |
| Obfuscation | 17 | 17 | 1.0000 |
| Tool injection | 289 | 288 | 0.9965 |
| Data extraction | 6,635 | 6,612 | 0.9965 |
| Direct injection | 4,292 | 4,263 | 0.9932 |
| Multi-turn | 1,020 | 1,004 | 0.9843 |
| Jailbreak | 1,468 | 1,442 | 0.9823 |
| Context poisoning | 440 | 430 | 0.9773 |
| Unknown | 5,958 | 5,724 | 0.9607 |

Extraction-oriented and direct-injection categories are detected at very high rates. The unknown category is the weakest large group. Obfuscation is perfect on this slice, but support is only 17 prompts and should not be over-generalized.

### 7.4 Comparison with a Prior Pipeline Variant

**Table IV.** Same repository lineage, different decision rules. The earlier row corresponds to a previous held-out run in which a semantic judge and retrieval were permitted to decide some rows (`logs/admin_evals/heldout_2c3c6156.json`, 7 September 2026).

| System | Acc. | Prec. | Rec. | F1 | AUC | FPR | Mean ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| Live three-SVM blend (Table I lineage) | 0.9820 | 0.9876 | 0.9759 | 0.9817 | — | 0.0120 | — |
| Prior multi-stage pipeline | 0.9583 | 0.9706 | 0.9469 | 0.9586 | 0.9665 | 0.0299 | 10.68 |

On this repository’s own held-out history, removing non-blend decision stages and retaining the three-SVM path improved aggregate detection relative to that earlier pipeline. This is **not** a claim that the blend dominates every published detector on every dataset.

---

## 8. Discussion

### 8.1 Interpretation of Findings

The literature favors a cheap common path and enforcement outside the model under attack [4], [11]. The measured system matches that design: three linear SVMs, one threshold, and no semantic override on the live path. The held-out evidence indicates that this common path can be both accurate and operationally lightweight.

Published F1 scores from other papers are not compared numerically here. Those results used different datasets and splits; placing them beside Table I would not constitute a valid comparison.

### 8.2 Design Choices Relative to Earlier Variants

An earlier project variant fused heterogeneous classical models and allowed semantic, retrieval, and judge stages to alter the final call. On this repository’s prior held-out record that pipeline scored F1 0.9586 (Table IV). The live system dropped those decision stages. Table I reports the system that remains.

### 8.3 Limitations

1. Rewrite fluency, intent fidelity, and user acceptance were not scored.  
2. External public detectors were not re-run on this test file.  
3. Obfuscation support is only 17 prompts.  
4. Training contains source mixtures that do not match the frozen test mixture one-for-one; generalization claims should respect that split.  
5. Only Jayavibhav, CyberEC, and S-Labs files are retained under `data/raw/` for this study.  
6. Threats that reside in agent memory, tool execution, or multi-agent coordination [3] lie outside a prompt gateway.  
7. A team-bank hit can still force a block. It did not fire on this test file; deployments with overlapping team examples may diverge from Table I for that reason alone.

---

## 9. Conclusion and Recommendations

### 9.1 Conclusion

This report presented an application-layer gateway for prompt-injection detection based on a weighted blend of three linear SVMs, together with an intent-preserving rewrite after blocking. On 68,446 frozen held-out prompts, the blend achieved accuracy 0.9820, precision 0.9876, recall 0.9759, F1-score 0.9817, and false-positive rate 0.0120. Every decision was attributed to the blend. Rewrite quality remains unmeasured and is therefore outside the empirical claims of this study.

### 9.2 Practical Recommendations

1. Deploy the blend as a gateway in front of the LLM. It does not replace logging, access control, or secret handling [4], [5].  
2. Do not re-enable semantic, retrieval, or judge decision stages and continue to cite Table I; those configurations constitute a different system.  
3. Treat attack-type labels as explanatory annotations, not as an independent block rule.  
4. Monitor the unknown category in production traffic and fold confirmed mistakes into the training review set.

### 9.3 Future Work

1. Score rewrite quality with an explicit rubric and human or model judges.  
2. Re-run strong public detectors on this same frozen test file.  
3. Enlarge the obfuscation and multi-turn slices.  
4. Measure the effect of the team-bank override once it fires on held-out text.  
5. Investigate agent-layer threats that a prompt gateway cannot observe [3].

---

## 10. References

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

[14] S. Arefin, “Three Linear SVMs for Prompt-Injection Detection, with Intent-Preserving Mitigation” [Computer software]. Available: https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling

---

## 11. Appendices

### Appendix A — Reproducing the Runtime Stack

```bash
python -m venv .venv
# Windows: .\.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python run_api.py
```

The API listens on http://localhost:8000. Health: http://localhost:8000/health. OpenAPI docs: http://localhost:8000/docs.

```bash
cd web && npm install && npm start
cd admin && npm install && npm start
```

Windows launchers: `Start.bat` and `StartAdmin.bat`.

Held-out scoring of the live decision:

```bash
python scripts/Check_Accuracy.py --mode heldout
```

That command scores the decision rule currently encoded in `configs/config.yaml`. With `blend_only: true`, the report corresponds to the blend summarized in Table I.

Train the three SVMs:

```bash
python main.py --step train
```

### Appendix B — Principal Artifact Paths

| Path | Description |
|---|---|
| `configs/config.yaml` | Live weights, threshold, and `blend_only` |
| `src/pipeline/pipeline.py` | Decision orchestration |
| `src/layers/layer2_classifiers.py` | The three SVMs |
| `src/layers/layer3_blend.py` | Weighted blend |
| `src/layers/layer4_rewriter.py` | Post-block safer-prompt rewrite |
| `models/detector/` | Saved SVM and vectorizer artifacts |
| `data/processed/` | Frozen train, validation, and test splits |
| `scripts/Check_Accuracy.py` | Held-out evaluation |
| `web/` | Public chat interface |
| `admin/` | Admin laboratory and reports |

### Appendix C — Software Citation (BibTeX)

```bibtex
@software{arefin_prompt_injection_defense,
  author = {Arefin, Shams-ul},
  title  = {Three Linear SVMs for Prompt-Injection Detection, with Intent-Preserving Mitigation},
  url    = {https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling},
  year   = {2026}
}
```
