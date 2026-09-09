# A Hybrid Lexical–Semantic Pipeline for Prompt-Injection Detection with Intent-Preserving Mitigation

---

## 1. Title Page

| | |
|---|---|
| **Title** | A Hybrid Lexical–Semantic Pipeline for Prompt-Injection Detection with Intent-Preserving Mitigation |
| **Author** | Shams-ul Arefin |
| **GitHub** | [@arefin95f](https://github.com/arefin95f) |
| **Project repository** | https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling |
| **Document type** | Research report |
| **Subject area** | Large language model security; adversarial natural language processing |
| **Citation metadata** | [`author/CITATION.cff`](author/CITATION.cff) |

---

## 2. Abstract

Large language models process natural language as both data and control. That dual role creates a security boundary failure known as prompt injection: untrusted text can override system instructions, extract confidential context, coerce tool use, or jailbreak safety policy. Existing defenses often specialize in one mechanism—rules, classical classifiers, transformers, or prompt engineering—and many stop at binary blocking, discarding recoverable user intent wrapped inside adversarial scaffolding.

This research report presents a hybrid lexical–semantic gateway that detects prompt-injection attempts and, when a block is issued, rewrites the input into a single policy-compliant request that preserves legitimate intent. The pipeline comprises text normalization, rule-based prefiltering, TF–IDF classical detectors fused by a weighted ensemble, a gated DeBERTa semantic module, train-only attack-bank retrieval, an ambiguity-conditioned judge with corroboration constraints, and an intent-preserving mitigation stage.

The final system is evaluated on a frozen held-out test set of 40,402 labeled prompts. Training uses 278,843 named-source examples. The complete pipeline achieves accuracy 0.9583, precision 0.9706, recall 0.9469, F1-score 0.9586, AUC-ROC 0.9665, and false-positive rate 0.0299, at a mean latency of 10.68 ms. Ablation analysis shows that classical layers alone maximize precision and minimize false positives, whereas the full hybrid configuration recovers recall with a controlled false-positive budget. The report documents named corpora, method design, quantitative results, limitations, and recommendations for future work. No external detector is claimed as a benchmarked baseline in this study; comparisons are internal ablations of the proposed pipeline.

**Keywords:** prompt injection; jailbreak detection; LLM security; hybrid NLP; ensemble learning; DeBERTa; intent-preserving mitigation; ablation study.

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

### 4.1 Background

Conversational agents, retrieval-augmented generation (RAG) systems, and tool-using agents increasingly place large language models at the center of software workflows. Unlike conventional interfaces with rigid schemas, these systems accept free-form text that can alter model behavior. Prompt injection exploits that openness: an adversary crafts input—or poisons retrieved content—so that the model prioritizes attacker instructions over the application’s intended policy [1]–[3]. Public incidents have demonstrated leakage of system prompts and hidden operational constraints [4].

### 4.2 Problem Statement

Two practical problems motivate this work.

First, **detection under diversity and cost constraints**. Attack families include direct overrides, jailbreaks, system and data extraction, tool coercion, obfuscation, narrative framing, and multi-turn context manipulation. A single detector class rarely covers all families while remaining fast enough for interactive gateways [1], [2], [11].

Second, **mitigation beyond refusal**. Many systems emit only a hard block. When a user’s legitimate goal is embedded inside adversarial wrappers, discarding the entire prompt harms usability and fails to convert a security event into a safe continuation.

### 4.3 Research Aim and Objectives

**Aim.** Design, implement, and evaluate a hybrid application-layer pipeline for prompt-injection detection with intent-preserving mitigation.

**Objectives.**

1. Construct a layered detector that combines lexical, classical, semantic, retrieval, and ambiguity-resolution components.
2. Enforce precision-oriented blocking so that weak evidence does not freely deny benign traffic.
3. Implement an intent-preserving rewrite path for blocked prompts.
4. Evaluate detection performance on a frozen held-out test set using standard classification metrics, latency, decision-source accounting, and component ablation.
5. Document named datasets, configuration, and reproducibility artifacts.

### 4.4 Research Questions

- **RQ1.** What held-out detection performance does the complete hybrid pipeline achieve?
- **RQ2.** How do classical-only and hybrid configurations trade precision, recall, false-positive rate, and latency?
- **RQ3.** Which pipeline stages account for final decisions on held-out traffic?
- **RQ4.** How does detection rate vary across attack categories present in the test set?

### 4.5 Scope and Boundaries

This report evaluates **offline detection quality** on labeled prompt classification. The intent-preserving rewriter is part of the implemented system and is described methodologically; **no separate quantitative user study or rewrite-quality metric** is reported here. Adaptive red-teaming against live downstream LLMs, and agent-layer threats outside the prompt gateway (persistent memory, multi-agent coordination), are outside the primary evaluation scope.

### 4.6 Contributions

1. A complete hybrid lexical–semantic gateway architecture with gated escalation and corroboration-constrained blocking.
2. An intent-preserving mitigation stage integrated with the detection pipeline.
3. A reproducible held-out evaluation on 40,402 prompts, including ablation and per-category analysis.
4. Transparent documentation of named training and evaluation sources used by the final system.

### 4.7 Report Organization

Section 5 reviews related literature. Section 6 presents methodology, including threat model, system design, datasets, and evaluation protocol. Section 7 reports results and analysis. Section 8 discusses implications and limitations. Section 9 concludes and recommends future work. References and appendices follow.

---

## 5. Literature Review

### 5.1 Taxonomies, Surveys, and Threat Models

Duarte *et al.* synthesize trends, taxonomies, evaluation practice, and defenses for prompt injection, covering direct overrides, multi-turn manipulation, structured indirect injection, and tool-assisted attacks [1]. Correia *et al.* systematically review defenses against injection and jailbreaking and extend NIST adversarial machine-learning taxonomy with additional mitigation categories [2]. Chu proposes a layered attack-surface model for agentic systems and argues that controls do not transfer cleanly across architectural layers or temporal scales [3]. Arshad develops a STRIDE-oriented enterprise threat model for LLM and RAG settings [5]. Sarvakar consolidates attack theory, techniques, and secure-system design considerations [6].

Collectively, these works establish that prompt injection is not a narrow input-validation bug: it is a structural consequence of instruction-following models operating on untrusted text.

### 5.2 Detection Frameworks

Hybrid and multi-layer detectors are a recurring theme. Prakash *et al.* combine heuristic prefiltering, semantic embeddings, and behavioral cues for real-time detection [7]. Hadiprakoso presents an adaptive multi-layer detection and mitigation framework [8]. Alshammari and Alsaleh integrate gateway telemetry with SIEM correlation and one-class SVM scoring to improve operational visibility, including multi-turn campaigns [9]. Adharsh *et al.* outline a model-agnostic detection framework oriented to LLM-based security assistants [10]. Dzhaliuk *et al.* compare classical machine learning, fine-tuned encoders, specialized injection detectors, and LLM-as-classifier setups, showing that effectiveness depends strongly on detector class and deployment cost [11].

### 5.3 Application-Layer Hardening and Adaptive Evaluation

Deep *et al.* evaluate multiple defense configurations under adaptive attack pressure and argue that durable boundaries must be enforced in application code rather than entrusted solely to the model under attack [4]. Chen *et al.* study test-time DefensiveTokens for systems that consume external data [12]. Viana proposes SPEF, a layered secure prompt-engineering framework designed for black-box API conditions [13].

### 5.4 Research Gap and Positioning

The literature supports layered defenses, application-controlled enforcement, and careful evaluation. Gaps remain for systems that simultaneously (i) escalate expensive semantic analysis only when classical evidence is uncertain, (ii) constrain hard blocks with corroboration and precision gates, (iii) couple detection with intent-preserving rewrite, and (iv) report frozen held-out metrics with named corpora and ablations.

This work occupies that space as an end-to-end gateway research system. It does not claim to be the first hybrid detector; it claims a coherent, measurable design that integrates detection policy with mitigation, documented against a fixed test contract.

---

## 6. Research Methodology

### 6.1 Research Design

The study follows a **design-and-evaluation** methodology:

1. Specify a threat model and design objectives.
2. Implement a layered gateway as the artifact under study.
3. Assemble named corpora into labeled train, validation, and test splits.
4. Measure detection performance on a frozen held-out test set.
5. Ablate major components on the same test set to isolate contribution and trade-offs.

The unit of analysis is a labeled prompt. The primary outcomes are classification metrics and latency. Internal validity is strengthened by freezing the test partition and restricting retrieval memory to training data. External validity is bounded by the corpora and attack categories present in that test set.

### 6.2 Threat Model

#### 6.2.1 Defended asset

An LLM-backed application that accepts untrusted text before model execution.

#### 6.2.2 Adversary capabilities

The adversary may submit or inject text that attempts to:

- override system instructions through direct commands, role reassignment, or jailbreak personas;
- extract system prompts, hidden policies, or sensitive application data;
- coerce tool use or hijack delimiters and context boundaries;
- conceal payloads through character substitution, zero-width characters, or encodings;
- distribute adversarial intent across narrative framing or multi-turn context;
- place indirect instructions in content later consumed by RAG or agent pipelines [3], [5], [6].

#### 6.2.3 Defender assumptions

The defender controls an application-layer gateway that can inspect prompts before they reach the model. This assumption aligns with evidence that model-self-protection is unreliable under adaptive pressure [4].

#### 6.2.4 Formal task

Given untrusted text \(x\), compute an action
\[
a \in \{\mathrm{ALLOW},\mathrm{FLAG},\mathrm{REVIEW},\mathrm{BLOCK}\}.
\]
When \(a=\mathrm{BLOCK}\), produce a mitigated prompt \(x'\) that retains legitimate intent while removing adversarial wrappers.

### 6.3 Design Objectives

1. High recall across attack categories present in evaluation.
2. Controlled false-positive rate on benign text.
3. Interactive latency on the common decision path.
4. No test leakage into retrieval memory.
5. Mitigation that rewrites blocked prompts rather than discarding recoverable goals.

### 6.4 System Architecture

The final implemented pipeline is summarized below.

| Stage | Module | Role |
|---|---|---|
| 0 | Text normalizer | Canonicalizes leetspeak, zero-width characters, Base64, and URL encodings |
| 1 | Lexical prefilter | Rule families and statistical cues (entropy; special-character density) |
| 2 | Classical detectors | TF–IDF (15,000 features; word \(n\)-grams 1–3) with logistic regression, random forest, XGBoost, and SVM |
| 3 | Ensemble fusion | Weighted probability fusion, ambiguity detection, precision-oriented block gate |
| 2b | Semantic module | Gated DeBERTa classifier (`protectai/deberta-v3-base-prompt-injection-v2`) |
| R | Attack retrieval | TF–IDF cosine similarity against a train-only attack bank |
| 4 | Ambiguity judge | Resolves uncertain cases; hard blocks require corroboration |
| 5 | Intent-preserving rewrite | Extracts residual legitimate intent and emits one safe request |

#### 6.4.1 Classical ensemble

Classifier probabilities are fused with weights \(w_{\mathrm{logistic}}=1.3\), \(w_{\mathrm{SVM}}=1.3\), \(w_{\mathrm{XGBoost}}=0.4\), and \(w_{\mathrm{RF}}=0.3\). The decision threshold is 0.52. Low confidence or low agreement (below 0.45) marks a case as ambiguous. Blocking further requires risk and agreement floors of 0.70, unless strong risk (≥ 0.82) is observed.

#### 6.4.2 Gated semantic module

The DeBERTa module runs when ensemble confidence is below 0.40 or the instance is ambiguous. Semantic evidence is merged under gating. Final hard blocking remains subject to precision and corroboration constraints so that semantic scores improve difficult cases without freely denying benign traffic.

#### 6.4.3 Train-only retrieval

An attack bank is built from training malicious examples. Similarity thresholds are 0.65 for match signaling and 0.85 for near-duplicate force decisions. Held-out test prompts are never inserted into the bank.

#### 6.4.4 Ambiguity judge and mitigation

Layer 4 adjudicates residual ambiguous cases. A judge-originated block requires corroboration from the ensemble, semantic module, or retrieval. Attack-type labels are explanatory metadata and do not independently force a block. Layer 5 removes adversarial wrappers and synthesizes one clarified request that preserves legitimate user intent.

#### 6.4.5 Control flow

Normalized input proceeds through Layers 1–3, retrieval, gated Layer 2b, optional Layer 4, type annotation, precision gating, and final action selection. Blocked prompts are rewritten by Layer 5. Decisions are logged for audit.

### 6.5 Datasets and Materials

#### 6.5.1 Named raw corpora

All corpora used or retained in the project are named explicitly. Files under `data/raw/` include:

| Dataset | Filename |
|---|---|
| Jayavibhav Prompt Injection | `jayavibhav_prompt_injection.jsonl` |
| Moltbook Extended | `moltbook_extended.jsonl` |
| CyberEC Prompt Injection Dataset 2 | `cyberec_prompt-injection-dataset2.jsonl` |
| S-Labs Prompt Injection | `s-labs_prompt-injection.jsonl` |
| Neuralchemy Threat Matrix | `neuralchemy_threat_matrix_all.jsonl` |
| PromptShield | `promptshield_all.jsonl` |

#### 6.5.2 Final labeled splits

Processed records in `data/processed/{train,val,test}.jsonl` contain `text`, `label`, `attack_category`, and `source`.

**Training set (278,843 examples)**

| Source field | Count |
|---|---:|
| `jayavibhav_prompt_injection` | 248,553 |
| `s_labs_prompt_injection` | 15,130 |
| `cyberec_prompt_injection_dataset2` | 9,134 |
| `moltbook_extended` | 6,015 |
| Curated review (`review_queue`, `inbox_review`, `inbox_manual`) | 11 |
| **Total** | **278,843** |
| Malicious / Benign | 141,020 / 137,823 |

**Validation set (40,402 examples):** `jayavibhav` 39,237; `moltbook` 1,165.

**Held-out test set (40,402 examples):** `jayavibhav` 39,195; `moltbook` 1,207; malicious 20,622; benign 19,780.

Group-aware splitting with random seed 42 keeps related prompts within the same partition. Validation and test sets remain frozen for reporting. Neuralchemy Threat Matrix and PromptShield are retained as named raw corpora in the project materials; they are not counted among the `source` labels of the frozen validation and test splits reported above.

### 6.6 Evaluation Protocol

#### 6.6.1 Primary evaluation

Held-out evaluation uses `scripts/Check_Accuracy.py` on `data/processed/test.jsonl`. Reported metrics are:

- accuracy, precision, recall, F1-score;
- AUC-ROC;
- false-positive rate, false-negative rate, specificity;
- confusion counts;
- mean and 95th-percentile latency;
- decision-source distribution;
- per-attack-category detection rate on the malicious subset.

#### 6.6.2 Ablation configurations

On the same test set:

| Configuration | Meaning |
|---|---|
| Full pipeline | All stages enabled |
| Classical only | Layers 1–3 only |
| Without Layer 2b | Semantic module removed |
| Without retrieval | Attack-bank retrieval removed |
| Without Layer 4 | Ambiguity judge removed |

#### 6.6.3 Implementation settings for reported runs

Reported tables use the transformer backend for Layer 2b and the heuristic ambiguity judge for Layer 4. Optional live LLM judging is supported in configuration but is **not** the basis of the primary held-out tables. Configuration and orchestration live in `configs/config.yaml` and `src/pipeline/pipeline.py`.

#### 6.6.4 What is not claimed

This methodology does **not** include:

- head-to-head numerical benchmarking against third-party detectors on the same test file;
- quantitative scoring of rewrite fluency, fidelity, or user preference for Layer 5;
- adaptive multi-round attack success rate against a live target model.

Those are recommended extensions, not hidden results.

---

## 7. Results and Analysis

### 7.1 Overall Held-Out Performance (RQ1)

**Table 1.** Detection performance on the frozen held-out test set (\(N = 40{,}402\)).

| Metric | Value |
|---|---:|
| Accuracy | 0.9583 |
| Precision | 0.9706 |
| Recall | 0.9469 |
| F1-score | 0.9586 |
| AUC-ROC | 0.9665 |
| False-positive rate | 0.0299 |
| False-negative rate | 0.0531 |
| Specificity | 0.9701 |
| Mean latency (ms) | 10.68 |
| 95th-percentile latency (ms) | 15.72 |

**Confusion matrix:** TP = 19,528; TN = 19,188; FP = 592; FN = 1,094.

**Analysis.** The complete pipeline balances high precision (0.9706) with strong recall (0.9469). The false-positive rate of 2.99% indicates that roughly three in one hundred benign prompts are incorrectly treated as attacks under this operating point. Mean latency of 10.68 ms is consistent with interactive gateway use for the evaluated configuration.

### 7.2 Decision-Source Distribution (RQ3)

**Table 2.** Final decision sources on held-out traffic.

| Decision source | Count | Proportion |
|---|---:|---:|
| Layer-3 ensemble | 39,439 | 97.6% |
| Layer-4 judge | 921 | 2.3% |
| Retrieval | 42 | 0.1% |

**Analysis.** Nearly all decisions are resolved by the classical ensemble. Escalation paths are selective rather than dominant. Retrieval issues few final decisions at the chosen near-duplicate threshold, which explains why removing retrieval leaves headline metrics essentially unchanged in the ablation below.

### 7.3 Detection by Attack Category (RQ4)

**Table 3.** Detection rate by attack category (malicious subset only).

| Attack category | Support | Detected | Detection rate |
|---|---:|---:|---:|
| System extraction | 503 | 501 | 0.9960 |
| Data extraction | 6,635 | 6,540 | 0.9857 |
| Direct injection | 4,292 | 4,223 | 0.9839 |
| Tool injection | 289 | 275 | 0.9516 |
| Obfuscation | 17 | 16 | 0.9412 |
| Context poisoning | 440 | 409 | 0.9295 |
| Multi-turn | 1,020 | 944 | 0.9255 |
| Jailbreak | 1,468 | 1,330 | 0.9060 |
| Unknown | 5,958 | 5,290 | 0.8879 |

**Analysis.** Extraction and direct-injection categories are detected most reliably. Jailbreak and unknown-tagged attacks are comparatively harder. Obfuscation shows a high point estimate (0.9412), but support is only 17 examples; that rate must be interpreted cautiously. Unknown is both large in support and weakest in detection rate, making it a priority for future data curation and error analysis.

### 7.4 Ablation Study (RQ2)

**Table 4.** Component ablation on the same held-out test set.

| Configuration | Acc. | Prec. | Rec. | F1 | AUC | FPR | Latency (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|
| Full pipeline | 0.9583 | 0.9706 | 0.9469 | **0.9586** | 0.9665 | 0.0299 | 11.17 |
| Classical only (L1–L3) | 0.9307 | **0.9918** | 0.8714 | 0.9277 | **0.9932** | **0.0075** | 5.85 |
| Without Layer 2b | 0.9204 | 0.9930 | 0.8500 | 0.9160 | 0.9930 | 0.0063 | 6.54 |
| Without retrieval | 0.9583 | 0.9706 | 0.9469 | 0.9586 | 0.9666 | 0.0299 | 12.32 |
| Without Layer 4 | 0.9576 | 0.9794 | 0.9366 | 0.9575 | 0.9686 | 0.0205 | 15.33 |

**Analysis.**

1. **Classical only** is the high-precision, low-FPR, low-latency operating point (precision 0.9918; FPR 0.0075; 5.85 ms), but recall falls to 0.8714.
2. **Full hybrid** raises recall from 0.8714 to 0.9469 and F1 from 0.9277 to 0.9586, accepting a higher FPR of 0.0299.
3. **Removing Layer 2b** reduces recall to 0.8500 and F1 to 0.9160, indicating that the gated semantic module contributes materially on residual hard cases under the evaluated configuration.
4. **Removing retrieval** does not change headline metrics at current thresholds, consistent with Table 2.
5. **Removing Layer 4** slightly reduces recall (0.9366 vs 0.9469) and F1 (0.9575 vs 0.9586), showing a modest but positive contribution from the ambiguity judge.

### 7.5 Synthesis of Findings

Relative to the research questions: the full pipeline delivers strong balanced detection (RQ1); classical and hybrid modes embody a clear precision–recall trade-off (RQ2); decisions are overwhelmingly ensemble-driven with selective escalation (RQ3); and category-level performance is strongest on extraction/direct injection and weakest on unknown-tagged attacks (RQ4).

---

## 8. Discussion

### 8.1 Interpretation

The results support a layered gateway strategy emphasized in recent surveys and empirical studies [1], [2], [4], [7], [11]. Inexpensive classical detectors can carry most traffic with excellent precision. Gated semantic analysis and limited ambiguity adjudication then recover recall on harder residual cases. This division of labor explains both the decision-source distribution and the ablation trade-offs.

Intent-preserving mitigation addresses a usability gap left by detect-and-drop systems. Because rewrite quality is not quantitatively scored in this report, the mitigation contribution should be understood as an implemented design response to the second research problem, not as a measured superiority claim.

### 8.2 Relation to Prior Work

Compared with hybrid detectors [7], [8] and secure prompt-engineering frameworks [13], this system emphasizes measurable held-out detection, train-only retrieval hygiene, corroboration-constrained blocking, and an integrated rewrite stage. Compared with adaptive defense evaluations that stress model-self-protection failures [4], the present design assumes application-layer enforcement—the setting in which the reported metrics apply.

### 8.3 Limitations

The following limitations are stated explicitly and without embellishment:

1. **No external baselines.** Tables compare internal configurations only. Absolute standing versus other published detectors on this exact test file is not established here.
2. **Mitigation not scored.** Layer 5 is implemented; rewrite fidelity, safety of \(x'\), and user acceptance are not measured in the primary tables.
3. **Category imbalance and sparse cells.** Obfuscation has only 17 malicious test examples.
4. **Unknown-tagged weakness.** Detection rate 0.8879 on a large unknown subset indicates remaining coverage gaps.
5. **Retrieval under-utilized at current thresholds.** Few final decisions originate from retrieval.
6. **Judge modality.** Primary results use the heuristic judge, not a live frontier LLM judge.
7. **Scope boundary.** Persistent-memory, tool-execution, and multi-agent threats described in agent attack-surface models [3] are not fully covered by a prompt-only gateway.
8. **Corpus composition.** Training draws on multiple named sources; the frozen test set is dominated by Jayavibhav with a Moltbook minority. Generalization beyond these sources requires further study.

### 8.4 Validity Considerations

Internal validity benefits from a frozen test partition and train-only retrieval. Construct validity for “prompt injection detection” depends on label quality and category definitions in the source corpora. Conclusion validity is limited by the absence of statistical significance tests across multiple random splits or seeds in the reported tables. External validity is bounded by dataset mix and the offline classification setting.

### 8.5 Ethical Considerations

This work is defensive. Named corpora and the attack bank exist to support detection research. The artifacts should not be used to develop offensive campaigns against third-party systems. Secrets must remain in local environment configuration and must not be committed to version control.

---

## 9. Conclusion and Recommendations

### 9.1 Conclusion

This research report presented a hybrid lexical–semantic pipeline for prompt-injection detection with intent-preserving mitigation. Using named datasets and a frozen held-out test of 40,402 prompts, the final system achieved an F1-score of 0.9586, precision 0.9706, recall 0.9469, and false-positive rate 0.0299, with mean latency 10.68 ms. Ablations demonstrate that classical layers provide high-precision efficiency, while the full hybrid configuration recovers recall. Decision accounting shows that the ensemble resolves most traffic, with selective escalation to judgment and rare retrieval finals. The work contributes a coherent, reproducible gateway design and an honest account of what has and has not been measured.

### 9.2 Recommendations

**For deployment.**

1. Choose the operating mode deliberately: classical-only when false positives are most costly; full hybrid when missed attacks are most costly.
2. Monitor false positives on benign creative and code prompts after deployment.
3. Keep retrieval memory train-curated and free of production holdout leakage.

**For future research.**

1. Add **external baselines** on the same frozen test set (for example, a strong specialized transformer detector and a classical-only published comparator), without altering test labels.
2. Evaluate **Layer 5 quantitatively** (intent fidelity, residual attack success after rewrite, and human preference).
3. Expand **obfuscation and multi-turn** evaluation support.
4. Perform **error analysis** on unknown and jailbreak misses to guide data and rule enrichment.
5. Study calibrated **live LLM judging** under the existing corroboration constraints.
6. Strengthen **retrieval** through higher-quality bank entries and threshold retuning.
7. Extend defenses toward **agent-layer** threats beyond the prompt gateway [3].

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

[14] S. Arefin, “A Hybrid Lexical–Semantic Pipeline for Prompt-Injection Detection with Intent-Preserving Mitigation” [Computer software]. https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling

---

## 11. Appendices

### Appendix A — Software Reproduction

```bash
python -m venv .venv
# Windows: .\.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python run_api.py

cd web && npm install && npm start
cd admin && npm install && npm start
```

Helpers: `Start.bat`, `StartAdmin.bat`.

```bash
python scripts/Check_Accuracy.py --mode heldout
python scripts/Check_Accuracy.py --mode ablation
```

### Appendix B — Principal Repository Paths

| Path | Description |
|---|---|
| `configs/config.yaml` | Pipeline configuration |
| `src/pipeline/pipeline.py` | End-to-end orchestration |
| `data/raw/` | Named source corpora |
| `data/processed/` | Train / validation / test splits |
| `data/attack_bank.json` | Train-only retrieval memory |
| `author/` | License, notice, authors, citation |
| `docs/ALWAYS_ON_API.md` | Deployment notes |

### Appendix C — BibTeX

```bibtex
@software{arefin_prompt_injection_defense,
  author = {Arefin, Shams-ul},
  title  = {A Hybrid Lexical--Semantic Pipeline for Prompt-Injection Detection with Intent-Preserving Mitigation},
  url    = {https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling},
  year   = {2026}
}
```

### Appendix D — Integrity Statement

All numerical results in Section 7 are taken from the project’s held-out and ablation evaluation artifacts for the frozen test set of 40,402 prompts. This report does not invent external baseline scores, rewrite-quality metrics, or attack-success rates that were not measured. Where a capability is implemented but not quantified, that boundary is stated in Sections 4.5, 6.6.4, and 8.3.
