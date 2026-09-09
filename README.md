# A Hybrid Lexical–Semantic Pipeline for Prompt-Injection Detection with Intent-Preserving Mitigation

## Title Page

**Title:** A Hybrid Lexical–Semantic Pipeline for Prompt-Injection Detection with Intent-Preserving Mitigation  

**Author:** Shams-ul Arefin  
**GitHub:** [@arefin95f](https://github.com/arefin95f)  
**Project repository:** https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling  
**Citation metadata:** [`author/CITATION.cff`](author/CITATION.cff)  

**Document type:** Research report (IEEE citation style)  
**Formatting note for Word/PDF export:** Times New Roman, 12 pt; 1.5 or double line spacing; numbered pages; retain the numbered headings below.

---

## Abstract

Large Language Models (LLMs) process natural language as both data and control. Prompt injection exploits that property to override system instructions, extract confidential context, manipulate tool use, or bypass safety policies. This research addresses the problem of detecting such attacks at an application gateway and mitigating blocked prompts without discarding recoverable user intent. The study designs and evaluates a hybrid lexical–semantic pipeline that combines text normalization, rule-based prefiltering, TF–IDF classical classifiers fused by a weighted ensemble, a gated DeBERTa semantic module, train-only attack-bank retrieval, an ambiguity-conditioned judge with corroboration constraints, and an intent-preserving rewriter.  

Named public and curated corpora are used. The final training split contains 278,843 labeled examples. Evaluation is performed on a frozen held-out test set of 40,402 prompts. The complete system achieves accuracy 0.9583, precision 0.9706, recall 0.9469, F1-score 0.9586, AUC-ROC 0.9665, and false-positive rate 0.0299, with mean latency 10.68 ms. Ablation analysis shows that classical layers alone are highly precise but lower in recall, while the full hybrid configuration recovers recall under a controlled false-positive budget. The report concludes with practical recommendations for deployment and clearly stated directions for future work. No result in this document is extrapolated beyond the measured experiments.

**Index Terms**—Prompt injection, jailbreak detection, LLM security, hybrid NLP, ensemble learning, DeBERTa, intent-preserving mitigation, ablation study.

---

## Table of Contents

1. [Introduction](#1-introduction)  
2. [Literature Review](#2-literature-review)  
3. [Research Methodology](#3-research-methodology)  
4. [Results and Analysis](#4-results-and-analysis)  
5. [Discussion](#5-discussion)  
6. [Conclusion and Recommendations](#6-conclusion-and-recommendations)  
7. [References](#7-references)  
8. [Appendices](#8-appendices)

---

## 1. Introduction

### 1.1 Research Topic

This research investigates **application-layer detection and mitigation of prompt-injection attacks** against Large Language Model systems. The topic is specific: a hybrid lexical–semantic gateway that both classifies adversarial prompts and rewrites blocked prompts into policy-compliant requests. It is relevant because prompt injection is repeatedly identified as a primary risk for LLM-integrated applications [1]–[3], and sufficient prior literature and labeled corpora exist to support systematic study [1], [2], [11].

### 1.2 Research Problem

**Problem statement.** LLM applications cannot reliably separate trusted system instructions from untrusted user or retrieved text. Adversaries can therefore craft prompts that cause unauthorized behavior, including instruction override, secret leakage, jailbreaking, and unsafe tool invocation [4]–[6].

**Why the problem matters.**  
- Security impact is high: a successful injection can expose system prompts, private data, or privileged actions [4], [5].  
- Traditional input validation is poorly matched to non-deterministic language interfaces [5].  
- Many defenses either over-block benign creative or technical text, or stop at binary refusal and discard legitimate user goals wrapped inside adversarial scaffolding [1], [7], [8].  
- Production systems need defenses that are accurate, auditable, and fast enough for interactive use [7], [11].

### 1.3 Research Objectives

**Main objective.**  
To design, implement, and empirically evaluate a hybrid lexical–semantic pipeline that detects prompt-injection attacks at an application gateway and mitigates blocked prompts through intent-preserving rewriting.

**Specific objectives.**  
1. To construct a multi-layer detection architecture combining normalization, lexical rules, TF–IDF ensemble classification, gated semantic scoring, train-only retrieval, and corroboration-gated judgment.  
2. To integrate an intent-preserving mitigation stage that converts blocked adversarial prompts into a single safe, policy-compliant user request.  
3. To evaluate the complete system on a frozen held-out test set using standard detection metrics (accuracy, precision, recall, F1-score, AUC-ROC, false-positive rate, latency).  
4. To quantify the contribution of major components through controlled ablation experiments on the same held-out set.

### 1.4 Scope and Boundaries

This report evaluates **offline detection quality** on labeled prompt text and documents the final implemented mitigation module. It does not claim adaptive red-team Attack Success Rate results, human-rated rewrite quality scores, or head-to-head numeric superiority over external detectors on a shared public leaderboard, because those experiments were not part of the measured study reported here.

### 1.5 Organization of the Report

Section 2 reviews related literature and states the research gap. Section 3 presents methodology, datasets, sampling, and analysis design. Section 4 reports results. Section 5 discusses findings relative to prior work. Section 6 concludes with recommendations and future research. References and appendices follow.

---

## 2. Literature Review

### 2.1 Taxonomies, Surveys, and Threat Models

Duarte *et al.* provide a systematic review of prompt-injection attacks, covering taxonomies, evaluation methods, defenses, and open problems across direct, multi-turn, structured, and tool-assisted threats [1]. Correia *et al.* survey defenses against injection and jailbreaking and extend NIST adversarial machine-learning taxonomy with additional defense categories [2]. Chu proposes a layered attack-surface model for agentic systems and argues that controls do not transfer across architectural layers or temporal scales [3]. Arshad develops a STRIDE-oriented enterprise threat model for LLM and RAG settings [5]. Sarvakar synthesizes attack theory, techniques, and secure-system principles [6].

### 2.2 Detection Frameworks

Prakash *et al.* propose a hybrid real-time detector combining heuristic prefiltering, semantic embeddings, and behavioral cues [7]. Hadiprakoso describes an adaptive multi-layer framework for detection and mitigation [8]. Alshammari and Alsaleh integrate gateway telemetry with SIEM correlation and one-class SVM scoring for operational monitoring [9]. Adharsh *et al.* outline a model-agnostic framework for LLM-based security assistants [10]. Dzhaliuk *et al.* comparatively evaluate classical machine learning, fine-tuned encoders, specialized injection detectors, and LLM-as-classifier setups, emphasizing accuracy–cost trade-offs [11].

### 2.3 Application-Layer Hardening

Deep *et al.* evaluate multiple defenses under adaptive attack pressure and conclude that security boundaries should be enforced in application code rather than entrusted solely to the model under attack [4]. Chen *et al.* study test-time DefensiveTokens for systems that consume external data [12]. Viana proposes SPEF, a layered secure prompt-engineering framework for black-box API settings [13].

### 2.4 Research Gap

Prior work establishes that layered defenses are necessary [1], [2], [7], [8] and that application-controlled enforcement is preferable to model-only self-protection [4]. Remaining gaps relevant to this study are:

1. **Integrated detect-and-mitigate pipelines** are less commonly evaluated end-to-end than detection-only classifiers; many systems stop at block/allow decisions [1], [8].  
2. **Cost-aware gating**—using classical detectors for the common path and semantic models only under uncertainty—requires transparent empirical reporting of latency and decision-source mix [11].  
3. **Leakage-safe retrieval memory** (train-only attack banks) is not always stated explicitly in applied detector papers.  
4. **Component ablations** on a frozen held-out set are needed to show which layers change precision and recall, rather than reporting a single aggregate score.

This research addresses those gaps by implementing a complete hybrid gateway with intent-preserving rewrite, naming all corpora, evaluating on a frozen held-out test set, and reporting ablations. It does not claim to close every gap in agent-stack security identified by Chu [3].

---

## 3. Research Methodology

### 3.1 Research Design

The study follows an **experimental systems research design**:

1. Design and implement the detection–mitigation pipeline.  
2. Prepare named labeled corpora and freeze validation/test partitions.  
3. Train classical detectors and construct a train-only attack bank.  
4. Evaluate the complete pipeline on held-out test data.  
5. Repeat evaluation under controlled ablations.  
6. Analyze metrics, confusion structure, decision sources, and per-category detection rates.

The design is quantitative for detection performance. Mitigation is implemented in the final system and described structurally; **human or automatic quality scoring of rewritten prompts was not conducted in the reported experiments** and is therefore not presented as a measured result.

### 3.2 System Under Study (Final Implementation)

The final pipeline is organized as follows.

| Stage | Module | Role |
|---|---|---|
| 0 | Text normalizer | Canonicalizes leetspeak, zero-width characters, Base64, and URL encodings |
| 1 | Lexical prefilter | Rule families and statistical cues (entropy, special-character density) |
| 2 | Classical detectors | TF–IDF (15,000 features; word \(n\)-grams 1–3) with logistic regression, random forest, XGBoost, and SVM |
| 3 | Ensemble fusion | Weighted probability fusion, ambiguity detection, precision-oriented block gate |
| 2b | Semantic module | Gated DeBERTa classifier (`protectai/deberta-v3-base-prompt-injection-v2`) |
| R | Attack retrieval | TF–IDF cosine similarity against train-only `data/attack_bank.json` |
| 4 | Ambiguity judge | Resolves uncertain cases; hard blocks require corroboration |
| 5 | Intent-preserving rewrite | Extracts residual legitimate intent and emits one safe natural-language request |

**Ensemble weights:** logistic 1.3, SVM 1.3, XGBoost 0.4, random forest 0.3.  
**Operating threshold:** 0.52.  
**Ambiguity rule:** confidence or agreement below 0.45.  
**Precision gate:** block requires risk and agreement floors of 0.70, unless strong risk ≥ 0.82.  
**Semantic gate:** DeBERTa runs when ensemble confidence is below 0.40 or the case is ambiguous (semantic threshold 0.78).  
**Retrieval:** match threshold 0.65; near-duplicate force threshold 0.85.  
**Judge policy:** block only with corroboration from ensemble, semantic, or retrieval evidence; attack-type labels do not independently force a block.

Configuration and orchestration are provided in `configs/config.yaml` and `src/pipeline/pipeline.py`.

### 3.3 Data Collection Method

Data collection is **secondary labeled-corpus assembly**, not a survey or interview study. Named source files under `data/raw/` are:

| Dataset | File |
|---|---|
| Jayavibhav Prompt Injection | `jayavibhav_prompt_injection.jsonl` |
| Moltbook Extended | `moltbook_extended.jsonl` |
| CyberEC Prompt Injection Dataset 2 | `cyberec_prompt-injection-dataset2.jsonl` |
| S-Labs Prompt Injection | `s-labs_prompt-injection.jsonl` |
| Neuralchemy Threat Matrix | `neuralchemy_threat_matrix_all.jsonl` |
| PromptShield | `promptshield_all.jsonl` |

Processed records in `data/processed/{train,val,test}.jsonl` contain `text`, `label`, `attack_category`, and `source`. Small curated team-review rows (`review_queue`, `inbox_review`, `inbox_manual`) appear in the training split.

### 3.4 Sample Size and Sampling Technique

**Sampling technique.** Group-aware splitting with random seed 42 assigns related prompts (shared `group_id`) to the same partition, then forms train / validation / test splits (nominal ratios 0.7 / 0.15 / 0.15 in configuration). Validation and test partitions used for reporting are frozen.

**Sample sizes in the final processed splits.**

| Split | \(N\) | Malicious | Benign |
|---|---:|---:|---:|
| Train | 278,843 | 141,020 | 137,823 |
| Validation | 40,402 | 20,402 | 20,000 |
| Held-out test | 40,402 | 20,622 | 19,780 |

**Training-source counts (named):**

| Source field | Count |
|---|---:|
| `jayavibhav_prompt_injection` | 248,553 |
| `s_labs_prompt_injection` | 15,130 |
| `cyberec_prompt_injection_dataset2` | 9,134 |
| `moltbook_extended` | 6,015 |
| Curated review sources | 11 |
| **Total train** | **278,843** |

**Held-out test sources:** `jayavibhav` (39,195) and `moltbook` (1,207).  
**Validation sources:** `jayavibhav` (39,237) and `moltbook` (1,165).

Attack-bank retrieval memory is built from **training malicious examples only**. Held-out test prompts are never inserted into retrieval memory.

### 3.5 Variables and Metrics

- **Independent factors (ablations):** full pipeline; classical-only (Layers 1–3); without Layer 2b; without retrieval; without Layer 4.  
- **Dependent measures:** accuracy, precision, recall, F1-score, AUC-ROC, false-positive rate (FPR), false-negative rate (FNR), specificity, confusion counts, mean and 95th-percentile latency, decision-source distribution, per-attack-category detection rate.

### 3.6 Data Analysis Procedure

Analysis is quantitative:

1. Run end-to-end inference on the frozen test set (`scripts/Check_Accuracy.py`, held-out mode).  
2. Compute classification metrics from predicted versus gold labels.  
3. Tabulate confusion matrix and decision sources.  
4. Compute detection rates within each attack category among malicious examples.  
5. Repeat under each ablation configuration on the same test set.  
6. Interpret differences descriptively.  

Formal hypothesis tests (for example, McNemar tests across systems) and external baseline re-implementations on this exact test file were **not** part of the reported analysis and are therefore not included.

### 3.7 Ethical Considerations

The work is defensive. Named datasets and the attack bank are used for detection research and evaluation. The report does not provide offensive exploit recipes against third-party systems.

---

## 4. Results and Analysis

### 4.1 Held-Out Detection Performance

**Table I.** Detection performance on the frozen held-out test set (\(N = 40{,}402\)).

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

**Analysis.** The system balances high precision (0.9706) with high recall (0.9469). The FPR of 0.0299 indicates that approximately 3% of benign prompts are incorrectly treated as attacks under the selected operating point. Mean latency of 10.68 ms is compatible with interactive gateway use for the measured configuration.

### 4.2 Decision-Source Distribution

**Table II.** Sources of final decisions on held-out traffic.

| Decision source | Count | Proportion |
|---|---:|---:|
| Layer-3 ensemble | 39,439 | 97.6% |
| Layer-4 judge | 921 | 2.3% |
| Retrieval | 42 | 0.1% |

**Analysis.** Nearly all decisions are resolved by the classical ensemble. The judge and retrieval paths are reserved for residual cases. This distribution supports the design goal of keeping the common path inexpensive while retaining escalation routes for uncertainty.

### 4.3 Per-Category Detection Rates

**Table III.** Detection rate by attack category (malicious subset only).

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

**Analysis.** Extraction-oriented and direct-injection categories achieve the highest detection rates. Jailbreak and unknown categories are comparatively harder. Obfuscation shows a high rate but very small support (\(n = 17\)); that cell should be interpreted cautiously.

### 4.4 Ablation Results

**Table IV.** Component ablation on the same held-out test set.

| Configuration | Acc. | Prec. | Rec. | F1 | AUC | FPR | Latency (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|
| Full pipeline | 0.9583 | 0.9706 | 0.9469 | 0.9586 | 0.9665 | 0.0299 | 11.17 |
| Classical only (L1–L3) | 0.9307 | 0.9918 | 0.8714 | 0.9277 | 0.9932 | 0.0075 | 5.85 |
| Without Layer 2b | 0.9204 | 0.9930 | 0.8500 | 0.9160 | 0.9930 | 0.0063 | 6.54 |
| Without retrieval | 0.9583 | 0.9706 | 0.9469 | 0.9586 | 0.9666 | 0.0299 | 12.32 |
| Without Layer 4 | 0.9576 | 0.9794 | 0.9366 | 0.9575 | 0.9686 | 0.0205 | 15.33 |

**Analysis.**  
1. Classical-only maximizes precision and minimizes FPR, but recall falls to 0.8714.  
2. The full pipeline raises recall to 0.9469 with FPR 0.0299, producing the best F1-score among the reported configurations (0.9586).  
3. Removing Layer 2b reduces recall to 0.8500, indicating that the gated semantic module contributes to difficult residual cases under this evaluation.  
4. Removing retrieval leaves aggregate scores essentially unchanged at the chosen thresholds, consistent with Table II (only 42 retrieval finals).  
5. Removing Layer 4 slightly reduces recall relative to the full pipeline (0.9366 versus 0.9469).

Suggested charts for the Word/PDF version of this report (data already tabulated): (a) bar chart of F1 and FPR by ablation; (b) bar or pie chart of decision sources; (c) bar chart of per-category detection rates.

---

## 5. Discussion

### 5.1 Comparison with Previous Studies

The findings align with the layered-defense consensus in the literature [1], [2], [7], [8], [11]: inexpensive classical methods handle most traffic, while semantic components help on harder tails. They also support the application-gateway position advanced by Deep *et al.* [4], because enforcement occurs before model execution rather than relying on the attacked model alone.

Direct numeric comparison with published F1-scores from other papers is **not** made here. Those scores were obtained on different datasets, splits, and protocols. Claiming superiority from cross-paper metric copying would be scientifically invalid. Within this study, the meaningful comparison is internal: full pipeline versus ablations on the same frozen test set (Table IV).

### 5.2 Significance of the Findings

1. **Objective 1–2 (system design):** A complete detect-and-mitigate gateway was implemented, including intent-preserving rewrite after blocking.  
2. **Objective 3 (evaluation):** On 40,402 held-out prompts, the system reaches F1-score 0.9586 and FPR 0.0299 at interactive latency.  
3. **Objective 4 (ablation):** Classical layers provide precision; hybrid escalation improves recall. Retrieval is rarely decisive at current thresholds.  
4. **Practical significance:** Operators can choose classical-only when false positives are costlier than misses, or the full pipeline when recall is prioritized under a still-moderate FPR.

### 5.3 Limitations (Stated Without Overclaim)

1. Mitigation quality (fluency, intent fidelity, user acceptance) was **not** scored in the reported experiments.  
2. External detector baselines were **not** re-run on this exact test file.  
3. Obfuscation support in the test slice is very small (\(n = 17\)).  
4. Training includes additional named sources beyond those appearing in the frozen val/test mixture; readers should interpret generalization with that split composition in mind.  
5. Neuralchemy and PromptShield files exist in `data/raw/` as named corpora; they are not listed among the counted train/val/test `source` fields in Section 3.4.  
6. Agent-layer threats spanning persistent memory, tool execution, and multi-agent coordination [3] exceed the scope of a prompt gateway alone.  
7. Primary Layer-4 results use the heuristic judge path configured for the reported runs.

These limitations define honest boundaries; they are not filled with estimated or assumed numbers.

---

## 6. Conclusion and Recommendations

### 6.1 Conclusion

This research defined a clear problem—prompt-injection detection and mitigation at an LLM application gateway—and addressed it with a hybrid lexical–semantic pipeline. Using named datasets and a frozen held-out test of 40,402 prompts, the final system achieved accuracy 0.9583, precision 0.9706, recall 0.9469, F1-score 0.9586, AUC-ROC 0.9665, and FPR 0.0299, with mean latency 10.68 ms. Ablations show that classical detection is precise and fast, while the full hybrid configuration improves recall. Intent-preserving rewriting is part of the final implemented system; its qualitative effectiveness remains an open measurement task.

### 6.2 Practical Recommendations

1. **Deploy as an application gateway** in front of the LLM, not as a substitute for logging, access control, and secret hygiene [4], [5].  
2. **Select the operating mode by risk tolerance:** classical-only for minimal FPR; full pipeline when higher recall is required.  
3. **Keep retrieval memory train-only** and audit decision logs for false-positive review.  
4. **Treat attack-type labels as explanations**, not independent block triggers.  
5. **Monitor weak categories** (jailbreak, unknown) during operations and feed confirmed cases into curated training review.

### 6.3 Recommendations for Future Research

1. Evaluate rewrite quality with explicit human or automatic rubrics (intent fidelity, safety, fluency).  
2. Re-implement strong public detectors on the **same** frozen test set for fair external comparison.  
3. Expand obfuscation and multi-turn evaluation support.  
4. Improve attack-bank coverage and threshold calibration so retrieval contributes more than near-duplicate cases.  
5. Study calibrated live LLM judging under the existing corroboration constraints.  
6. Extend defenses toward agent-stack layers identified in layered attack-surface research [3].

---

## 7. References

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

[14] S. Arefin, “A Hybrid Lexical–Semantic Pipeline for Prompt-Injection Detection with Intent-Preserving Mitigation” [Computer software]. Available: https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling

---

## 8. Appendices

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

Windows helpers: `Start.bat`, `StartAdmin.bat`.

```bash
python scripts/Check_Accuracy.py --mode heldout
python scripts/Check_Accuracy.py --mode ablation
```

### Appendix B — Principal Repository Paths

| Path | Description |
|---|---|
| `configs/config.yaml` | Final pipeline configuration |
| `src/pipeline/pipeline.py` | End-to-end orchestration |
| `data/raw/` | Named source corpora |
| `data/processed/` | Train / validation / test splits |
| `data/attack_bank.json` | Train-only retrieval memory |
| `author/` | License, notice, authors, citation |
| `scripts/Check_Accuracy.py` | Held-out and ablation evaluation |

### Appendix C — BibTeX

```bibtex
@software{arefin_prompt_injection_defense,
  author = {Arefin, Shams-ul},
  title  = {A Hybrid Lexical--Semantic Pipeline for Prompt-Injection Detection with Intent-Preserving Mitigation},
  url    = {https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling},
  year   = {2026}
}
```
