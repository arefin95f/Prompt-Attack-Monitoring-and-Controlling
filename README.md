# Three Linear SVMs for Prompt-Injection Detection, with Intent-Preserving Mitigation

## Title Page

**Title:** Three Linear SVMs for Prompt-Injection Detection, with Intent-Preserving Mitigation

**Author:** Shams-ul Arefin  
**GitHub:** [@arefin95f](https://github.com/arefin95f)  
**Project repository:** https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling  
**Citation metadata:** [`author/CITATION.cff`](author/CITATION.cff)

**Document type:** Research report (IEEE citation style)  
**Formatting note for Word/PDF export:** Times New Roman, 12 pt; 1.5 or double line spacing; numbered pages; retain the numbered headings below.

---

## Abstract

Large Language Models treat natural language as both data and control. Prompt injection uses that fact to override instructions, extract hidden context, or push unsafe tool use. This project detects those prompts at an application gateway and, when a prompt is blocked, offers one safer wording of the recoverable request.

The live detector is a weighted blend of three linear support-vector machines. One reads word features after English stopwords are removed. One keeps those short words, because words such as “not”, “do”, and “you” are often the attack cue. One reads character chunks, so misspelled or obfuscated wording still matches. The block or allow call is that blend at threshold 0.48. A known team-bank example can still force a block. The semantic model, attack-bank search, precision gate, and ambiguity judge do not change the call.

Training uses 278,843 labeled examples. Evaluation uses a frozen held-out test set of 40,402 prompts. On that set the live blend reaches accuracy 0.9800, precision 0.9774, recall 0.9836, F1-score 0.9805, AUC-ROC 0.9965, and false-positive rate 0.0237, at 4.78 ms mean latency. Every one of the 40,402 decisions came from the blend. Rewrite quality was not scored. No figure in this report is taken from a different decision rule.

**Index Terms**—Prompt injection, jailbreak detection, LLM security, linear SVM, TF–IDF, character n-grams, intent-preserving mitigation.

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

This research studies **application-layer detection and mitigation of prompt-injection attacks** against Large Language Model systems. The implemented gateway classifies a prompt with three linear SVMs and, if the blend blocks it, rewrites the recoverable request into one safer prompt. Prompt injection is a primary risk for LLM applications [1]–[3], and labeled corpora exist for a systematic measurement [1], [2], [11].

### 1.2 Research Problem

**Problem statement.** An LLM application cannot reliably separate trusted instructions from untrusted user or retrieved text. An adversary can therefore override instructions, leak secrets, jailbreak the model, or invoke unsafe tools [4]–[6].

**Why the problem matters.**

- A successful injection can expose a system prompt, private data, or a privileged action [4], [5].
- Ordinary input validation is a poor match for a language interface [5].
- Many defenses either block harmless technical text or refuse the whole request and throw away a legitimate goal wrapped in an attack [1], [7], [8].
- A gateway has to be accurate enough to trust and fast enough to sit in front of a chat [7], [11].

### 1.3 Research Objectives

**Main objective.**  
To design, implement, and measure a gateway that detects prompt injection with a three-SVM blend and mitigates a blocked prompt by offering one safer request.

**Specific objectives.**

1. To train three linear SVMs on complementary text views and fuse them with fixed weights.
2. To keep later stages off the decision path when they lower the held-out score.
3. To attach an intent-preserving rewrite after a block, without treating that rewrite as a measured quality result.
4. To score the live decision on a frozen held-out test set.

### 1.4 Scope and Boundaries

This report measures **offline detection** on labeled prompt text and describes the rewrite module. It does not report adaptive attack success rate, human rewrite ratings, or a leaderboard comparison against other detectors on this file. Those experiments were not run.

### 1.5 Organization of the Report

Section 2 reviews related work. Section 3 describes the live system, data, and metrics. Section 4 reports the held-out result of that system. Section 5 discusses what the result does and does not support. Section 6 concludes.

---

## 2. Literature Review

### 2.1 Taxonomies, Surveys, and Threat Models

Duarte *et al.* review prompt-injection attacks, taxonomies, evaluation methods, and defenses across direct, multi-turn, structured, and tool-assisted threats [1]. Correia *et al.* survey defenses against injection and jailbreaking and extend the NIST adversarial-learning taxonomy [2]. Chu argues that controls do not transfer across architectural layers of an agent system [3]. Arshad develops a STRIDE-oriented threat model for LLM and retrieval settings [5]. Sarvakar synthesizes attack techniques and secure-system principles [6].

### 2.2 Detection Frameworks

Prakash *et al.* combine heuristic prefiltering, embeddings, and behavioral cues [7]. Hadiprakoso describes an adaptive multi-layer detector [8]. Alshammari and Alsaleh pair gateway telemetry with one-class SVM scoring [9]. Dzhaliuk *et al.* compare classical models, encoders, specialized injection detectors, and LLM-as-classifier setups, and stress the accuracy–cost trade-off [11].

### 2.3 Application-Layer Hardening

Deep *et al.* conclude that a security boundary should be enforced in application code, not left to the model under attack [4]. Chen *et al.* study test-time defensive tokens for systems that read external data [12]. Viana proposes a layered prompt-engineering framework for black-box APIs [13].

### 2.4 Research Gap

Layered defenses are well motivated [1], [2], [7], [8], and application-side enforcement is preferable to model-only self-protection [4]. Two practical gaps remain. Many systems stop at block or allow and do not offer a safer request [1], [8]. Many also add semantic or heuristic stages without showing whether those stages help or hurt the same frozen test set [11].

This project answers those gaps with a named corpus, a frozen test file, a three-SVM blend as the only decision, and a rewrite after a block. It does not claim to close agent-memory or multi-agent threats [3].

---

## 3. Research Methodology

### 3.1 Research Design

The study is an experimental systems design:

1. Implement the gateway.
2. Freeze named train, validation, and test splits.
3. Train the three SVMs and keep a train-only attack bank for explanation, not for the decision.
4. Score the live blend on the frozen test set.
5. Report metrics, the confusion matrix, who decided, and detection rate by attack type.

Detection numbers are quantitative. **Rewrite quality was not scored** and is not presented as a measured result.

### 3.2 System Under Study

The live path is the blend. Other modules still exist in the repository. They do not decide.

| Stage | Module | Role in the live system |
|---|---|---|
| 0 | Text normalizer | Canonicalizes leetspeak, zero-width characters, Base64, and URL encodings before scoring |
| 1 | Lexical prefilter | Rule and statistical cues. Does not set the final block or allow |
| 2 | Three linear SVMs | Stopword TF–IDF, no-stopword TF–IDF, and character n-grams |
| 3 | Blend | Weighted average of the three risks. This is the decision |
| 2b | Semantic module | Off the decision path |
| R | Attack retrieval | Search still exists. It does not force a block |
| 4 | Ambiguity judge | Off the decision path |
| 5 | Intent-preserving rewrite | After a block, emits one safer natural-language request |

**Weights:** stopword SVM 0.1365, no-stopword SVM 0.3859, character SVM 0.4776.  
**Threshold:** 0.48. A score above 0.48 is malicious.  
**Override:** an exact team-bank hit still forces BLOCK. On the held-out file below, that override did not fire.  
**Configuration:** `configs/config.yaml` (`blend_only: true`). Orchestration is in `src/pipeline/pipeline.py`.

Why three views of the same classifier: English stopword lists delete injection cues. Character n-grams still match when the spelling is altered. The weights were chosen on the validation split and then frozen for the test reported here.

### 3.3 Data

Data are assembled from named labeled files under `data/raw/`, not from a survey.

| Dataset | File |
|---|---|
| Jayavibhav Prompt Injection | `jayavibhav_prompt_injection.jsonl` |
| Moltbook Extended | `moltbook_extended.jsonl` |
| CyberEC Prompt Injection Dataset 2 | `cyberec_prompt-injection-dataset2.jsonl` |
| S-Labs Prompt Injection | `s-labs_prompt-injection.jsonl` |
| Neuralchemy Threat Matrix | `neuralchemy_threat_matrix_all.jsonl` |
| PromptShield | `promptshield_all.jsonl` |

Processed rows in `data/processed/{train,val,test}.jsonl` contain `text`, `label`, `attack_category`, and `source`. A small number of team-review rows sit in the training split only.

### 3.4 Sample Size and Split

Related prompts that share a `group_id` stay in the same partition (seed 42). Nominal ratios are 0.7 / 0.15 / 0.15. The validation and test files used here are frozen.

| Split | \(N\) | Malicious | Benign |
|---|---:|---:|---:|
| Train | 278,843 | 141,020 | 137,823 |
| Validation | 40,402 | 20,402 | 20,000 |
| Held-out test | 40,402 | 20,622 | 19,780 |

**Training sources:** `jayavibhav_prompt_injection` 248,553; `s_labs_prompt_injection` 15,130; `cyberec_prompt_injection_dataset2` 9,134; `moltbook_extended` 6,015; curated review sources 11.  
**Held-out test sources:** `jayavibhav` 39,195 and `moltbook` 1,207.  
**Validation sources:** `jayavibhav` 39,237 and `moltbook` 1,165.

Neuralchemy and PromptShield files are present under `data/raw/`. They are not among the counted train, validation, or test `source` fields above.

### 3.5 Metrics

Accuracy, precision, recall, F1-score, AUC-ROC, false-positive rate, false-negative rate, specificity, confusion counts, mean and 95th-percentile latency, decision source, and detection rate by attack category on the malicious subset.

### 3.6 Analysis Procedure

The numbers in Section 4 come from `scripts/Check_Accuracy.py` in held-out mode on `data/processed/test.jsonl` (`N = 40,402`, limit 0). The job wrote `logs/admin_evals/heldout_53998991.json` on 12 September 2026. The script’s mode name is `full`. With `blend_only: true`, that mode still scores the blend. It does not turn the gates back on. McNemar tests and a re-implementation of external detectors on this file were not run.

### 3.7 Ethics

The work is defensive. The report does not give exploit recipes against third-party systems.

---

## 4. Results and Analysis

### 4.1 Held-Out Detection Performance

**Table I.** Live 3-SVM blend on the frozen held-out test set (\(N = 40{,}402\)). Generated 12 September 2026, 14:45 UTC.

| Metric | Value |
|---|---:|
| Accuracy | 0.9800 |
| Precision | 0.9774 |
| Recall | 0.9836 |
| F1-score | 0.9805 |
| AUC-ROC | 0.9965 |
| False-positive rate | 0.0237 |
| False-negative rate | 0.0164 |
| Specificity | 0.9763 |
| Mean latency (ms) | 4.78 |
| 95th-percentile latency (ms) | 5.65 |

**Confusion matrix:** TP = 20,283; TN = 19,312; FP = 468; FN = 339.

About 2.4% of benign prompts were blocked. About 1.6% of attacks were missed. Mean latency of 4.78 ms is compatible with an interactive gateway.

### 4.2 Who Decided

**Table II.** Decision source on the same 40,402 prompts.

| Decision source | Count | Proportion |
|---|---:|---:|
| 3-SVM blend (`layer3_ensemble`) | 40,402 | 100% |

Layer 2b, retrieval, and Layer 4 decided zero rows. That is the definition of this result. A file that shows Layer 4 or retrieval as a decision source is a different system and must not be quoted as this table.

### 4.3 Detection by Attack Category

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

Extraction and direct-injection categories are caught almost completely. The unknown category is the weakest large group. Obfuscation is perfect on this slice but the support is 17 prompts, so that cell should not be generalized.

### 4.4 Comparison with the Previous Project System

**Table IV.** Same test file, two different decisions. These are not an ablation of the live blend. The earlier row is the previous project held-out (`logs/admin_evals/heldout_2c3c6156.json`, 7 September 2026), when Layer 4 decided 921 rows and retrieval decided 42.

| System | Acc. | Prec. | Rec. | F1 | AUC | FPR | ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| Live 3-SVM blend | 0.9800 | 0.9774 | 0.9836 | 0.9805 | 0.9965 | 0.0237 | 4.78 |
| Prior 4-model pipeline | 0.9583 | 0.9706 | 0.9469 | 0.9586 | 0.9665 | 0.0299 | 10.68 |

The live blend is higher on accuracy, recall, F1, and AUC, and lower on false-positive rate and latency, than that earlier pipeline on this file. It is not a claim that the blend beats every published detector on every dataset.

---

## 5. Discussion

### 5.1 What the Result Supports

The literature argues for a cheap common path and for enforcement outside the model under attack [4], [11]. The measured system matches that shape: three linear SVMs, one threshold, no semantic override. The held-out file shows that this common path can be both the accurate path and the fast path.

Published F1 scores from other papers are not compared numerically. Those scores used other datasets and other splits. Copying them beside Table I would not be a valid comparison.

### 5.2 What Was Dropped, and Why

An earlier version of this project fused logistic regression, random forest, XGBoost, and one SVM, and allowed a semantic model, retrieval, and a judge to change the call. On this repository’s own held-out file that pipeline scored F1 0.9586 (Table IV). The live system dropped those classifiers and took those later stages off the decision. The held-out score of the system that remains is Table I.

### 5.3 Limitations

1. Rewrite fluency, intent fidelity, and user acceptance were not scored.
2. Other public detectors were not re-run on this test file.
3. Obfuscation support is 17 prompts.
4. Train contains sources that do not appear in the frozen test mixture. Generalization should be read with that split in mind.
5. Neuralchemy and PromptShield are in `data/raw/` but are not in the counted split sources.
6. Threats that live in agent memory, tool execution, or multi-agent coordination [3] are outside a prompt gateway.
7. A team-bank hit can still force a block. It did not do so on this test file. A deployment with overlapping team examples can differ from Table I by that override alone.

---

## 6. Conclusion and Recommendations

### 6.1 Conclusion

The implemented gateway detects prompt injection with a blend of three linear SVMs and, after a block, offers one safer request. On 40,402 frozen held-out prompts that blend reached accuracy 0.9800, precision 0.9774, recall 0.9836, F1-score 0.9805, AUC-ROC 0.9965, and false-positive rate 0.0237, at 4.78 ms mean latency. All 40,402 decisions were the blend. Rewrite quality remains unmeasured.

### 6.2 Practical Recommendations

1. Deploy the blend as a gateway in front of the LLM. It does not replace logging, access control, or secret handling [4], [5].
2. Do not turn the semantic model, retrieval force-block, precision gate, or judge back on and still quote Table I. Those stages are a different system.
3. Keep any attack bank built from training text only.
4. Treat attack-type labels as explanations, not as an extra block rule.
5. Watch the unknown category in live traffic, and add confirmed mistakes to the training review set.

### 6.3 Future Work

1. Score rewrite quality with an explicit rubric.
2. Re-run strong public detectors on this same test file.
3. Enlarge the obfuscation and multi-turn slices.
4. Measure whether a team-bank override helps or hurts once it actually fires on held-out text.
5. Study agent-layer threats that a prompt gateway cannot see [3].

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

[14] S. Arefin, “Three Linear SVMs for Prompt-Injection Detection, with Intent-Preserving Mitigation” [Computer software]. Available: https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling

---

## 8. Appendices

### Appendix A — Run the System

```bash
python -m venv .venv
# Windows: .\.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python run_api.py
```

The API listens on http://localhost:8000. Health: http://localhost:8000/health. Docs: http://localhost:8000/docs.

```bash
cd web && npm install && npm start
cd admin && npm install && npm start
```

Windows launchers: `Start.bat` and `StartAdmin.bat`.

Held-out scoring of the live decision:

```bash
python scripts/Check_Accuracy.py --mode heldout
```

That command scores whatever `configs/config.yaml` currently decides. With `blend_only: true`, the report is the blend in Table I, even if the script labels the mode `full`.

Train the three SVMs:

```bash
python main.py --step train
```

### Appendix B — Principal Paths

| Path | Description |
|---|---|
| `configs/config.yaml` | Live weights, threshold, and `blend_only` |
| `src/pipeline/pipeline.py` | Decision path |
| `src/layers/layer2_classifiers.py` | The three SVMs |
| `models/detector/` | Saved SVM and vectorizer files |
| `data/processed/` | Frozen train, validation, and test splits |
| `scripts/Check_Accuracy.py` | Held-out evaluation |
| `logs/admin_evals/heldout_53998991.json` | Source of Table I |
| `web/` | Public chat |
| `admin/` | Admin lab and reports |

### Appendix C — BibTeX

```bibtex
@software{arefin_prompt_injection_defense,
  author = {Arefin, Shams-ul},
  title  = {Three Linear SVMs for Prompt-Injection Detection, with Intent-Preserving Mitigation},
  url    = {https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling},
  year   = {2026}
}
```
