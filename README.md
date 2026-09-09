# A Hybrid Lexical–Semantic Pipeline for Prompt-Injection Detection with Intent-Preserving Mitigation

**Author:** Shams-ul Arefin  
**Email / GitHub:** [@arefin95f](https://github.com/arefin95f)  
**Repository:** https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling  
**Citation metadata:** [`author/CITATION.cff`](author/CITATION.cff)

---

## Abstract

Large Language Models (LLMs) cannot reliably separate trusted instructions from untrusted natural-language content. Prompt injection exploits that ambiguity to override system policies, extract confidential context, invoke tools, or jailbreak safety constraints. This paper proposes a hybrid lexical–semantic detection and mitigation pipeline that places an application-layer gateway in front of the model. The pipeline combines text normalization, rule-based prefiltering, TF–IDF classical classifiers fused by a weighted ensemble, a gated DeBERTa semantic module, train-only attack-bank retrieval, an ambiguity-conditioned judge with corroboration constraints, and an intent-preserving rewriter that converts blocked adversarial prompts into a single policy-compliant user request. The training corpus integrates named public and curated sources totaling 278,843 labeled examples; evaluation uses a frozen held-out test set of 40,402 prompts. The complete system attains accuracy 0.9583, precision 0.9706, recall 0.9469, F1-score 0.9586, AUC-ROC 0.9665, and false-positive rate 0.0299, with mean latency 10.68 ms. Ablation experiments quantify the contribution of each major component and characterize the precision–recall operating trade-off between classical and hybrid configurations.

### Index Terms

Prompt injection, jailbreak detection, large language model security, hybrid natural language processing, ensemble classification, DeBERTa, intent-preserving mitigation, ablation study.

---

## I. Introduction

The rapid deployment of LLMs in conversational agents, retrieval-augmented generation (RAG) systems, and tool-using agents has expanded the software attack surface beyond traditional input validation. Because model behavior is steered by text, adversarial prompts can reprogram the intended task—an attack class now widely recognized as a primary risk for LLM applications [1]–[3]. Documented incidents show that system prompts and operational constraints can be extracted through carefully crafted injections [4].

Prior defenses span signature filters, classical machine learning, fine-tuned transformers, application-level prompt engineering, and model-side self-protection. Surveys and comparative studies show that no single detector dominates across attack families, cost budgets, and deployment constraints [1], [2], [11]. Simultaneously, many pipelines stop at binary blocking: legitimate user goals wrapped in adversarial scaffolding are discarded rather than recovered.

This work addresses both issues through a unified gateway architecture. The system escalates computational cost only when classical evidence is uncertain, enforces precision-oriented blocking rules, and—when a prompt is blocked—extracts residual benign intent and rewrites a safe continuation. The contributions are as follows:

1. A complete hybrid detection architecture that integrates lexical rules, TF–IDF ensembles, gated semantic scoring, retrieval memory, and corroboration-gated judgment.
2. An intent-preserving mitigation stage that transforms blocked injections into clarified, policy-compliant requests.
3. A reproducible evaluation protocol on a frozen held-out test set with named training sources, train-only retrieval construction, and systematic ablations.
4. Empirical evidence that the hybrid configuration improves recall over classical-only detection while retaining a controlled false-positive rate suitable for interactive use.

---

## II. Related Work

### A. Taxonomies, Surveys, and Threat Models

Duarte *et al.* present a systematic review of prompt-injection attacks, covering taxonomies, evaluation practices, defenses, and open challenges across direct, multi-turn, structured, and tool-assisted threats [1]. Correia *et al.* survey mitigation strategies against injection and jailbreaking and extend NIST adversarial machine-learning taxonomy with additional defense categories [2]. Chu introduces the Layered Attack Surface Model for agentic systems and argues that controls are not transferable across architectural layers or temporal horizons [3]. Arshad formulates an enterprise-oriented STRIDE threat model for LLM and RAG deployments [5]. Sarvakar consolidates theoretical foundations, attack techniques, and secure-system design guidance [6].

### B. Detection Systems

Prakash *et al.* propose a hybrid real-time detector combining heuristic prefiltering, semantic embeddings, and behavioral cues [7]. Hadiprakoso describes an adaptive multi-layer framework for detection and mitigation [8]. Alshammari and Alsaleh couple gateway telemetry with SIEM correlation and one-class SVM anomaly scoring for operational visibility [9]. Adharsh *et al.* outline a model-agnostic detection framework for LLM-based security assistants [10]. Dzhaliuk *et al.* compare classical ML, fine-tuned encoders, specialized injection detectors, and LLM-as-classifier setups on a large labeled corpus, emphasizing accuracy–cost trade-offs [11].

### C. Hardening Beyond Classification

Deep *et al.* evaluate multiple defenses under adaptive attack pressure and conclude that security boundaries must be enforced in application code rather than entrusted solely to the model under attack [4]. Chen *et al.* study test-time DefensiveTokens for systems that consume external data [12]. Viana proposes SPEF, a layered secure prompt-engineering framework operating under black-box API constraints [13].

### D. Relation to This Work

Building on the layered-defense consensus in [1], [2], [7], [8], this paper presents an end-to-end gateway that couples hybrid detection with intent-preserving rewrite. Relative to prompt-engineering-only frameworks [13] and token-only test-time defenses [12], the emphasis here is measurable offline detection quality, low interactive latency, and mitigation that retains legitimate user intent after a block decision.

---

## III. Threat Model and Design Objectives

### A. Problem Statement

Let \(x\) denote untrusted text entering an LLM application (user message or retrieved content). The defender computes an action
\[
a \in \{\mathrm{ALLOW},\mathrm{FLAG},\mathrm{REVIEW},\mathrm{BLOCK}\}
\]
and, when \(a=\mathrm{BLOCK}\), produces a mitigated prompt \(x'\) that preserves legitimate intent while removing adversarial instruction wrappers.

### B. Adversary Model

The adversary may submit or inject text that attempts to:

- override system instructions through direct commands, role reassignment, or jailbreak personas;
- extract system prompts, hidden policies, or sensitive application data;
- coerce tool use or delimiter/context hijacking;
- conceal payloads via obfuscation (character substitution, zero-width characters, encodings);
- distribute intent across narrative framing or multi-turn context poisoning;
- place indirect instructions in content later consumed by RAG or agent pipelines [3], [5], [6].

The defender is assumed to control an application-layer gateway that can inspect prompts before model execution, consistent with evidence that model-self-protection is insufficient under adaptive pressure [4].

### C. Design Objectives

The system is designed to (i) detect diverse injection families with high recall, (ii) maintain a low false-positive rate on benign creative and technical text, (iii) keep median interactive latency in the tens of milliseconds for the common path, (iv) prevent evaluation leakage by constructing retrieval memory from training data only, and (v) mitigate blocked prompts by rewriting rather than discarding recoverable user goals.

---

## IV. Proposed System

### A. Architecture Overview

Fig. 1 (conceptual) summarizes the final pipeline implemented in this repository.

| Stage | Module | Function |
|---|---|---|
| Normalization | Text normalizer | Canonicalizes leetspeak, zero-width characters, Base64, and URL encodings |
| Layer 1 | Lexical prefilter | High-signal rule families and statistical cues (entropy, special-character density) |
| Layer 2 | Classical detectors | TF–IDF features (15,000 dimensions; word \(n\)-grams 1–3) with logistic regression, random forest, XGBoost, and SVM |
| Layer 3 | Ensemble fusion | Weighted probability fusion, ambiguity detection, and precision-oriented block gate |
| Layer 2b | Semantic module | Gated DeBERTa prompt-injection classifier (`protectai/deberta-v3-base-prompt-injection-v2`) |
| Retrieval | Attack bank | TF–IDF cosine similarity against a memory built exclusively from training attacks |
| Layer 4 | Ambiguity judge | Resolves uncertain cases; hard blocks require corroboration from ensemble, semantic, or retrieval evidence |
| Layer 5 | Intent-preserving rewrite | Extracts residual legitimate intent and emits one safe natural-language request |

### B. Classical Ensemble

Classifier probabilities are fused with weights \(w_{\mathrm{logistic}}=1.3\), \(w_{\mathrm{SVM}}=1.3\), \(w_{\mathrm{XGBoost}}=0.4\), and \(w_{\mathrm{RF}}=0.3\). The operating threshold is 0.52. Cases with low confidence or low inter-model agreement (below 0.45) are marked ambiguous. Blocking further requires risk and agreement floors (0.70) unless strong risk (≥ 0.82) is observed, reducing brittle false blocks on weakly evidenced inputs.

### C. Gated Semantic Scoring

The DeBERTa module executes when ensemble confidence falls below 0.40 or the instance is ambiguous. Semantic scores are merged into the decision pathway under gating; final hard blocking remains subject to ensemble precision constraints and corroboration policy so that semantic evidence improves difficult cases without dominating benign traffic.

### D. Train-Only Retrieval

An attack bank is constructed from training malicious examples and queried by cosine similarity (match threshold 0.65; near-duplicate force threshold 0.85). Held-out test prompts are never inserted into retrieval memory.

### E. Ambiguity Judge and Mitigation

Layer 4 adjudicates ambiguous residual cases. A block decision from the judge requires corroborating signal from the ensemble, semantic module, or retrieval hit. Attack-type labels are retained as explanatory metadata and do not independently force a block. Layer 5 then removes adversarial wrappers (for example, jailbreak personas and “ignore previous instructions” scaffolds) and synthesizes a single clarified prompt that preserves the user’s legitimate objective.

### F. End-to-End Control Flow

Normalized input proceeds through Layers 1–3, retrieval, gated Layer 2b, optional Layer 4, type annotation, precision gating, and final action selection. Blocked prompts are rewritten by Layer 5. Decisions are logged for audit and offline analysis.

---

## V. Experimental Setup

### A. Named Datasets and Corpora

All corpora used in this work are explicitly named. Raw sources available under `data/raw/` are:

| Dataset name | File |
|---|---|
| Jayavibhav Prompt Injection | `jayavibhav_prompt_injection.jsonl` |
| Moltbook Extended | `moltbook_extended.jsonl` |
| CyberEC Prompt Injection Dataset 2 | `cyberec_prompt-injection-dataset2.jsonl` |
| S-Labs Prompt Injection | `s-labs_prompt-injection.jsonl` |
| Neuralchemy Threat Matrix | `neuralchemy_threat_matrix_all.jsonl` |
| PromptShield | `promptshield_all.jsonl` |

Processed labeled splits used by the final system are stored in `data/processed/{train,val,test}.jsonl`. Each record carries fields `text`, `label`, `attack_category`, and `source`.

**Training set composition (final):** 278,843 examples.

| Named source (`source` field) | Count |
|---|---:|
| `jayavibhav_prompt_injection` | 248,553 |
| `s_labs_prompt_injection` | 15,130 |
| `cyberec_prompt_injection_dataset2` | 9,134 |
| `moltbook_extended` | 6,015 |
| Curated team review (`review_queue`, `inbox_review`, `inbox_manual`) | 11 |
| **Total** | **278,843** |
| Malicious / Benign | 141,020 / 137,823 |

**Validation set:** 40,402 examples (`jayavibhav`: 39,237; `moltbook`: 1,165).  
**Held-out test set (paper-primary):** 40,402 examples (`jayavibhav`: 39,195; `moltbook`: 1,207); 20,622 malicious and 19,780 benign.

Group-aware splitting with random seed 42 preserves related prompts within the same split. Validation and test partitions remain frozen for reporting.

### B. Evaluation Protocol

Primary metrics are computed on the frozen test set using `scripts/Check_Accuracy.py` in held-out mode: accuracy, precision, recall, F1-score, AUC-ROC, false-positive rate, false-negative rate, confusion counts, latency, decision-source distribution, and per-type detection rates. Ablations evaluate the same test set under:

- `full` — complete pipeline;
- `classical_only` — Layers 1–3 only;
- `no_layer2b` — semantic module removed;
- `no_retrieval` — attack-bank retrieval removed;
- `no_layer4` — ambiguity judge removed.

Attack-bank retrieval is always constructed from training data only.

### C. Implementation

The final implementation resides in this repository (`configs/config.yaml`, `src/pipeline/pipeline.py`, and associated layer modules). Reported held-out runs use the transformer backend for Layer 2b and the heuristic ambiguity judge for Layer 4. Optional live LLM judging is supported by configuration but is not required for the primary results below.

---

## VI. Results

### A. Held-Out Detection Performance

**Table I.** Performance on the frozen held-out test set (\(N=40{,}402\)).

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

Confusion matrix: TP = 19,528; TN = 19,188; FP = 592; FN = 1,094.

**Table II.** Final decision sources on held-out traffic.

| Decision source | Count | Proportion |
|---|---:|---:|
| Layer-3 ensemble | 39,439 | 97.6% |
| Layer-4 judge | 921 | 2.3% |
| Retrieval | 42 | 0.1% |

The ensemble resolves the large majority of cases; semantic escalation and judgment are reserved for residual uncertainty.

**Table III.** Detection rate by attack category (malicious subset).

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

### B. Ablation Study

**Table IV.** Ablation on the same held-out test set.

| Configuration | Acc. | Prec. | Rec. | F1 | AUC | FPR | Latency (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|
| Full pipeline | 0.9583 | 0.9706 | 0.9469 | **0.9586** | 0.9665 | 0.0299 | 11.17 |
| Classical only (L1–L3) | 0.9307 | **0.9918** | 0.8714 | 0.9277 | **0.9932** | **0.0075** | 5.85 |
| Without Layer 2b | 0.9204 | 0.9930 | 0.8500 | 0.9160 | 0.9930 | 0.0063 | 6.54 |
| Without retrieval | 0.9583 | 0.9706 | 0.9469 | 0.9586 | 0.9666 | 0.0299 | 12.32 |
| Without Layer 4 | 0.9576 | 0.9794 | 0.9366 | 0.9575 | 0.9686 | 0.0205 | 15.33 |

The classical ensemble provides a high-precision, low-latency baseline. The full hybrid configuration recovers substantial recall (0.9469 versus 0.8714) at a moderate false-positive rate of 2.99%. Removing the semantic module degrades recall further, indicating its role on difficult residual cases. Retrieval contributes few final decisions at the selected near-duplicate threshold. The ambiguity judge yields a modest recall gain relative to the configuration without Layer 4.

---

## VII. Discussion

The results support a layered application-gateway strategy consistent with recent surveys and empirical studies [1], [2], [4], [7], [11]: inexpensive classical detectors handle the bulk of traffic, while gated semantic analysis improves coverage on harder attack families such as jailbreaks and unknown-tagged prompts.

**Limitations.** Obfuscation support in the frozen test slice is limited (\(n=17\)). The unknown category remains the weakest family. Near-duplicate retrieval rarely issues final decisions at the current threshold and can be strengthened through bank curation. Broader agent-stack threats spanning persistent memory, tool execution, and multi-agent coordination [3] require complementary controls beyond a prompt gateway. Live LLM judging is available but is not the basis of the primary tables.

**Reproducibility.** Configuration, source code, named dataset files, and evaluation scripts are provided in the repository. Held-out and ablation summaries corresponding to Tables I–IV are produced by the accuracy-check tooling under `scripts/Check_Accuracy.py`.

---

## VIII. Conclusion

This paper presented a hybrid lexical–semantic pipeline for prompt-injection detection with intent-preserving mitigation. Using named public and curated datasets and a frozen held-out test of 40,402 prompts, the final system achieves an F1-score of 0.9586 and a false-positive rate of 0.0299 at interactive latency. Ablations clarify the complementary roles of classical precision and hybrid recall. Future work includes richer obfuscation and multi-turn benchmarks, improved retrieval memory, calibrated live judging under corroboration constraints, and tighter coupling with agent-layer defenses.

---

## References

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

## Appendix A — Software Usage

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

### Principal paths

| Path | Description |
|---|---|
| `configs/config.yaml` | Final pipeline configuration |
| `src/pipeline/pipeline.py` | End-to-end orchestration |
| `data/raw/` | Named source corpora |
| `data/processed/` | Train / validation / test splits |
| `data/attack_bank.json` | Train-only retrieval memory |
| `author/` | License, notice, authors, citation |

---

## Appendix B — BibTeX

```bibtex
@software{arefin_prompt_injection_defense,
  author = {Arefin, Shams-ul},
  title  = {A Hybrid Lexical--Semantic Pipeline for Prompt-Injection Detection with Intent-Preserving Mitigation},
  url    = {https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling},
  year   = {2026}
}
```
