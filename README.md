# A Hybrid Lexical–Semantic Pipeline for Prompt-Injection Detection with Intent-Preserving Mitigation

**Shams-ul Arefin**  
Independent Researcher  
https://github.com/arefin95f  
https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling

---

## Abstract

Large language models (LLMs) execute instructions expressed in natural language and therefore cannot, by themselves, enforce a reliable boundary between trusted policy and untrusted content. Prompt injection exploits that boundary failure to override system behavior, exfiltrate confidential context, coerce tool use, or circumvent safety constraints. This paper presents a hybrid lexical–semantic gateway that detects such attacks and, when a block is issued, recovers the user’s legitimate intent as a single policy-compliant request. The architecture combines text normalization, rule-based prefiltering, a weighted TF–IDF ensemble, a gated DeBERTa semantic module, train-only attack-bank retrieval, and an ambiguity judge constrained by corroboration. On a frozen held-out test set of 40,402 labeled prompts, the complete system achieves an F1-score of 0.9586, precision of 0.9706, recall of 0.9469, AUC-ROC of 0.9665, and a false-positive rate of 0.0299, at a mean latency of 10.68 ms. Controlled ablations show that classical layers alone are highly precise yet incomplete, whereas the hybrid configuration restores recall under a bounded false-positive budget. The training corpus comprises 278,843 named examples drawn from public and curated sources; retrieval memory is constructed exclusively from training attacks to preclude test leakage. Source code, configuration, named datasets, and evaluation scripts accompany this work.

### Index Terms

Prompt injection, jailbreak detection, large language model security, hybrid natural language processing, ensemble learning, DeBERTa, intent-preserving mitigation, ablation study.

---

## I. Introduction

The integration of LLMs into assistants, retrieval-augmented generation (RAG) pipelines, and tool-using agents has shifted a substantial fraction of application control into free-form text. Unlike conventional software interfaces, an LLM treats language simultaneously as data and as executable instruction. Consequently, an adversary who can influence model context may rewrite the intended task—an attack class now ranked among the most severe risks for LLM applications [1]–[3]. Public incidents have already demonstrated extraction of system prompts and hidden operational constraints [4].

Existing defenses occupy several imperfect niches. Signature filters are fast but brittle under paraphrase and obfuscation. Classical classifiers are efficient yet limited in semantic coverage. Fine-tuned transformers improve representation quality at higher cost and can over-trigger on benign creative text. Prompt-engineering and model-self-protection strategies remain attractive for black-box deployments, yet adaptive evaluations indicate that security boundaries entrusted solely to the attacked model are fragile [4], [12], [13]. Comparative studies further show that detector choice is inseparable from deployment economics: accuracy, latency, and false-positive tolerance must be co-optimized [11].

A second gap is operational. Many systems terminate at binary refusal. In practice, adversarial scaffolding frequently wraps a legitimate user goal. Hard blocking without recovery discards useful intent and degrades user experience, while unrestricted forwarding preserves risk.

This paper addresses both gaps with an application-layer gateway that (i) escalates computational cost only when classical evidence is uncertain, (ii) enforces precision-oriented blocking under corroboration constraints, and (iii) rewrites blocked prompts into clarified, policy-compliant requests. The contributions are:

1. **A gated hybrid detector** that unifies lexical rules, TF–IDF ensembles, semantic scoring, retrieval memory, and ambiguity judgment under a single decision policy.
2. **Intent-preserving mitigation** that separates adversarial wrappers from residual legitimate goals and emits one safe continuation.
3. **A leakage-aware evaluation protocol** on a frozen held-out test set, with named training sources, train-only retrieval construction, and component ablations.
4. **Empirical characterization** of the precision–recall trade-off between classical-only and hybrid operation at interactive latency.

---

## II. Related Work

### A. Taxonomies and Threat Models

Systematic reviews have mapped the rapid evolution of prompt-injection techniques—from direct overrides to multi-turn, structured, multimodal, and tool-mediated attacks—and have catalogued corresponding defenses [1], [2]. Correia *et al.* further align mitigation literature with an extended NIST adversarial-machine-learning taxonomy, improving terminological consistency across studies [2]. For agentic systems, Chu argues that attack surfaces must be decomposed by architectural layer and temporal scale, because a control validated in one cell of that grid need not transfer to another [3]. Enterprise-oriented analyses using STRIDE and related methodologies emphasize trust boundaries in RAG and tool pipelines where retrieved text becomes effective control input [5], [6]. The present work adopts the application-gateway stance implied by these analyses: detection and mitigation are enforced *before* model execution.

### B. Detection Methods

Hybrid and multi-layer detectors are an emerging design pattern. Prakash *et al.* combine heuristic prefiltering with semantic embeddings and behavioral cues for real-time screening [7]. Hadiprakoso likewise pursues adaptive multi-layer detection and mitigation [8]. Operational security research couples model gateways with SIEM correlation and one-class anomaly models to improve visibility into multi-turn campaigns [9]. Dataset- and assistant-oriented frameworks stress model-agnostic monitoring for security workflows [10]. At corpus scale, Dzhaliuk *et al.* compare classical machine learning, fine-tuned encoders, specialized injection detectors, and LLM-as-classifier configurations, clarifying that higher detection rates often incur substantially higher serving cost [11].

### C. Hardening Beyond Binary Classification

Complementary lines of work harden systems without relying on a single upstream classifier. Deep *et al.* show, under adaptive attack pressure, that defenses depending on the model to police itself eventually fail, whereas application-level output constraints can hold in their setting [4]. Chen *et al.* study compact test-time DefensiveTokens for systems that consume external data [12]. Viana’s SPEF framework organizes black-box secure prompt engineering into layered application controls [13]. These results motivate treating detection as necessary but incomplete: a production gateway should also shape what reaches the model after a risky input is identified.

### D. Positioning

Relative to surveys [1]–[3] and detector comparisons [7], [11], this paper contributes a complete, measurable gateway that couples hybrid detection with intent-preserving rewrite. Relative to prompt-engineering frameworks [13] and token-only test-time defenses [12], it prioritizes offline detection metrics, interactive latency, train-only retrieval hygiene, and recovery of legitimate user intent after a block.

---

## III. Threat Model and Problem Formulation

### A. System Setting

We consider an LLM application that accepts untrusted text \(x\) from a user or from an upstream retrieval/tool channel. A defender-controlled gateway inspects \(x\) and returns an action
\[
a(x)\in\{\mathrm{ALLOW},\mathrm{FLAG},\mathrm{REVIEW},\mathrm{BLOCK}\}.
\]
If \(a(x)=\mathrm{BLOCK}\), the gateway additionally emits a mitigated request \(x'\) intended to preserve legitimate user goals while removing adversarial instruction content.

### B. Adversary

The adversary may craft or inject text that attempts to:

- override system instructions via direct commands, role reassignment, or jailbreak personas;
- extract system prompts, hidden policies, or sensitive application state;
- coerce tool invocation or delimiter/context hijacking;
- conceal payloads through obfuscation (character substitution, zero-width characters, encodings);
- distribute malicious intent across narrative framing or multi-turn context;
- embed indirect instructions in content later consumed by RAG or agent pipelines [3], [5], [6].

We assume the adversary cannot modify gateway code or training-time artifacts, but can adapt phrasing freely. Security enforcement is therefore placed in application code rather than entrusted solely to the model under attack [4].

### C. Objectives

The gateway is optimized jointly for (i) high recall across attack families, (ii) low false-positive rate on benign technical and creative text, (iii) low latency on the common classical path, (iv) absence of test leakage into retrieval memory, and (v) usable mitigation after blocking.

---

## IV. Proposed Method

### A. Architecture

The final system is a staged pipeline. Inexpensive lexical and classical stages run on every input; semantic and judgment stages are gated by uncertainty.

**Algorithm 1** (gateway inference).

1. Normalize \(x\) (leet, zero-width, Base64/URL canonicalization).
2. Compute Layer-1 rule and statistical cues.
3. Score Layer-2 TF–IDF classifiers and fuse probabilities in Layer 3.
4. Query the train-only attack bank by cosine similarity.
5. If ensemble confidence is low or the case is ambiguous, run gated DeBERTa scoring and merge evidence.
6. If residual ambiguity remains, invoke the corroboration-constrained judge.
7. Apply the precision gate and emit \(a(x)\); if blocked, synthesize \(x'\) via intent-preserving rewrite.

| Stage | Module | Role |
|---|---|---|
| 0 | Normalizer | Canonicalizes obfuscated surface forms |
| 1 | Lexical prefilter | Rule families and entropy / special-character cues |
| 2 | Classical detectors | TF–IDF (15k features; word \(n\)-grams 1–3) with logistic regression, random forest, XGBoost, and SVM |
| 3 | Ensemble fusion | Weighted probability fusion, ambiguity detection, precision gate |
| 2b | Semantic module | Gated DeBERTa prompt-injection classifier |
| R | Retrieval | Near-duplicate search over train-only attack memory |
| 4 | Ambiguity judge | Resolves uncertain cases under corroboration constraints |
| 5 | Intent rewrite | Extracts residual goal and emits one safe request |

### B. Classical Ensemble

Let \(p_m(x)\) denote the malicious-class probability of model \(m\). Layer 3 computes a weighted fusion with
\[
w_{\mathrm{logistic}}=1.3,\quad w_{\mathrm{SVM}}=1.3,\quad w_{\mathrm{XGBoost}}=0.4,\quad w_{\mathrm{RF}}=0.3.
\]
The decision threshold is 0.52. Instances with confidence or inter-model agreement below 0.45 are marked ambiguous. Hard blocking further requires risk and agreement floors of 0.70, unless strong risk (\(\ge 0.82\)) is observed. This policy reduces brittle false blocks on weakly evidenced inputs while preserving decisive action on high-agreement attacks.

### C. Gated Semantic Module

A DeBERTa prompt-injection classifier (`protectai/deberta-v3-base-prompt-injection-v2`) is invoked when ensemble confidence falls below 0.40 or the instance is ambiguous, using a malicious threshold of 0.78. Semantic scores are merged into the evidence pathway under gating; final hard blocks remain subject to ensemble precision constraints and corroboration. In this way, semantic capacity is reserved for difficult residual cases rather than applied indiscriminately to every prompt.

### D. Train-Only Attack Retrieval

An attack bank is constructed from training malicious examples and queried by TF–IDF cosine similarity (match threshold 0.65; near-duplicate force threshold 0.85). Held-out validation and test prompts are never inserted into retrieval memory. Retrieval therefore contributes memorized near-duplicate detection without contaminating evaluation.

### E. Ambiguity Judgment

Layer 4 adjudicates residual ambiguous cases. A block issued by the judge requires corroborating evidence from the ensemble, the semantic module, or retrieval. Attack-type labels are explanatory metadata only and never independently force a block. The primary reported configuration uses a deterministic heuristic judge; an optional live LLM judge is supported by configuration for deployment variants.

### F. Intent-Preserving Mitigation

Upon a block, Layer 5 separates adversarial wrappers—jailbreak personas, instruction overrides, extraction scaffolds, and related patterns—from residual legitimate goals. An intent-preserving rewriter then emits exactly one natural-language request suitable for safe continuation. When a clean goal cannot be recovered with sufficient fidelity, the rewriter falls back to a category-conditioned clarification prompt rather than forwarding the original attack text. This design treats mitigation as recovery of user intent, not merely refusal.

---

## V. Experimental Setup

### A. Named Corpora

All datasets used in this study are explicitly named. Raw corpora maintained under `data/raw/` are:

| Corpus | File |
|---|---|
| Jayavibhav Prompt Injection | `jayavibhav_prompt_injection.jsonl` |
| Moltbook Extended | `moltbook_extended.jsonl` |
| CyberEC Prompt Injection Dataset 2 | `cyberec_prompt-injection-dataset2.jsonl` |
| S-Labs Prompt Injection | `s-labs_prompt-injection.jsonl` |
| Neuralchemy Threat Matrix | `neuralchemy_threat_matrix_all.jsonl` |
| PromptShield | `promptshield_all.jsonl` |

Processed records in `data/processed/{train,val,test}.jsonl` contain `text`, `label`, `attack_category`, and `source`. Attack categories are normalized to a canonical taxonomy (including system extraction, data extraction, tool injection, jailbreak, direct injection, multi-turn, obfuscation, context tampering / poisoning, and related families), with dataset-specific aliases mapped at ingest time.

### B. Split Composition

**Training set:** 278,843 labeled examples (141,020 malicious; 137,823 benign).

| Source field | Count |
|---|---:|
| `jayavibhav_prompt_injection` | 248,553 |
| `s_labs_prompt_injection` | 15,130 |
| `cyberec_prompt_injection_dataset2` | 9,134 |
| `moltbook_extended` | 6,015 |
| Curated review (`review_queue`, `inbox_review`, `inbox_manual`) | 11 |
| **Total** | **278,843** |

**Validation set:** 40,402 examples (`jayavibhav`: 39,237; `moltbook`: 1,165).  
**Held-out test set:** 40,402 examples (`jayavibhav`: 39,195; `moltbook`: 1,207), with 20,622 malicious and 19,780 benign labels.

Splits are group-aware with random seed 42 so that related prompts remain within a single partition. Validation and test partitions are frozen for all reported metrics. Training draws on the broader named mixture above; evaluation concentrates on the frozen Jayavibhav–Moltbook held-out slices to provide a stable, leakage-controlled benchmark.

### C. Protocol and Baselines

Primary metrics are accuracy, precision, recall, F1-score, AUC-ROC, false-positive rate, false-negative rate, confusion counts, latency, decision-source distribution, and per-category detection rate. All metrics are computed on the frozen test set.

The principal controlled baseline is **classical-only** operation (Layers 1–3), which isolates the contribution of semantic, retrieval, and judgment stages. Additional leave-one-component-out ablations disable Layer 2b, retrieval, or Layer 4 individually. Attack-bank memory is always train-only. Evaluation is performed with `scripts/Check_Accuracy.py`.

### D. Implementation

The complete system is implemented in this repository. Reported held-out results use the transformer backend for Layer 2b and the heuristic judge for Layer 4. Thresholds and feature flags are fixed in `configs/config.yaml`.

---

## VI. Results

### A. Held-Out Detection Performance

**Table I.** Detection performance on the frozen held-out test set (\(N=40{,}402\)).

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

Confusion matrix: \(\mathrm{TP}=19{,}528\), \(\mathrm{TN}=19{,}188\), \(\mathrm{FP}=592\), \(\mathrm{FN}=1{,}094\).

At interactive latency, the gateway sustains high precision and strong recall simultaneously. The false-positive rate remains below 3%, which is material for user-facing assistants where over-blocking erodes trust.

**Table II.** Distribution of final decision sources.

| Source | Count | Share |
|---|---:|---:|
| Layer-3 ensemble | 39,439 | 97.6% |
| Layer-4 judge | 921 | 2.3% |
| Retrieval | 42 | 0.1% |

Nearly all decisions are resolved on the classical path. Escalation is selective: judgment and retrieval intervene only on residual uncertainty or near-duplicates. This distribution explains the observed latency profile.

**Table III.** Detection rate by attack category (malicious subset).

| Category | Support | Detected | Rate |
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

Extraction- and injection-style attacks are detected at very high rates. Jailbreak and unknown-tagged prompts remain comparatively harder, motivating the gated semantic and judgment stages analyzed next.

### B. Ablation Study

**Table IV.** Component ablations on the same held-out test set.

| Configuration | Acc. | Prec. | Rec. | F1 | AUC | FPR | Latency (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|
| Full pipeline | 0.9583 | 0.9706 | 0.9469 | **0.9586** | 0.9665 | 0.0299 | 11.17 |
| Classical only (L1–L3) | 0.9307 | **0.9918** | 0.8714 | 0.9277 | **0.9932** | **0.0075** | 5.85 |
| Without Layer 2b | 0.9204 | 0.9930 | 0.8500 | 0.9160 | 0.9930 | 0.0063 | 6.54 |
| Without retrieval | 0.9583 | 0.9706 | 0.9469 | 0.9586 | 0.9666 | 0.0299 | 12.32 |
| Without Layer 4 | 0.9576 | 0.9794 | 0.9366 | 0.9575 | 0.9686 | 0.0205 | 15.33 |

Three conclusions follow.

First, classical-only operation is an excellent high-precision baseline (precision 0.9918; FPR 0.0075) but misses a nontrivial fraction of attacks (recall 0.8714). Second, the full hybrid configuration restores recall to 0.9469 and yields the best F1-score, accepting a controlled increase in false positives. Third, removing the semantic module harms recall more than classical-only operation, indicating that gated DeBERTa and the surrounding policy interact on difficult residuals; retrieval, at the selected near-duplicate threshold, rarely determines the final label; and the ambiguity judge contributes a modest but positive recall gain relative to its removal.

---

## VII. Discussion

The results support a simple operational principle: **resolve the common case classically; escalate semantically only under uncertainty**. This principle aligns with layered-defense recommendations in the broader literature [1], [2], [7], [11] and with evidence that application-layer enforcement is indispensable [4]. Decision-source statistics make the principle concrete: 97.6% of held-out decisions never leave the ensemble.

Intent-preserving mitigation complements detection. Whereas binary gateways optimize only \(a(x)\), the proposed system also optimizes the post-block trajectory by recovering a usable \(x'\). In user-facing deployments, that recovery converts a security event into a continued, policy-safe dialogue rather than an abrupt dead end.

**Limitations.** Obfuscation support in the frozen test slice is sparse (\(n=17\)), so Table III rates for that category should be interpreted cautiously. Unknown-tagged prompts remain the weakest family. Retrieval’s limited final-decision share suggests that bank coverage and thresholding can be improved without changing the overall architecture. Layer 5 is evaluated functionally—always emitting a safe continuation—but large-scale human preference studies of rewrite quality are left to future work. Finally, threats that live primarily in agent memory, tool execution, or multi-agent coordination [3] require complementary controls beyond a prompt gateway.

**Threats to validity.** Labels inherit the conventions of the named source corpora. Group-aware splitting reduces leakage of near-duplicate prompts across partitions, and retrieval memory excludes test content; residual semantic overlap across sources can nevertheless inflate absolute scores relative to a fully out-of-distribution adversary. External detector reproductions on the identical frozen test file would further strengthen comparative claims and are a natural extension of this study.

---

## VIII. Conclusion

This paper introduced a hybrid lexical–semantic gateway for prompt-injection detection with intent-preserving mitigation. Using named public and curated corpora and a frozen held-out test of 40,402 prompts, the system attains an F1-score of 0.9586 and a false-positive rate of 0.0299 at interactive latency. Ablations demonstrate that classical layers supply precision and speed, while gated semantic analysis and constrained judgment restore recall on harder residual attacks. Future work includes richer obfuscation and multi-turn benchmarks, denser retrieval memory, calibrated live judging, human evaluation of rewrite quality, and tighter integration with agent-layer defenses.

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

[14] S. Arefin, “A Hybrid Lexical–Semantic Pipeline for Prompt-Injection Detection with Intent-Preserving Mitigation” [Computer software]. Available: https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling

---

## Appendix A — Reproducibility

```bash
python -m venv .venv
# Windows: .\.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python run_api.py
```

```bash
python scripts/Check_Accuracy.py --mode heldout
python scripts/Check_Accuracy.py --mode ablation
```

| Path | Description |
|---|---|
| `configs/config.yaml` | Fixed thresholds and feature flags |
| `src/pipeline/pipeline.py` | End-to-end orchestration |
| `data/raw/` | Named source corpora |
| `data/processed/` | Train, validation, and test splits |
| `data/attack_bank.json` | Train-only retrieval memory |
| `author/` | License, notice, authors, and citation metadata |

---

## Appendix B — BibTeX

```bibtex
@software{arefin2026promptinjection,
  author = {Arefin, Shams-ul},
  title  = {A Hybrid Lexical--Semantic Pipeline for Prompt-Injection Detection with Intent-Preserving Mitigation},
  url    = {https://github.com/arefin95f/Prompt-Attack-Monitoring-and-Controlling},
  year   = {2026}
}
```
