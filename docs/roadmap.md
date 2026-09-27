# Roadmap

Built as a series of releases. **Each release is finished, tagged and demo-able on its own.**

The project is scoped to **v0.4 plus a write-up**. That's the point where it tells a complete story: a published multilingual dataset, a trained detector with measured results, and a live demo of an AI agent that is hijacked without the gateway and safe with it. Later ideas are listed under [Future work](#future-work): they're deliberately parked, not forgotten.

Each release has a "done when" checklist. A release isn't done until every box is ticked, including the README update.

| Release | Status |
|---|---|
| v0.1 Foundation | ✅ released (v0.1, v0.1.1) |
| v0.2 Multilingual dataset | ✅ released (v0.2, v0.2.1) |
| v0.3 Classifier & benchmark | 🚧 next |
| v0.4 Agent security (core) | planned |
| Wrap-up: write-up + demo | planned |

---

## v0.1 — Foundation ✅
Rule-based baseline, canary tokens, `/v1/scan` API, threat model, tests, Docker, CI.

**Done when**
- [x] Rules detector with normalisation (Unicode, zero-width, base64)
- [x] Source-aware policy (user / retrieved / tool)
- [x] Canary token leak detection
- [x] Threat model mapped to OWASP LLM Top 10 + MITRE ATLAS
- [x] Live dashboard (`/dashboard`) + traffic simulator
- [x] Backtest engine: metrics by source / language / family, threshold sweep, what-if comparison, runs in CI
- [x] Tests green locally and in GitHub Actions
- [x] Pushed to GitHub, tagged `v0.1`; first fix released as `v0.1.1` through a PR

---

## v0.2 — Multilingual attack dataset ✅
The foundation for everything else, and a publishable asset in its own right.

**Scope**
- Direct injection (public datasets) + **indirect injection** (BIPIA: attacks embedded in emails)
- **Spanish** coverage: machine-translated attacks *and* matching harmless texts (same translator, so translation style can't become a shortcut), plus a human-translated and adapted Spanish test set
- **Shortcut fixes**: "Spanish = safe" and "email = attack" both measured and corrected
- **Hard benign** examples: harmless text that looks like attacks, in both languages
- Held-out evaluation sets: unseen attack styles, other languages, hand-written sets

**Done when**
- [x] Reproducible Colab notebooks build the dataset from licensed sources (01 collect, 02 splits + Spanish)
- [x] Deduplication and leakage check: no text appears in more than one split
- [x] Notebook 04: dataset card built from the data (sources, licences, labels, limitations) + publishing
- [x] [Published on Hugging Face](https://huggingface.co/datasets/edithngalame/prompt-injection-en-es) under `edithngalame`, tagged `v0.2`
- [x] **v0.2.1** fix, found by the v0.3 baselines: `validation` had no emails (thresholds tuned on it blocked ~9% of harmless test emails), and a baseline memorised the harmless email sentences shared by train and test. Validation now gets whole emails, and train / validation / test use separate sentence lists

---

## v0.3 — Classifier + first benchmark
**Scope**
- Baselines: rules, TF-IDF + logistic regression, and at least one open-source detector
- Fine-tune **mDeBERTa-v3-base** (the multilingual variant: plain DeBERTa-v3 is English-only) on Colab T4
- Export to ONNX, integrate as a second detector layer in the gateway
- Metrics per source and per language: recall, precision, false-positive rate on hard benign, CPU latency
- Check the remaining email bias: false-positive rate on harmless emails
- Run the hand-written red-team and Spanish sets against the model (the lightweight part of the parked adversarial evaluation)

**Done when**
- [ ] Results table in README with every baseline, and the progress chart updated
- [ ] The `xfail` known-limitation tests flip to passing (or honestly explained if not)
- [ ] Model card on Hugging Face

---

## v0.4 — Agent security (core)
The release that turns this from "a classifier" into "a security layer for AI agents".

**Scope**
- OpenAI-compatible `/v1/chat/completions` proxy (apps switch by changing one URL)
- **Taint tracking**: once untrusted content (retrieved docs, tool output) enters a session, the session is marked tainted
- **Tool permission policy**: high-risk tools (send email, HTTP requests, write data) are blocked or need human approval in tainted sessions, *even if no attack was detected*
- Output checks: canary leak detection and markdown-image exfiltration stripping
- **Demo**: a small email-assistant agent that gets hijacked without the gateway and doesn't with it

**Done when**
- [ ] Policy config file (YAML) documented with examples
- [ ] End-to-end demo recorded as a GIF in the README
- [ ] Threat model updated with the residual risks of the taint approach

---

## Wrap-up — write-up and demo
- Technical write-up (blog post or README section): problem, design decisions, results, limitations
- Short demo video or GIF of the agent demo
- README polished for a reader with three minutes

---

## Future work
Parked on purpose to keep the project focused. Each could become its own release if a job or client needs it.

- **Adversarial evaluation**: garak and promptfoo runs, an adaptive LLM attacker, a public leaderboard
- **Shadow mode and traffic capture**: test a new detector on live traffic without enforcing it
- **PII and secret scanning** of responses (Presidio)
- **Tool-output and MCP tool-description attack data** for the dataset (v0.4's tool permissions cover this risk in the meantime), and MCP description scanning at tool registration time
- **Easy adoption**: PyPI package, LangChain / LlamaIndex integrations
- **Compliance reporting**: audit reports mapped to OWASP, NIST AI RMF and the EU AI Act
- **Hosted demo**: public dashboard running on synthetic traffic

---

## Freelance checkpoint
After **v0.4** there's enough to offer a paid service: an *AI agent security review*. Threat-model a client's chatbot or agent, test it with the red-team sets and backtests, and deliver findings plus a hardening plan.
