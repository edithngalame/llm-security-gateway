# Roadmap

Built as a series of releases. **Each release is finished, tagged and demo-able on its own**, so the project is portfolio-ready at every stage, not only at the end.

Each release has a "done when" checklist. A release isn't done until every box is ticked, including the README update.

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
- [ ] Tests green locally and in GitHub Actions
- [ ] Pushed to GitHub, tagged `v0.1`

---

## v0.2 — Multilingual attack dataset
The foundation for everything else, and a publishable asset in its own right.

**Scope**
- Direct injection (public datasets) + **indirect injection** (BIPIA-style: attacks embedded in emails, web pages, documents)
- **Poisoned MCP tool descriptions**: malicious instructions hidden in tool metadata
- **Spanish** coverage: translated attacks reviewed by a fluent Spanish speaker, plus native Spanish attacks written from scratch, not only machine translation
- **Hard benign** set: harmless text that looks like attacks, in both languages
- Splits that **hold out entire attack families** to measure generalisation

**Done when**
- [ ] Reproducible Colab notebook builds the dataset from sources
- [ ] Dataset card: sources, licences, label definitions, known biases
- [ ] Published on Hugging Face under your account
- [ ] Deduplication check: no near-duplicates leak between train and test

---

## v0.3 — Classifier + first benchmark
**Scope**
- Baselines: rules, TF-IDF + logistic regression, Meta Prompt Guard, ProtectAI DeBERTa
- Fine-tune **mDeBERTa-v3-base** (the multilingual variant: plain DeBERTa-v3 is English-only) on Colab T4
- Export to ONNX, integrate as a second detector layer
- Metrics per source and per language: precision, recall, FPR on hard benign, p50/p95 latency on CPU
- Backtest compares rules vs. rules + classifier on the v0.2 test split (`--detectors` option)
- Dashboard shows which detector layer made each decision

**Done when**
- [ ] Results table in README with every baseline
- [ ] The `xfail` known-limitation tests flip to passing (or honestly explained if not)
- [ ] Model card on Hugging Face

---

## v0.4 — Agent security layer
The release that turns this from "a classifier" into "a security layer for AI agents".

**Scope**
- OpenAI-compatible `/v1/chat/completions` proxy (apps switch by changing one URL)
- Output scanning: canary check, PII and secrets (Presidio + secret patterns), markdown-image exfiltration stripping
- **Taint tracking**: once untrusted content (retrieved docs, tool output) enters a session, the session is marked tainted
- **Tool permission policy**: each tool declares a risk level; high-risk tools (send email, HTTP POST, write DB) are blocked or require human approval in tainted sessions, *even if no attack was detected*
- **MCP tool description scanning** when an agent registers tools
- Demo: a small email-assistant agent that gets hijacked without the gateway and doesn't with it
- **Shadow mode**: run a new detector or threshold on live traffic without enforcing it, log what it *would* have decided, and compare against the enforced config on the dashboard. The real-time counterpart of backtesting
- **Opt-in traffic capture** for backtests (off by default, retention limit, redaction), so real traffic can be replayed without breaking the "no raw text in logs" rule
- Dashboard: sessions view showing taint status and tool calls blocked or held for approval

**Done when**
- [ ] Policy config file (YAML) documented with examples
- [ ] End-to-end demo recorded as a GIF in the README
- [ ] Threat model updated with residual risks of the taint approach

---

## v0.5 — Adversarial evaluation & public benchmark
**Scope**
- Static red-teaming with garak and promptfoo
- **Adaptive attacker**: an LLM that rewrites attacks against the full gateway until they pass; report attempts-to-bypass
- Attack success rate against the demo agent: no protection / rules only / full gateway / full gateway + taint policy
- Publish the benchmark: dataset + evaluation script + leaderboard others can submit to

**Done when**
- [ ] Results reproducible with one command
- [ ] Honest section in README: what still gets through, and why

---

## v0.6 — Easy adoption
**Scope**
- `pip install` package on PyPI
- One-line integrations for LangChain and LlamaIndex
- CPU latency target: p95 under ~30 ms for the classifier on typical inputs (measure, then decide)
- Docker image published

**Done when**
- [ ] "Protect your app in 5 minutes" quickstart works on a clean machine

---

## v0.7 — Compliance reporting
**Scope**
- Audit report generated from gateway logs: blocked/flagged events over time, by category and source
- Mapping of controls to OWASP LLM Top 10, NIST AI RMF and the EU AI Act
- Exportable as PDF for non-technical stakeholders

**Done when**
- [ ] Sample report in the repo, generated from the demo agent's traffic
- [ ] Mapping reviewed against the current official texts (these frameworks change)

---

## v1.0 — Launch
- Live hosted demo + public dashboard (synthetic traffic from the simulator, running 24/7)
- Technical write-up (blog post): problem, design, results, limitations
- 3-minute demo video
- Posted on LinkedIn, relevant subreddits and communities

---

## Freelance checkpoint
After **v0.4** you have enough to offer a paid service: "AI agent security review": threat-model a client's chatbot or agent, test it with your harness, deliver findings and a hardening plan.
