# Threat Model — LLM Security Gateway

**Version:** 0.2 · **Status:** covers the full roadmap (v0.1–v1.0) · **Method:** asset → trust boundary → threat → control, mapped to OWASP Top 10 for LLM Applications (2025) and MITRE ATLAS.

## 1. System under protection

A typical LLM application: a chat or agent front end, an LLM API, a retrieval layer (vector DB over company documents or web pages), and optionally tools the model can call (email, database, HTTP).

The gateway sits on every path into and out of the model:

```
             TB1                TB2                 TB3
 User ──────►│  ┌─────────┐    │   ┌─────┐          │
             │  │         │────┼──►│ LLM │          │
 Retriever ──┼─►│ Gateway │    │   └──┬──┘          │
 (docs, web) │  │         │◄───┼──────┘             │
 Tools ──────┼─►│         │────┼──► tool calls ─────┼──► email / DB / HTTP
             │  └─────────┘    │                    │
```

**Trust boundaries**
- **TB1 — untrusted content → gateway.** Everything arriving here is attacker-controllable: user text *and* retrieved documents *and* tool results.
- **TB2 — gateway ↔ model provider.** Prompts leave our infrastructure; responses are untrusted until scanned.
- **TB3 — model → actions.** Model output that triggers tools or is rendered to users.

## 2. Assets

| Asset | Why it matters |
|---|---|
| System prompt & business logic | Leaks reveal guardrails, enable targeted attacks, expose IP |
| User & company data in context | PII, credentials, confidential documents (GDPR exposure) |
| Tool privileges | Sending email, writing to DBs, calling APIs *as the application* |
| Output integrity | Users act on answers; manipulated output = fraud/misinformation |
| Availability & cost | Each request costs tokens; abuse is a financial DoS |

## 3. Threat actors

- **Malicious user**: types attacks directly (jailbreaks, prompt extraction).
- **Content poisoner**: never talks to the app; plants instructions in a web page, email, PDF or shared doc that the app will later retrieve. *This is the most underestimated actor*, because the victim is a normal user.
- **Compromised tool/API**: a third-party service returns malicious output.
- **Malicious MCP server author**: publishes a useful-looking tool whose *description* contains hidden instructions. The agent reads the description when the tool is registered, before any tool is even called.

## 4. Threats and controls

| # | Threat | OWASP LLM 2025 | MITRE ATLAS | Gateway control | Step |
|---|---|---|---|---|---|
| T1 | Direct prompt injection / jailbreak | LLM01 | AML.T0051.000, AML.T0054 | Rule layer + fine-tuned multilingual classifier on `source=user` | v0.1, v0.3 |
| T2 | **Indirect injection** via retrieved docs / web | LLM01, LLM08 | AML.T0051.001 | Stricter thresholds + "addressed-to-AI" rules on `source=retrieved`; classifier trained on indirect data (BIPIA) | v0.1, v0.3 |
| T3 | Injection via tool output in agent loops | LLM01, LLM06 | AML.T0051.001 | Same as T2 on `source=tool`; **taint tracking + tool permission policy** limits impact when detection fails | v0.1, v0.4 |
| T4 | System prompt extraction | LLM07 | AML.T0056 | Input: extraction rules. Output: **canary token** check (detects leaks input filters missed) | v0.1 |
| T5 | Sensitive data in responses | LLM02 | AML.T0057 | Output PII/secret scanning (Presidio + secret regexes), redaction | v0.4 |
| T6 | Data exfiltration via rendered output (markdown image URLs, links) | LLM05 | AML.T0057 | Exfiltration rules on output; strip or neutralise external image URLs | v0.1, v0.4 |
| T7 | Obfuscated payloads (zero-width chars, homoglyphs, base64) | LLM01 | AML.T0051 | Unicode normalisation, invisible-char stripping, base64 decode-and-rescan | v0.1 |
| T8 | Cost / resource abuse | LLM10 | AML.T0034 | Request size limits (done), rate limiting per key | v0.1, v0.4 |
| T9 | Attacks on the gateway itself (evasion of the classifier) | — | AML.T0015 | Held-out attack families; garak & promptfoo; **adaptive LLM attacker** reporting attempts-to-bypass; layered detectors | v0.2, v0.5 |
| T10 | Logs become a data leak | LLM02 | — | Log decisions and categories, **never** raw prompt text by default | v0.1 |
| T11 | **MCP tool description poisoning** | LLM01, LLM03 | AML.T0051.001 | Scan tool descriptions and schemas at registration (`source=tool_description`, strictest thresholds); pin approved descriptions and alert on changes ("rug pull") | v0.2, v0.4 |
| T12 | **Hijacked agent performs harmful actions** (sends data out, deletes records) | LLM06 | AML.T0053 | Taint tracking: untrusted content marks the session; high-risk tools blocked or need human approval in tainted sessions, *independent of detection* | v0.4 |
| T13 | Evasion via non-English attacks | LLM01 | AML.T0051 | Multilingual classifier (mDeBERTa-v3); Spanish in train and test sets; per-language metrics | v0.2, v0.3 |

*ATLAS IDs to double-check against the current matrix at atlas.mitre.org before publishing. IDs are occasionally renumbered.*

## 5. Design principles

1. **Source-aware scanning.** The same sentence is normal from a user and suspicious inside a PDF. Trust is decided by *where text came from*, not only by what it says.
2. **Defence in depth.** Cheap rules → ML classifier → output checks. Any layer can block; no single layer is trusted to be complete.
3. **Detect success, not just attempts.** Canary tokens and output scanning catch attacks that evaded input filtering.
4. **Limit impact, not just attempts.** Detection will sometimes fail. Taint tracking and tool permissions make sure a missed attack still can't trigger high-risk actions without approval.
5. **Measure false positives as seriously as detections.** A gateway that blocks normal users gets disabled, which is worse than a weaker one that stays on.
6. **Privacy by default.** The gateway handles sensitive text; it must not become the leak.

## 6. Out of scope / residual risk (be honest in the write-up)

- **Detection is probabilistic.** Prompt injection has no known complete fix at the model level; the gateway reduces risk, it does not eliminate it.
- **The real mitigation for T3/T12 is least privilege.** An agent that can't send email can't be tricked into sending email. The taint policy enforces this at runtime, but it only knows about the tools it is told about, and the risk levels are set by humans who can get them wrong.
- **Taint tracking trades usefulness for safety.** Blocking tools in every tainted session is safe but annoying; approval prompts get rubber-stamped. v0.4 must measure how often legitimate tasks are interrupted.
- **Compliance mappings (v0.7) are guidance, not legal advice.** OWASP, NIST AI RMF and the EU AI Act evolve; mappings must be re-checked against the official texts at each release.
- Training-time attacks (model/data poisoning of the LLM itself, OWASP LLM04) and supply-chain risk in model weights (LLM03) are not addressed by a runtime gateway.
- Multi-turn attacks that spread an injection across several messages are only partially covered until conversation-level scanning is added.

## 7. Evaluation plan (v0.2, v0.3, v0.5)

- Metrics per source **and per language**: precision, recall, **false positive rate on hard benign data**, p50/p95 latency.
- Test split holds out entire attack families to measure generalisation to unseen attacks.
- Red-team: attack success rate against the demo agent under four settings: no protection / rules only / full detection / full detection + taint policy.
- Adaptive attacker: median attempts an LLM attacker needs to bypass the gateway, with the attacker allowed to see block decisions.
- Taint policy cost: share of benign agent tasks interrupted by a block or approval prompt.
