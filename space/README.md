---
title: LLM Security Gateway
emoji: 🛡️
colorFrom: indigo
colorTo: red
sdk: gradio
python_version: "3.11"
app_file: app.py
pinned: true
license: mit
short_description: Detects prompt injection in English and Spanish
models:
  - edithngalame/mdeberta-v3-prompt-injection-en-es
datasets:
  - edithngalame/prompt-injection-en-es
---

# LLM Security Gateway: live demo

Paste a message and see whether the [LLM Security Gateway](https://github.com/edithngalame/llm-security-gateway) lets it reach an AI model. Rules first, then a fine-tuned multilingual classifier ([model](https://huggingface.co/edithngalame/mdeberta-v3-prompt-injection-en-es)), with a source-aware policy: documents are judged more strictly than user messages.

This Space runs the gateway's own code from GitHub, pinned to the `v0.3` release.
