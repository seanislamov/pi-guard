Threat model

- Instruction overrides: attempts to negate system/developer policies.
- Tool hijacks: requests to run disallowed tools or with invalid args.
- RAG poisoning: instructions embedded in retrieved content.
- Data exfiltration: prompts to reveal secrets/system prompts.
- Jailbreak patterns: DAN, roleplay, obfuscations (base64, zero-width).

Controls
- Pre-filters with regex and entropy/length checks.
- Classifier score (placeholder ML hook).
- Policy engine with ALLOW/SANITIZE/BLOCK actions.
- RAG guard: quote suspicious lines; add trusted header.
- Tool guard: allowlist + arg sanitizer.