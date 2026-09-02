# Changelog

## 0.2.0 - 2026-09-03

### Added
- feat: `TorkGovernance.scan_tool_result/3` and `TorkGovernance.ToolResultScan` -- on-device, zero-network scanning of MCP tool results for PII and prompt-injection heuristics before they reach model context (DECIDED-TACT2-V2-C), ported from the JS SDK's `tool-result-scan.ts`. TIER 1 parity: `tork-injection-heuristics-v1` ruleset (`instruction_override`, `role_reassignment`, `exfiltration_url`), `heuristic:` finding prefix, `$.a[0].b` location grammar, four-way action mapping (blocked→deny, injection→escalate, pii→redact, else→allow).
- feat: 5 missing PII types (`address`, `date_of_birth`, `passport`, `drivers_license`, `bank_account`) added to `TorkGovernance.PII`, bringing this SDK to full parity with the JS SDK's basic 10-type (TIER 1) vocabulary.

### Fixed
- fix: `credit_card` redaction label changed from `[CREDIT_CARD_REDACTED]` to `[CARD_REDACTED]` to match the JS/Python SDKs.
- fix: `ssn`, `credit_card`, `email`, `phone` patterns now anchored with `\b` word boundaries and `ip_address` now validates octet ranges (0-255), matching the JS source patterns exactly.

## 0.1.2 - 2026-03-09

### Added
- feat: agent/session context fields (agent_id, agent_role, session_id, session_turn)
