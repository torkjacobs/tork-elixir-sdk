# Changelog

## 0.3.0 - 2026-09-25

### Added
- PII registry bundle 1.2.0 (24 countries, incl. AU TFN/ABN/Medicare).
- **The country layer: 24 country profiles, 54 patterns, 20 check digits.**
  Patterns, keywords, redaction labels and checksum gates are generated from
  Tork's own country registry and consumed verbatim from the SDK bundle
  (`Registry-Version: 1.2.0`, content `cfd4f61ebaf45e74`). Countries: AU, US, GB, EU, AE, SA, NG, IN, JP,
  CN, KR, BR, CA, ZA, GH, IT, KE, MU, MX, MY, PK, SG, TH, ID.
  1.2.0 adds three `alwaysOn` Australian patterns -- `au_tfn`, `au_abn` and
  `au_medicare` -- that run on every document regardless of region
  activation; `TorkGovernance.PII.Country.patterns_for_regions/1` now wires
  them in unconditionally so this SDK can catch a TFN, ABN or Medicare number
  in a sentence that activates no country signal at all (the ABN's own
  cloud-corpus sentence is exactly this case).
- New modules: `Tork.Governance.Pii.Registry` (the bundle's 51 patterns),
  `Tork.Governance.Pii.Activation` (the 51 signals and the country map),
  `TorkGovernance.PII.Checksums` (20 algorithms) and
  `TorkGovernance.PII.Country` (the matcher). All pure and local: no network,
  no clock.
- `TorkGovernance.PII.detect_and_redact/2` returns `:has_pii`, `:types`,
  `:count`, `:matches`, `:redacted_text`, `:country_matches`,
  `:country_labels` and `:regions`, and takes an optional region list that
  forces a set of country profiles on. `detect/1` and `redact/1` keep their
  signatures and their documented results.
- **Nine check digits ported by hand.** The bundle names twenty algorithms and
  specifies the eleven that reduce to a weight vector and a modulus; the other
  nine (`br_cpf`, `br_cnpj`, `cn_resident_id`, `de_steuer_id`, `fr_nir`,
  `it_codice_fiscale`, `jp_my_number`, `kr_rrn`, `sg_nric`) are ported from the
  cloud's `lib/pii/checksums.ts`, each tested against the issuing authority's
  own worked example where one is published.

### Fixed
- **SDK-ELIXIR-PARTIAL-REDACTION.** Until 0.2.0 `redact/1` reduced over the
  patterns, each `Regex.replace` running over the string the previous pattern
  had already rewritten. Two types matching overlapping spans could leave half
  an identifier standing beside a redaction token -- digits exposed in output
  the caller had been told was redacted. Every match is now collected against
  the original text, overlaps are resolved before anything is rewritten, and
  the surviving spans are spliced right to left in one pass.
  `nothing is ever partially redacted` asserts the invariant across all 268
  vectors.

### Notes
- This release folds in 0.2.0, which is in this repository but was never
  published to Hex (Hex is at 0.1.0).
- `country_matches` offsets are BYTE offsets, matching `Regex.scan/3` with
  `return: :index`.
- **The bundle now states the whole contract, and this SDK implements it.**
  Bundle 1.0.0's README documented three rules; measured against the cloud's
  golden snapshot they disagreed with it on 14 of 86 country-corpus cases, so
  this SDK carried two more of its own. Bundle **1.1.0 documents seven**, marks
  each SDK or cloud-only, and ships the data all seven need in every language
  file -- the activation signals, the country map, the asymmetric 60/40 window,
  the symmetric 60 context window, the whole-word vocabulary, the near-miss
  policy, the table constants and the reference labels. So the locally generated
  activation layer is **deleted**, no window is hard-coded any more, and rules 6
  (near miss), 7 (column header) and 7b (nearest label) are implemented here for
  the first time. Every rule now reads its data off the placed bundle.
- Advisory checksums never reject a match: `ca_sin`, `emirates_id`,
  `de_tax_id`, `kr_rrn`, `sa_national_id`. Korea stopped issuing check digits on
  20 Oct 2020.
- Not ported, and still cloud-only: the slot, context,
  gravity and name layers, industry profiles, and org configuration.
- **Indonesia is the country 1.1.0 added, and it is the one that proves the
  whole-word rule.** `id_nik`'s only short spellings -- NIK, KTP, NPWP -- are
  `wholeWordKeywords`, not ordinary keywords, because `nik` sits inside
  *teknik*, *elektronik*, *klinik* and *pabrik*. Matching them by substring
  would open the gate on an Indonesian sales ledger; matching them on a word
  boundary catches "NIK 3171010101900001" and leaves *teknik* alone. An SDK that
  merged the two lists would be shipping a false-positive bug, so the boundary
  test is implemented rather than the shortcut, and four unit cases assert both
  halves.
- **FLAGGED, upstream: bundle 1.1.0 cannot detect Australia's TFN, ABN or
  Medicare number.** `checksums.json` declares `au_tfn` and `au_abn` as
  `requiredBy` and `au_medicare` as `advisoryFor` patterns of those names, and
  `patterns` ships none of them -- the AU profile carries only `au_acn` and
  `au_phone_intl`. The AU activation signals are still keyed on "tfn", "tax
  file" and "medicare", so the bundle switches Australia on for identifiers it
  then has no pattern to catch. The cloud detects all three. This is a recall
  gap no SDK can close from the bundle, and the six parity cases it costs are
  recorded in the fixture as `BUNDLE GAP` rather than silently accepted.

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
