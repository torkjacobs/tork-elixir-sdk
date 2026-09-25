# Tork Governance Elixir SDK

On-device AI governance with PII detection, redaction, and cryptographic receipts for Elixir and Phoenix applications.

## Installation

Add `tork_governance` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:tork_governance, "~> 0.3.0"}
  ]
end
```

## Quick Start

```elixir
result = TorkGovernance.govern("My SSN is 123-45-6789")

result.action        #=> :redact
result.output        #=> "My SSN is [SSN_REDACTED]"
result.pii_detected  #=> [%{type: :ssn, match: "123-45-6789"}]
result.receipt       #=> %{receipt_id: "rcpt_...", input_hash: "sha256:...", ...}
```

## Country PII detection

23 country profiles, 50 patterns and 20 check digits, generated from Tork's own
country registry (bundle `1.0.0`) and computed entirely on-device.

Countries: AU, US, GB, EU, AE, SA, NG, IN, JP, CN, KR, BR, CA, ZA, GH, IT, KE,
MU, MX, MY, PK, SG, TH.

A country's patterns switch on when the text activates that country — the same
content signals the cloud uses — so ordinary business text is not measured
against 50 national-identifier patterns it could never contain. On the
1,159-line business corpus this SDK is tested against, nothing is redacted.

```elixir
r = TorkGovernance.PII.detect_and_redact(
  "South African ID number 8001015009087 for the FICA check."
)

r.regions        # ["ZA"]
r.country_labels # ["ZA_ID"]
r.redacted_text  # "South African ID number [ZA_ID_REDACTED] for the FICA check."
```

Force profiles on when you already know the jurisdiction:

```elixir
forced = TorkGovernance.PII.detect_and_redact(
  "Documento 529.982.247-25 arquivado.", ["br"]
)
# forced.redacted_text == "Documento [CPF_REDACTED] arquivado."
```

Three gates keep the false-positive rate down, and all three must pass:

1. **Activation** — one of the country's content signals fires.
2. **Keyword** — for 18 of the 24 national, tax and health identifiers, one of
   the identifier's keywords must appear within 60 characters before the match
   or 40 after.
3. **Check digit** — for the 10 identifiers whose issuing authority publishes
   the algorithm, a number of the right shape that fails its check digit is not
   that country's identifier. Where the algorithm is community-sourced rather
   than authority-published (`ca_sin`, `emirates_id`, `de_tax_id`, `kr_rrn`,
   `sa_national_id`) the checksum is advisory and never rejects a match.

Offsets in `country_matches` are byte offsets, which is what `Regex.scan/3`
with `return: :index` reports.

Still cloud-only, and not in this SDK: the near-miss fallback, the slot,
context, gravity and name layers, industry profiles, and org configuration.

## PII Detection

```elixir
matches = TorkGovernance.PII.detect("Contact john@example.com or call 555-123-4567")
#=> [%{type: :email, match: "john@example.com"}, %{type: :phone, match: "555-123-4567"}]

redacted = TorkGovernance.PII.redact("SSN: 123-45-6789")
#=> "SSN: [SSN_REDACTED]"
```

### Supported PII Types

**Parity tier: TIER 1** -- this is the JS SDK's basic 10-type vocabulary,
with JS-identical types and redaction labels. This SDK does not implement
the Python SDK's additional regional-detector tier; the `region`/`industry`
options on `govern/2` select which extra patterns are documented as
available, not an Elixir-native regional pattern set.

| Type | Example | Redaction |
|------|---------|-----------|
| SSN | 123-45-6789 | [SSN_REDACTED] |
| Credit Card | 4111-1111-1111-1111 | [CARD_REDACTED] |
| Email | john@example.com | [EMAIL_REDACTED] |
| Phone | 555-123-4567 | [PHONE_REDACTED] |
| Address | 123 Main Street | [ADDRESS_REDACTED] |
| IP Address | 192.168.1.1 | [IP_REDACTED] |
| Date of Birth | 05/12/1990 | [DOB_REDACTED] |
| Passport | AB1234567 | [PASSPORT_REDACTED] |
| Driver's License | A12345678901 | [DL_REDACTED] |
| Bank Account | 123456789 | [ACCOUNT_REDACTED] |

## Scanning Tool Results

A tool result returned by an MCP server -- or any external system you don't
control -- is untrusted input about to be appended to a model's context.
`TorkGovernance.scan_tool_result/3` scans it BEFORE that happens, entirely
on-device, for two things:

1. **PII**, using the same detector as `govern/2` (see above).
2. **Prompt injection**, using a conservative heuristic pattern set. Every
   injection finding is labelled `heuristic:<type>` so a downstream reader
   of a receipt can never mistake a regex hit for a verified determination.
   The ruleset (`tork-injection-heuristics-v1`) currently detects three
   types: `instruction_override`, `role_reassignment`, `exfiltration_url`.

This is a pure, synchronous, **zero-network** operation -- ported
byte-for-byte (regex sources, receipt schema, action mapping) from the JS
SDK's `tool-result-scan.ts`, so a receipt produced here has the same shape
as one produced by the JS or Python SDKs. See
`TorkGovernance.ToolResultScan` for the Elixir-specific implementation
notes (regex/unicode handling, why there's no cycle guard, map key
ordering).

```elixir
result = TorkGovernance.scan_tool_result(
  "lookup_customer",
  %{"content" => [%{"type" => "text", "text" => "Contact jane.doe@example.com"}]},
  server_uri: "mcp://crm.internal/customers"
)

result.action     #=> :redact  (:allow | :redact | :escalate | :deny)
result.sanitized  #=> payload with PII masked in place
result.receipt.tool_result_scan
#=> %{
#     attested_by: "client",
#     blocked: false,
#     capture_mode: "edge",
#     findings: %{injection: %{}, pii: %{"email" => 1}},
#     injection_ruleset: "tork-injection-heuristics-v1",
#     sdk_language: "elixir",
#     sdk_version: "0.2.0",
#     server_uri: "mcp://crm.internal/customers",
#     tool_name: "lookup_customer",
#     totals: %{injection: 0, pii: 1}
#   }
```

Pass `block_on_injection: true` to have the scan refuse to hand back a
payload at all when an injection heuristic fires -- `result.action` becomes
`:deny`, `result.sanitized` is `nil`, and `result.reason` explains why
(without ever quoting the flagged text back).

## Phoenix Integration

### Plug Pipeline

Add the governance plug to your router pipeline:

```elixir
pipeline :governed do
  plug TorkGovernance.Plug
end

scope "/api", MyAppWeb do
  pipe_through [:api, :governed]
  post "/chat", ChatController, :create
end
```

Access the governance result in your controller:

```elixir
defmodule MyAppWeb.ChatController do
  use MyAppWeb, :controller

  def create(conn, params) do
    receipt = conn.assigns[:tork_receipt]
    governed_text = conn.assigns[:tork_result].output

    json(conn, %{
      message: governed_text,
      receipt_id: receipt.receipt_id
    })
  end
end
```

### Controller Helpers

Use the Phoenix adapter to govern params directly:

```elixir
defmodule MyAppWeb.UserController do
  use MyAppWeb, :controller
  alias TorkGovernance.Adapters.Phoenix, as: TorkPhoenix

  def create(conn, params) do
    governed_params = TorkPhoenix.govern_params(params)
    # governed_params has all string values redacted for PII

    json(conn, %{status: "ok"})
  end

  def show(conn, _params) do
    user = get_user()
    governed = TorkPhoenix.govern_response(user)
    json(conn, governed)
  end
end
```

## Cryptographic Receipts

Every governance operation generates a verifiable receipt:

```elixir
result = TorkGovernance.govern("Sensitive data")

result.receipt.receipt_id   #=> "rcpt_a1b2c3..."
result.receipt.timestamp    #=> "2026-02-08T12:00:00Z"
result.receipt.input_hash   #=> "sha256:9f86d08..."
result.receipt.output_hash  #=> "sha256:abc123..."
result.receipt.pii_count    #=> 1
result.receipt.action       #=> :redact
```

## License

MIT
