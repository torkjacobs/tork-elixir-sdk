# Tork Governance Elixir SDK

On-device AI governance with PII detection, redaction, and cryptographic receipts for Elixir and Phoenix applications.

## Installation

Add `tork_governance` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:tork_governance, "~> 0.1.0"}
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

## PII Detection

```elixir
matches = TorkGovernance.PII.detect("Contact john@example.com or call 555-123-4567")
#=> [%{type: :email, match: "john@example.com"}, %{type: :phone, match: "555-123-4567"}]

redacted = TorkGovernance.PII.redact("SSN: 123-45-6789")
#=> "SSN: [SSN_REDACTED]"
```

### Supported PII Types

| Type | Example | Redaction |
|------|---------|-----------|
| SSN | 123-45-6789 | [SSN_REDACTED] |
| Email | john@example.com | [EMAIL_REDACTED] |
| Phone | 555-123-4567 | [PHONE_REDACTED] |
| Credit Card | 4111-1111-1111-1111 | [CREDIT_CARD_REDACTED] |
| IP Address | 192.168.1.1 | [IP_REDACTED] |

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
