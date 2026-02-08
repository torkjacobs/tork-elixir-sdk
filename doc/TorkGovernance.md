# `TorkGovernance`
[🔗](https://github.com/torkjacobs/tork-elixir-sdk/blob/main/lib/tork.ex#L1)

On-device AI governance with PII detection, redaction, and cryptographic receipts.

## Usage

    result = TorkGovernance.govern("My SSN is 123-45-6789")
    result.action   #=> :redact
    result.output   #=> "My SSN is [SSN_REDACTED]"
    result.receipt   #=> %{receipt_id: "...", input_hash: "...", ...}

# `govern`

```elixir
@spec govern(
  String.t(),
  keyword()
) :: map()
```

Apply governance rules to the input text.

Detects PII, applies redaction if found, and generates a cryptographic receipt.

## Options

  * `:action` - Override the default action (`:redact`)

## Examples

    iex> result = TorkGovernance.govern("Hello world")
    iex> result.action
    :allow

    iex> result = TorkGovernance.govern("SSN: 123-45-6789")
    iex> result.action
    :redact

---

*Consult [api-reference.md](api-reference.md) for complete listing*
