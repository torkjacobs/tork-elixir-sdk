# `TorkGovernance.PII`
[🔗](https://github.com/torkjacobs/tork-elixir-sdk/blob/main/lib/tork/pii.ex#L1)

PII detection and redaction using regex patterns.

# `detect`

```elixir
@spec detect(String.t()) :: [map()]
```

Detect all PII matches in the given text.

Returns a list of `%{type: atom, match: string}` maps.

## Examples

    iex> TorkGovernance.PII.detect("SSN: 123-45-6789")
    [%{type: :ssn, match: "123-45-6789"}]

# `redact`

```elixir
@spec redact(String.t()) :: String.t()
```

Redact all PII in the given text, replacing matches with type-specific placeholders.

## Examples

    iex> TorkGovernance.PII.redact("SSN: 123-45-6789")
    "SSN: [SSN_REDACTED]"

---

*Consult [api-reference.md](api-reference.md) for complete listing*
