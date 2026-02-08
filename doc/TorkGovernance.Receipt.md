# `TorkGovernance.Receipt`
[🔗](https://github.com/torkjacobs/tork-elixir-sdk/blob/main/lib/tork/receipt.ex#L1)

Cryptographic receipt generation for governance operations.

# `build`

```elixir
@spec build(String.t(), String.t(), [map()], atom()) :: map()
```

Build a governance receipt for an operation.

Generates a unique receipt ID, SHA-256 hashes of input and output,
and a UTC timestamp.

## Examples

    iex> receipt = TorkGovernance.Receipt.build("input", "output", [], :allow)
    iex> is_binary(receipt.receipt_id)
    true

# `generate_id`

```elixir
@spec generate_id() :: String.t()
```

Generate a unique receipt ID.

# `hash`

```elixir
@spec hash(String.t()) :: String.t()
```

Compute a SHA-256 hash of the given text.

---

*Consult [api-reference.md](api-reference.md) for complete listing*
