# `TorkGovernance.Adapters.Phoenix`
[🔗](https://github.com/torkjacobs/tork-elixir-sdk/blob/main/lib/tork/adapters/phoenix.ex#L1)

Phoenix-specific governance helpers.

Provides functions to govern controller params and response data.

## Usage in a Controller

    defmodule MyAppWeb.ChatController do
      use MyAppWeb, :controller
      alias TorkGovernance.Adapters.Phoenix, as: TorkPhoenix

      def create(conn, params) do
        governed = TorkPhoenix.govern_params(params)
        # Use governed params...
        json(conn, %{status: "ok"})
      end
    end

# `govern_params`

```elixir
@spec govern_params(
  map(),
  keyword()
) :: map()
```

Govern a params map by detecting and redacting PII in string values.

Recursively traverses the map and governs all string values.

## Examples

    iex> TorkGovernance.Adapters.Phoenix.govern_params(%{"name" => "SSN: 123-45-6789"})
    %{"name" => "SSN: [SSN_REDACTED]"}

# `govern_response`

```elixir
@spec govern_response(
  term(),
  keyword()
) :: term()
```

Govern response data before sending as JSON.

Recursively traverses the data structure and redacts PII in string values.

---

*Consult [api-reference.md](api-reference.md) for complete listing*
