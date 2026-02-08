# `TorkGovernance.Plug`
[🔗](https://github.com/torkjacobs/tork-elixir-sdk/blob/main/lib/tork/plug.ex#L1)

Plug middleware for Tork governance.

Automatically governs incoming request bodies for PII and attaches
the governance receipt to `conn.assigns[:tork_receipt]`.

## Usage in a Phoenix Router

    pipeline :governed do
      plug TorkGovernance.Plug
    end

    scope "/api", MyAppWeb do
      pipe_through [:api, :governed]
      post "/chat", ChatController, :create
    end

---

*Consult [api-reference.md](api-reference.md) for complete listing*
