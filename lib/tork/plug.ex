defmodule TorkGovernance.Plug do
  @moduledoc """
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
  """

  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    if conn.method in ["POST", "PUT", "PATCH"] do
      govern_conn(conn)
    else
      conn
    end
  end

  defp govern_conn(conn) do
    try do
      {:ok, body, conn} = Plug.Conn.read_body(conn)

      if body != "" do
        result = TorkGovernance.govern(body)

        conn
        |> Plug.Conn.assign(:tork_result, result)
        |> Plug.Conn.assign(:tork_receipt, result.receipt)
      else
        conn
      end
    rescue
      _ -> conn
    end
  end
end
