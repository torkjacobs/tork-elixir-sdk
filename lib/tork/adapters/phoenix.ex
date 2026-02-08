defmodule TorkGovernance.Adapters.Phoenix do
  @moduledoc """
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
  """

  @doc """
  Govern a params map by detecting and redacting PII in string values.

  Recursively traverses the map and governs all string values.

  ## Examples

      iex> TorkGovernance.Adapters.Phoenix.govern_params(%{"name" => "SSN: 123-45-6789"})
      %{"name" => "SSN: [SSN_REDACTED]"}
  """
  @spec govern_params(map(), keyword()) :: map()
  def govern_params(params, opts \\ []) when is_map(params) do
    govern_value(params, opts)
  end

  @doc """
  Govern response data before sending as JSON.

  Recursively traverses the data structure and redacts PII in string values.
  """
  @spec govern_response(term(), keyword()) :: term()
  def govern_response(data, opts \\ []) do
    govern_value(data, opts)
  end

  defp govern_value(value, opts) when is_binary(value) do
    result = TorkGovernance.govern(value, opts)
    result.output
  end

  defp govern_value(value, opts) when is_map(value) do
    Map.new(value, fn {k, v} -> {k, govern_value(v, opts)} end)
  end

  defp govern_value(value, opts) when is_list(value) do
    Enum.map(value, &govern_value(&1, opts))
  end

  defp govern_value(value, _opts), do: value
end
