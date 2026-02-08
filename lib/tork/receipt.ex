defmodule TorkGovernance.Receipt do
  @moduledoc """
  Cryptographic receipt generation for governance operations.
  """

  @doc """
  Build a governance receipt for an operation.

  Generates a unique receipt ID, SHA-256 hashes of input and output,
  and a UTC timestamp.

  ## Examples

      iex> receipt = TorkGovernance.Receipt.build("input", "output", [], :allow)
      iex> is_binary(receipt.receipt_id)
      true
  """
  @spec build(String.t(), String.t(), [map()], atom()) :: map()
  def build(input, output, pii_list, action) do
    %{
      receipt_id: generate_id(),
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      input_hash: hash(input),
      output_hash: hash(output),
      pii_count: length(pii_list),
      pii_types: Enum.map(pii_list, & &1.type) |> Enum.uniq(),
      action: action
    }
  end

  @doc """
  Generate a unique receipt ID.
  """
  @spec generate_id() :: String.t()
  def generate_id do
    "rcpt_" <> (:crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower))
  end

  @doc """
  Compute a SHA-256 hash of the given text.
  """
  @spec hash(String.t()) :: String.t()
  def hash(text) do
    "sha256:" <> (:crypto.hash(:sha256, text) |> Base.encode16(case: :lower))
  end
end
