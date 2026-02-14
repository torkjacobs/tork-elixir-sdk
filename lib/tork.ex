defmodule TorkGovernance do
  @moduledoc """
  On-device AI governance with PII detection, redaction, and cryptographic receipts.

  ## Usage

      result = TorkGovernance.govern("My SSN is 123-45-6789")
      result.action   #=> :redact
      result.output   #=> "My SSN is [SSN_REDACTED]"
      result.receipt   #=> %{receipt_id: "...", input_hash: "...", ...}
  """

  alias TorkGovernance.PII
  alias TorkGovernance.Receipt

  @doc """
  Apply governance rules to the input text.

  Detects PII, applies redaction if found, and generates a cryptographic receipt.

  ## Options

    * `:action` - Override the default action (`:redact`)
    * `:region` - List of regional PII profiles to activate (e.g. `["ae", "in"]`)
    * `:industry` - Industry profile to activate (e.g. `"healthcare"`, `"finance"`, `"legal"`)

  ## Examples

      iex> result = TorkGovernance.govern("Hello world")
      iex> result.action
      :allow

      iex> result = TorkGovernance.govern("SSN: 123-45-6789")
      iex> result.action
      :redact

      iex> result = TorkGovernance.govern("Emirates ID: 784-1234-1234567-1", region: ["ae"])
      iex> result.region
      ["ae"]
  """
  @spec govern(String.t(), keyword()) :: map()
  def govern(text, opts \\ []) do
    pii_matches = PII.detect(text)
    region = Keyword.get(opts, :region)
    industry = Keyword.get(opts, :industry)

    if Enum.empty?(pii_matches) do
      receipt = Receipt.build(text, text, pii_matches, :allow)

      %{
        action: :allow,
        output: text,
        pii_detected: [],
        receipt: receipt,
        region: region,
        industry: industry
      }
    else
      redacted = PII.redact(text)
      action = Keyword.get(opts, :action, :redact)
      receipt = Receipt.build(text, redacted, pii_matches, action)

      %{
        action: action,
        output: redacted,
        pii_detected: pii_matches,
        receipt: receipt,
        region: region,
        industry: industry
      }
    end
  end
end
