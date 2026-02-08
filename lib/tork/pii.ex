defmodule TorkGovernance.PII do
  @moduledoc """
  PII detection and redaction using regex patterns.
  """

  @patterns [
    {:ssn, ~r/\d{3}-\d{2}-\d{4}/, "[SSN_REDACTED]"},
    {:email, ~r/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/, "[EMAIL_REDACTED]"},
    {:phone, ~r/(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/, "[PHONE_REDACTED]"},
    {:credit_card, ~r/\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}/, "[CREDIT_CARD_REDACTED]"},
    {:ip_address, ~r/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, "[IP_REDACTED]"}
  ]

  @doc """
  Detect all PII matches in the given text.

  Returns a list of `%{type: atom, match: string}` maps.

  ## Examples

      iex> TorkGovernance.PII.detect("SSN: 123-45-6789")
      [%{type: :ssn, match: "123-45-6789"}]
  """
  @spec detect(String.t()) :: [map()]
  def detect(text) do
    Enum.flat_map(@patterns, fn {type, regex, _replacement} ->
      regex
      |> Regex.scan(text)
      |> Enum.map(fn [match | _] -> %{type: type, match: match} end)
    end)
  end

  @doc """
  Redact all PII in the given text, replacing matches with type-specific placeholders.

  ## Examples

      iex> TorkGovernance.PII.redact("SSN: 123-45-6789")
      "SSN: [SSN_REDACTED]"
  """
  @spec redact(String.t()) :: String.t()
  def redact(text) do
    Enum.reduce(@patterns, text, fn {_type, regex, replacement}, acc ->
      Regex.replace(regex, acc, replacement)
    end)
  end
end
