defmodule TorkGovernance.PII do
  @moduledoc """
  PII detection and redaction using regex patterns.

  Patterns, types, and redaction labels are ported from the JS SDK's basic
  detector (`pii.ts` `PII_PATTERNS`) so this module is JS-identical: same
  10 types, same labels, same detection order (which matters -- see
  `redact/1`).
  """

  # Order matches JS's PII_PATTERNS insertion order exactly. This is not
  # cosmetic: `redact/1` applies patterns sequentially over an accumulating
  # string, so an input where two patterns could both match the same run of
  # characters (e.g. a 16-digit card number with no separators also fits
  # `bank_account`'s \\d{8,17}) resolves to whichever pattern runs first --
  # exactly as it does in the JS source.
  @patterns [
    {:ssn, ~r/\b\d{3}-\d{2}-\d{4}\b/, "[SSN_REDACTED]"},
    {:credit_card, ~r/\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/, "[CARD_REDACTED]"},
    {:email, ~r/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/, "[EMAIL_REDACTED]"},
    {:phone, ~r/\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/, "[PHONE_REDACTED]"},
    {:address,
     ~r/\b\d{1,5}\s+\w+(?:\s+\w+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\b/i,
     "[ADDRESS_REDACTED]"},
    {:ip_address,
     ~r/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/,
     "[IP_REDACTED]"},
    {:date_of_birth, ~r/\b(?:0[1-9]|1[0-2])\/(?:0[1-9]|[12]\d|3[01])\/(?:19|20)\d{2}\b/,
     "[DOB_REDACTED]"},
    {:passport, ~r/\b[A-Z]{1,2}\d{6,9}\b/, "[PASSPORT_REDACTED]"},
    {:drivers_license, ~r/\b[A-Z]\d{7,14}\b/, "[DL_REDACTED]"},
    {:bank_account, ~r/\b\d{8,17}\b/, "[ACCOUNT_REDACTED]"}
  ]

  @doc """
  The PII types this module has a live pattern for, in detection order.

  Used by the parity test that guards against this SDK ever claiming a
  PII type (in docs, in a receipt, in another module) that has no backing
  pattern here.
  """
  @spec types() :: [atom()]
  def types, do: Enum.map(@patterns, fn {type, _regex, _redaction} -> type end)

  @doc """
  Detect all PII matches in the given text.

  Returns a list of `%{type: atom, match: string}` maps. `match` is always
  the literal string `"[REDACTED]"`, never the matched substring itself --
  the same discipline the JS detector uses so a caller cannot accidentally
  log the sensitive value straight out of a detection result.

  ## Examples

      iex> TorkGovernance.PII.detect("SSN: 123-45-6789")
      [%{type: :ssn, match: "[REDACTED]"}]
  """
  @spec detect(String.t()) :: [map()]
  def detect(text) do
    Enum.flat_map(@patterns, fn {type, regex, _replacement} ->
      regex
      |> Regex.scan(text)
      |> Enum.map(fn [_match | _] -> %{type: type, match: "[REDACTED]"} end)
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
