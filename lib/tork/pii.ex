defmodule TorkGovernance.PII do
  alias TorkGovernance.PII.Country

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

  REDACTION IS ONE PASS. Until 0.2.0 this reduced over the patterns, each
  `Regex.replace` running over the string the previous pattern had already
  rewritten. Two types matching overlapping spans could leave half an identifier
  standing beside a redaction token -- digits exposed in output the caller had
  been told was redacted. Every match is now collected against the original
  text, overlaps are resolved before anything is rewritten, and the surviving
  spans are spliced right to left in a single pass.

  ## Examples

      iex> TorkGovernance.PII.redact("SSN: 123-45-6789")
      "SSN: [SSN_REDACTED]"
  """
  @spec redact(String.t()) :: String.t()
  def redact(text), do: detect_and_redact(text).redacted_text

  @doc """
  Detect PII and return matches, the redacted text, and the country layer's
  findings in one call.

  `regions` forces a set of country profiles on, case-insensitively; `nil` or
  `[]` infers them from the content.

  Returns a map with `:has_pii`, `:types`, `:count`, `:matches`,
  `:redacted_text`, `:country_matches`, `:country_labels` and `:regions`.
  """
  @spec detect_and_redact(String.t(), [String.t()] | nil) :: map()
  def detect_and_redact(text, regions \\ nil) do
    l0 =
      Enum.flat_map(@patterns, fn {type, regex, replacement} ->
        regex
        |> Regex.scan(text, return: :index, capture: :first)
        |> List.flatten()
        |> Enum.reject(fn {_start, len} -> len == 0 end)
        |> Enum.map(fn {start, len} ->
          %{type: type, start: start, stop: start + len, redaction: replacement}
        end)
      end)

    active_regions =
      if is_list(regions) and regions != [] do
        Enum.map(regions, &String.upcase/1)
      else
        Country.infer_regions(text)
      end

    country_matches = Country.detect(text, Country.patterns_for_regions(active_regions))

    # Resolve overlaps before anything is rewritten. A country identifier
    # supersedes any L0 span it fully contains -- the cloud does the same,
    # which is how a Saudi national ID stops coming back as [PHONE_REDACTED].
    claimed0 = Enum.map(country_matches, &{&1.start_index, &1.end_index})

    spans0 =
      Enum.map(country_matches, fn c ->
        %{start_index: c.start_index, end_index: c.end_index, redaction: c.redaction}
      end)

    {_claimed, spans, kept} =
      Enum.reduce(l0, {claimed0, spans0, []}, fn hit, {claimed, spans, kept} ->
        overlapping =
          Enum.filter(claimed, fn {rs, re} -> hit.start < re and hit.stop > rs end)

        cond do
          overlapping == [] ->
            {claimed ++ [{hit.start, hit.stop}],
             spans ++ [%{start_index: hit.start, end_index: hit.stop, redaction: hit.redaction}],
             kept ++ [%{type: hit.type, match: "[REDACTED]"}]}

          not Enum.all?(overlapping, fn {rs, re} ->
            {cs, ce} = Country.trimmed_core(text, rs, re)
            hit.start <= cs and hit.stop >= ce
          end) ->
            {claimed, spans, kept}

          # An L0 span that fully contains a country span still loses: the
          # country label is the more specific claim.
          Enum.any?(overlapping, fn {rs, re} ->
            Enum.any?(country_matches, &(&1.start_index == rs and &1.end_index == re))
          end) ->
            {claimed, spans, kept}

          true ->
            claimed = Enum.reject(claimed, &(&1 in overlapping))

            spans =
              Enum.reject(spans, fn s -> {s.start_index, s.end_index} in overlapping end)

            {claimed ++ [{hit.start, hit.stop}],
             spans ++ [%{start_index: hit.start, end_index: hit.stop, redaction: hit.redaction}],
             kept ++ [%{type: hit.type, match: "[REDACTED]"}]}
        end
      end)

    %{
      has_pii: kept != [] or country_matches != [],
      types: kept |> Enum.map(& &1.type) |> Enum.uniq(),
      count: length(kept) + length(country_matches),
      matches: kept,
      redacted_text: Country.apply_redactions(text, spans),
      country_matches: country_matches,
      country_labels: country_matches |> Enum.map(& &1.label) |> Enum.uniq(),
      regions: active_regions
    }
  end
end
