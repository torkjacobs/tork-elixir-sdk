defmodule TorkGovernance.ToolResultScan do
  @moduledoc """
  Tool-result scanning (DECIDED-TACT2-V2-C).

  A tool result returned by an MCP server -- or by any external system the
  caller does not control -- is untrusted input that is about to be appended
  to a model's context. This module scans it BEFORE that happens, on-device,
  for two things:

    1. PII, using the SAME on-device detector as `TorkGovernance.govern/2`
       (`TorkGovernance.PII.detect/1`). Nothing new was written for this:
       same patterns, same redaction labels, same zero-network guarantee.
    2. Prompt injection, using the conservative heuristic pattern set below,
       ported verbatim (regex sources) from the JS SDK's `tool-result-scan.ts`.
       Every injection finding is labelled `heuristic:<type>` so no caller
       can mistake a regex hit for a verified determination.

  ZERO NETWORK. Every function here is pure: no I/O, no clock, no process
  dictionary, no GenServer call. The payload never leaves the machine.

  WHAT THIS IS NOT: this is a client-side control that the CALLER runs and
  the caller attests to. It is not gateway-side enforcement -- a compromised
  or simply careless caller can skip it entirely, and Tork cannot tell.

  ## Parity notes (Elixir-specific)

  This module is a byte-for-byte port of the JS SDK's `tool-result-scan.ts`
  for everything observable in the `tool_result_scan` receipt block: the
  `heuristic:` prefix, the `tork-injection-heuristics-v1` ruleset id, the
  three injection type names, the `$.a[0].b` location grammar, the
  four-way action mapping (done in `TorkGovernance.scan_tool_result/3`),
  and the injection regex *source strings* themselves. A few things differ
  because Elixir is not JavaScript:

    * **Regex engine / unicode.** Erlang's `re` module is PCRE-based, so
      none of these patterns need lookaround rewrites (none of the ported
      patterns use lookaround, so this didn't come up in practice, but it
      would work if a future pattern needed it). Patterns are compiled
      WITHOUT the Elixir `u` (unicode) regex modifier, deliberately: `u`
      would make `\\d`/`\\w`/`\\s` match the broader Unicode digit/letter/
      space classes, which is NOT what JS's (non-`/u`-flagged) `\\d`/`\\w`
      do -- JS's character classes are ASCII-only regardless of the `/u`
      flag. Turning `u` on here would silently widen PII/injection matching
      beyond JS parity (e.g. `\\d{3}-\\d{2}-\\d{4}` matching non-ASCII digit
      scripts). The one observable cost: bounded "any character" spans like
      `[^.\\n]{0,40}` count *bytes*, not Unicode codepoints, when scanned
      text contains multi-byte UTF-8 sequences near a heuristic match --
      JS counts UTF-16 code units instead. This never changes *whether* a
      pattern fires, only the width of the context window it can span
      through non-ASCII text, so it's noted here rather than treated as a
      correctness bug.
    * **Cycle guard.** The JS/Python ports carry a `seen` set to avoid
      infinite recursion on a cyclic payload (`payload.self = payload`).
      There is deliberately no such guard here: Elixir terms are immutable,
      and immutable data cannot contain a reference to itself -- there is no
      way to construct `value = %{self: value}` in the language. A cycle
      guard here would be dead code guarding against an unreachable state,
      so this port omits it rather than faking one.
    * **Identity preservation.** `walk/5` still returns the exact same
      value (no rebuild) for a subtree with nothing to mask, mirroring the
      JS/Python algorithm 1:1 for performance. It is not independently
      *observable* the way it is in JS (`expect(x).toBe(y)` checks object
      reference identity; Elixir has no such concept for immutable maps/
      lists/binaries -- `==` is the only equality there is). Parity here is
      verified via deep equality instead.
    * **Traversal order.** JS objects preserve key insertion order, so the
      JS test suite's `findings` list has a deterministic cross-location
      order. Elixir maps make no such guarantee. The `tool_result_scan`
      receipt block is unaffected (it aggregates counts by type across the
      whole payload, not per-location), but the raw `findings` list
      returned by `scan/3` may enumerate locations in a different order
      than an equivalent JS run. Tests assert on finding *sets*, not list
      order, for this reason.
  """

  alias TorkGovernance.PII

  # Prefix on every injection finding's `type`. Not cosmetic: these patterns
  # are regexes over untrusted text, they carry false positives and false
  # negatives, and the label travels with the finding into the receipt.
  @injection_heuristic_prefix "heuristic:"

  # Identifies this exact pattern set in receipts. Bump when the patterns
  # change, so a receipt says which ruleset produced its counts. Every SDK
  # mirroring this implementation must emit the SAME value for the same
  # ruleset -- it is a shared identifier, not a per-language one.
  @injection_ruleset "tork-injection-heuristics-v1"

  @default_max_depth 32

  # Conservative on purpose. Each pattern targets a phrase that has no
  # plausible reason to appear in a legitimate tool result -- a database row,
  # a search hit, a file listing. Regex SOURCES are ported verbatim from the
  # JS SDK's INJECTION_PATTERNS; JS's /gi and /gim flags become Elixir's `i`
  # and `im` regex modifiers (there is no Elixir equivalent of `g` to carry
  # over -- `Regex.scan/2` already returns every match).
  @injection_pattern_sources [
    # -- instruction override --------------------------------------------
    {"instruction_override",
     ~r/\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:previous|prior|earlier|above|preceding|all|any)\b[^.\n]{0,30}\b(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions|guideline|guidelines)\b/i},
    {"instruction_override",
     ~r/\b(?:the\s+)?(?:instructions?|prompts?|rules?)\s+(?:above|below|before\s+this)\s+(?:are|is)\s+(?:now\s+)?(?:void|invalid|obsolete|outdated|no\s+longer\s+(?:valid|active|in\s+effect))\b/i},
    {"instruction_override",
     ~r/\bdisregard\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|guidelines?)\b/i},

    # -- role reassignment ------------------------------------------------
    {"role_reassignment", ~r/\byou\s+are\s+(?:now|no\s+longer)\s+(?:a|an|the)\b/i},
    {"role_reassignment",
     ~r/\b(?:from\s+now\s+on|starting\s+now|for\s+the\s+rest\s+of\s+this\s+(?:conversation|session))\b[^.\n]{0,30}\byou\s+(?:are|will|must|should)\b/i},
    {"role_reassignment", ~r/\bnew\s+(?:system\s+)?(?:instructions?|prompt|persona|role)\s*:/i},
    {"role_reassignment",
     ~r/\b(?:enable|enter|activate|switch\s+to)\s+(?:developer|god|dan|jailbreak|unrestricted)\s+mode\b/i},
    {"role_reassignment",
     ~r/\b(?:act|behave|respond|pretend\s+to\s+be)\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+)?(?:dan|unrestricted|unfiltered|uncensored|jailbroken)\b/i},
    {"role_reassignment",
     # A role header smuggled into content -- "system:" / "<|im_start|>system"
     # at the start of a line is a conversation-structure forgery, not prose.
     ~r/^[ \t>*-]*(?:<\|im_start\|>\s*)?(?:system|assistant|developer)\s*(?::|\]|>)/im},

    # -- exfiltration -----------------------------------------------------
    {"exfiltration_url",
     # A markdown image/link whose URL carries the content out as a query
     # parameter -- the classic zero-click exfiltration shape.
     ~r/!?\[[^\]\n]*\]\(\s*https?:\/\/[^)\s]*[?&][^)\s]*(?:data|payload|prompt|content|text|secret|token|key|conversation|history)=[^)\s]*\)/i},
    {"exfiltration_url",
     ~r/\bhttps?:\/\/\S*[?&](?:data|payload|secret|token|api[_-]?key|apikey|password|credential|conversation|history)=/i},
    {"exfiltration_url",
     ~r/\b(?:send|post|upload|forward|transmit|exfiltrate|leak|report)\b[^.\n]{0,60}\bto\s+https?:\/\/\S+/i}
  ]

  @injection_types @injection_pattern_sources
                   |> Enum.map(&elem(&1, 0))
                   |> Enum.uniq()
                   |> Enum.sort()

  @identifier ~r/^[A-Za-z_$][A-Za-z0-9_$]*$/

  @doc "Prefix on every injection finding's `type`."
  @spec injection_heuristic_prefix() :: String.t()
  def injection_heuristic_prefix, do: @injection_heuristic_prefix

  @doc "Identifier of the injection ruleset this module implements."
  @spec injection_ruleset() :: String.t()
  def injection_ruleset, do: @injection_ruleset

  @doc "Distinct injection types the ruleset can emit, for documentation/tests."
  @spec injection_types() :: [String.t()]
  def injection_types, do: @injection_types

  @doc """
  Scan a tool result for PII and prompt injection before it is appended to
  model context. Pure and synchronous: makes no network call and does not
  mutate `payload`.

  Returns `%{sanitized:, findings:, blocked:, reason:}`:

    * `:sanitized` -- the payload with PII masked in place, structurally
      identical otherwise. `nil` when `:blocked` is true -- there is
      deliberately no masked payload to accidentally append.
    * `:findings` -- a list of `%{kind:, type:, count:, location:}` maps.
    * `:blocked` -- true only when `:block_on_injection` is true and at
      least one injection heuristic fired.
    * `:reason` -- set only when `:blocked` is true.

  ## Options

    * `:block_on_injection` -- default `false`. Detect-and-report by
      default; when `true` and an injection pattern matches, `:blocked` is
      `true`, `:reason` is set, and `:sanitized` is `nil`.
    * `:max_depth` -- maximum nesting depth to walk. Deeper values are
      passed through unscanned and unmodified. Default #{@default_max_depth}.

  For the receipt-linked form (`attested_by: "client"`, `capture_mode:
  "edge"`), use `TorkGovernance.scan_tool_result/3`, which wraps this and
  records the scan.
  """
  @spec scan(String.t(), term(), keyword()) :: map()
  def scan(tool_name, payload, opts \\ []) do
    max_depth = Keyword.get(opts, :max_depth, @default_max_depth)
    block_on_injection = Keyword.get(opts, :block_on_injection, false)

    {sanitized, findings} = walk(payload, "$", 0, max_depth, [])

    injection_total = injection_count(findings)
    blocked = block_on_injection && injection_total > 0

    if blocked do
      types =
        findings
        |> Enum.filter(&(&1.kind == :injection))
        |> Enum.map(& &1.type)
        |> Enum.uniq()
        |> Enum.sort()

      reason =
        "Blocked: #{injection_total} prompt-injection heuristic match(es) " <>
          "[#{Enum.join(types, ", ")}] in the result of tool \"#{tool_name}\". " <>
          "These are heuristic pattern matches (#{@injection_ruleset}), not a verified " <>
          "determination. sanitized is nil so no masked copy can be appended to context by accident."

      %{sanitized: nil, findings: findings, blocked: true, reason: reason}
    else
      %{sanitized: sanitized, findings: findings, blocked: false, reason: nil}
    end
  end

  # ==========================================================================
  # Traversal
  # ==========================================================================

  # Strings are always scanned regardless of depth -- matches the JS source,
  # where the string check happens before the depth check.
  defp walk(value, location, _depth, _max_depth, findings) when is_binary(value) do
    scan_string(value, location, findings)
  end

  defp walk(value, _location, depth, max_depth, findings)
       when depth >= max_depth or is_nil(value) or (not is_list(value) and not is_map(value)) do
    {value, findings}
  end

  defp walk(value, location, depth, max_depth, findings) when is_list(value) do
    {items_rev, findings, changed} =
      value
      |> Enum.with_index()
      |> Enum.reduce({[], findings, false}, fn {item, index}, {acc, acc_findings, changed} ->
        {next, acc_findings} = walk(item, "#{location}[#{index}]", depth + 1, max_depth, acc_findings)
        {[next | acc], acc_findings, changed or next !== item}
      end)

    if changed, do: {Enum.reverse(items_rev), findings}, else: {value, findings}
  end

  # Structs (JS: non-plain objects / class instances) pass through
  # untouched -- they fail this guard and fall to the catch-all clause below.
  defp walk(value, location, depth, max_depth, findings) when is_map(value) and not is_struct(value) do
    {pairs_rev, findings, changed} =
      Enum.reduce(value, {[], findings, false}, fn {key, item}, {acc, acc_findings, changed} ->
        {next, acc_findings} = walk(item, child_path(location, key), depth + 1, max_depth, acc_findings)
        {[{key, next} | acc], acc_findings, changed or next !== item}
      end)

    if changed, do: {Map.new(pairs_rev), findings}, else: {value, findings}
  end

  defp walk(value, _location, _depth, _max_depth, findings), do: {value, findings}

  # Scan one string: PII (via the shared detector) then injection heuristics.
  # Returns the masked string plus findings appended, both keyed to `location`.
  defp scan_string(text, location, findings) do
    pii_findings =
      text
      |> PII.detect()
      |> Enum.frequencies_by(& &1.type)
      |> Enum.sort_by(fn {type, _count} -> Atom.to_string(type) end)
      |> Enum.map(fn {type, count} ->
        %{kind: :pii, type: Atom.to_string(type), count: count, location: location}
      end)

    injection_findings =
      @injection_pattern_sources
      |> Enum.reduce(%{}, fn {type, regex}, acc ->
        count = length(Regex.scan(regex, text))
        if count > 0, do: Map.update(acc, type, count, &(&1 + count)), else: acc
      end)
      |> Enum.sort_by(fn {type, _count} -> type end)
      |> Enum.map(fn {type, count} ->
        %{kind: :injection, type: "#{@injection_heuristic_prefix}#{type}", count: count, location: location}
      end)

    {PII.redact(text), findings ++ pii_findings ++ injection_findings}
  end

  defp child_path(parent, key) do
    key_string = to_key_string(key)

    if Regex.match?(@identifier, key_string) do
      "#{parent}.#{key_string}"
    else
      "#{parent}[#{encode_string(key_string)}]"
    end
  end

  defp to_key_string(key) when is_atom(key), do: Atom.to_string(key)
  defp to_key_string(key) when is_binary(key), do: key
  defp to_key_string(key), do: inspect(key)

  defp encode_string(string) do
    if Code.ensure_loaded?(Jason) do
      Jason.encode!(string)
    else
      escaped = string |> String.replace("\\", "\\\\") |> String.replace("\"", "\\\"")
      "\"#{escaped}\""
    end
  end

  # ==========================================================================
  # Receipt block
  # ==========================================================================

  @doc """
  Build the `tool_result_scan` receipt block for a completed scan.

  snake_case keys, `:reason`/`:server_uri` OMITTED from the map entirely
  (not set to `nil`) when absent -- the same discipline the JS/Python SDKs
  use, and for the same reason: it carries COUNTS ONLY. No payload, no
  matched substring, no location path, no tool argument ever appears here.

  Unlike JS (object insertion order) or Python (dict insertion order),
  Elixir maps carry NO iteration-order guarantee -- confirmed empirically:
  this block's 10 atom keys do NOT enumerate alphabetically via `Map.keys/1`,
  they enumerate in whatever order the map's internal hash layout produces.
  The key SET and every value are still exactly parity with JS/Python; only
  "alphabetical" is not a property of this Elixir map itself. A caller that
  needs a deterministically alphabetical wire form (e.g. to hash or diff
  this block byte-for-byte against another SDK's JSON) should use
  `ordered_pairs/1`, which sorts explicitly rather than relying on map
  iteration.
  """
  @spec build_receipt_block(String.t(), map(), String.t(), keyword()) :: map()
  def build_receipt_block(tool_name, result, sdk_version, opts \\ []) do
    server_uri = Keyword.get(opts, :server_uri)

    pii = counts_by_type(result.findings, :pii)
    injection = counts_by_type(result.findings, :injection)

    %{
      attested_by: "client",
      blocked: result.blocked,
      capture_mode: "edge",
      findings: %{injection: injection, pii: pii},
      injection_ruleset: @injection_ruleset
    }
    |> maybe_put(:reason, result.reason)
    |> Map.put(:sdk_language, "elixir")
    |> Map.put(:sdk_version, sdk_version)
    |> maybe_put(:server_uri, server_uri)
    |> Map.put(:tool_name, tool_name)
    |> Map.put(:totals, %{injection: sum_values(injection), pii: sum_values(pii)})
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  @doc """
  The receipt block's fields as a `{key, value}` list sorted alphabetically
  by key name -- the deterministic wire form `build_receipt_block/4` itself
  cannot guarantee (see its doc). Nested `:findings`/`:totals` maps are left
  as-is (their own keys, `injection`/`pii`, are already only two and fixed).
  """
  @spec ordered_pairs(map()) :: [{atom(), term()}]
  def ordered_pairs(block) do
    block
    |> Map.to_list()
    |> Enum.sort_by(fn {key, _value} -> Atom.to_string(key) end)
  end

  defp counts_by_type(findings, kind) do
    findings
    |> Enum.filter(&(&1.kind == kind))
    |> Enum.reduce(%{}, fn %{type: type, count: count}, acc ->
      Map.update(acc, type, count, &(&1 + count))
    end)
  end

  defp sum_values(map), do: map |> Map.values() |> Enum.sum()

  @doc "Distinct PII types in a scan result, for the attestation canonical form."
  @spec pii_types([map()]) :: [String.t()]
  def pii_types(findings) do
    findings |> Enum.filter(&(&1.kind == :pii)) |> Enum.map(& &1.type) |> Enum.uniq() |> Enum.sort()
  end

  @doc "Total PII match count in a scan result."
  @spec pii_count([map()]) :: non_neg_integer()
  def pii_count(findings) do
    findings |> Enum.filter(&(&1.kind == :pii)) |> Enum.map(& &1.count) |> Enum.sum()
  end

  @doc "Total injection match count in a scan result."
  @spec injection_count([map()]) :: non_neg_integer()
  def injection_count(findings) do
    findings |> Enum.filter(&(&1.kind == :injection)) |> Enum.map(& &1.count) |> Enum.sum()
  end

  @doc """
  Canonicalize an arbitrary tool-result payload to a binary suitable for
  hashing on the receipt. Uses `Jason` when loaded (matching what a real
  payload -- typically JSON decoded from an MCP tool result -- would encode
  back to); falls back to `:erlang.term_to_binary/1` otherwise.

  This is NOT a cross-SDK canonical form (unlike the `tool_result_scan`
  block above): it is only ever used as the input to this SDK's own
  `input_hash`/`output_hash`, which no test anywhere compares across SDKs.
  """
  @spec canonicalize(term()) :: binary()
  def canonicalize(term) do
    if Code.ensure_loaded?(Jason) do
      Jason.encode!(term)
    else
      :erlang.term_to_binary(term)
    end
  rescue
    _ -> :erlang.term_to_binary(term)
  end
end
