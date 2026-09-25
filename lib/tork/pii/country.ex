defmodule TorkGovernance.PII.Country do
  @moduledoc """
  The country layer: 24 country profiles, 51 patterns, 20 check digits.

  This implements the seven rules that `generated/sdk-registry/README.md` marks
  **SDK**, from the bundle alone. Bundle 1.1.0 carries the data all seven need
  -- the activation signals, the country map, the three windows, the whole-word
  vocabulary, the near-miss policy, the table constants and the reference
  labels -- so nothing here is hand-written registry data and no window is
  hard-coded.

    1. ACTIVATE   a country's patterns run only when one of its signals fires.
    2. MATCH      the regex, case-sensitively, globally.
    3. KEYWORD    whole-word (symmetric context window) or column verdict or
                  the ASYMMETRIC substring window (60 before, 40 after); then
                  7b may close the gate again.
    4. CHECKSUM   when required. Advisory checksums never reject.
    5. SUPERSEDE  a match containing every range it overlaps takes them.
    6. NEAR MISS  a checksum-failing identifier is redacted generically.
    7. COLUMN     in a delimited table a bare value cell is judged by its header.
    7b. NEAREST LABEL  a closer commercial label closes the gate.

  Still cloud-only, by design: the universal (L0) patterns, the slot, context,
  gravity and name layers, industry profiles and org configuration.

  Offsets are BYTE offsets, matching `Regex.scan/3` with `return: :index`.
  """

  alias Tork.Governance.Pii.Registry
  alias TorkGovernance.PII.Checksums

  @doc "Characters before a match that count as nearby for the substring gate."
  def keyword_window_before, do: Registry.keyword_window_before()
  @doc "Characters after. Deliberately NOT the same number as before."
  def keyword_window_after, do: Registry.keyword_window_after()
  @doc "The symmetric window: whole-word keywords and the near-miss gate."
  def context_window, do: Registry.context_window()

  # ── compiled once, cached in :persistent_term ───────────────────────────────

  defp cache do
    case :persistent_term.get({__MODULE__, :cache}, nil) do
      nil ->
        patterns = Registry.patterns()
        signals = Registry.signals()

        built = %{
          patterns: Map.new(patterns, fn p -> {p.name, Regex.compile!(p.regex)} end),
          by_name: Map.new(patterns, fn p -> {p.name, p} end),
          signals:
            Enum.map(signals, fn s ->
              opts = if String.contains?(s.flags, "i"), do: [:caseless], else: []
              Regex.compile!(s.regex, opts)
            end),
          signal_order: signals |> Enum.map(& &1.country) |> Enum.uniq(),
          country_patterns: Map.new(Registry.countries(), fn c -> {c.code, c.patterns} end),
          generic: MapSet.new(Registry.generic_id_keywords()),
          national_id_words: Registry.generic_id_keywords() ++ Registry.local_id_keywords()
        }

        :persistent_term.put({__MODULE__, :cache}, built)
        built

      cached ->
        cached
    end
  end

  defp slice(content, from, len) when len > 0, do: :binary.part(content, from, len)
  defp slice(_content, _from, _len), do: ""

  defp lower_window(content, lo, hi) do
    lo = max(lo, 0)
    hi = min(hi, byte_size(content))
    if hi > lo, do: content |> slice(lo, hi - lo) |> String.downcase(), else: ""
  end

  defp alnum?(<<c>>) when c in ?a..?z or c in ?0..?9 or c in ?A..?Z, do: true
  defp alnum?(_), do: false

  @doc false
  def all_keywords_of(%{keywords: k, whole_word_keywords: []}), do: k
  def all_keywords_of(%{keywords: k, whole_word_keywords: w}), do: k ++ w

  @doc false
  def specific_keywords(keywords) do
    generic = cache().generic
    Enum.reject(keywords, &MapSet.member?(generic, &1))
  end

  @doc "Rule 3, substring half: ASYMMETRIC -- 60 before the match, 40 after it."
  def has_nearby_context?(content, start, stop, keywords) do
    before = lower_window(content, start - keyword_window_before(), start)
    after_ = lower_window(content, stop, stop + keyword_window_after())
    Enum.any?(keywords, &(String.contains?(before, &1) or String.contains?(after_, &1)))
  end

  @doc "Symmetric context window either side, substring. Used by rule 6."
  def has_context_around?(content, start, stop, keywords) do
    w = lower_window(content, start - context_window(), stop + context_window())
    Enum.any?(keywords, &String.contains?(w, &1))
  end

  @doc """
  Rule 3, whole-word half: symmetric context window, a boundary each side,
  a boundary being "not a letter or digit".

  This is the gate Indonesia needs: `nik` sits inside *teknik*, *elektronik*,
  *klinik* and *pabrik*, so a substring test would open the gate on a ledger.
  """
  def has_whole_word_context_around?(_content, _start, _stop, []), do: false
  def has_whole_word_context_around?(_content, _start, _stop, nil), do: false

  def has_whole_word_context_around?(content, start, stop, words) do
    w = lower_window(content, start - context_window(), stop + context_window())
    Enum.any?(words, &whole_word_in?(w, &1, 0))
  end

  defp whole_word_in?(window, word, from) do
    rest = if from <= byte_size(window), do: slice(window, from, byte_size(window) - from), else: ""

    case :binary.match(rest, word) do
      :nomatch ->
        false

      {rel, len} ->
        i = from + rel
        before_ok = i == 0 or not alnum?(slice(window, i - 1, 1))
        j = i + len
        after_ok = j >= byte_size(window) or not alnum?(slice(window, j, 1))
        if before_ok and after_ok, do: true, else: whole_word_in?(window, word, i + 1)
    end
  end

  defp document_has_whole_word?(_content, []), do: false
  defp document_has_whole_word?(content, words),
    do: has_whole_word_context_around?(content, 0, byte_size(content), words)

  # ── rule 1: activation ──────────────────────────────────────────────────────

  @doc "The countries this text activates, in the bundle's signal order."
  def infer_regions(content) do
    c = cache()
    lower = String.downcase(content)
    signals = Registry.signals() |> Enum.with_index()

    Enum.reduce(c.signal_order, [], fn code, regions ->
      signals
      |> Enum.filter(fn {s, _i} -> s.country == code end)
      |> Enum.reduce_while(regions, fn {s, i}, acc ->
        cond do
          not Regex.match?(Enum.at(c.signals, i), content) ->
            {:cont, acc}

          true ->
            by_substring = s.keywords != [] and Enum.any?(s.keywords, &String.contains?(lower, &1))
            by_whole_word = document_has_whole_word?(content, s.whole_word_keywords)

            # Both lists empty means the shape alone is distinctive enough.
            if (s.keywords != [] or s.whole_word_keywords != []) and
                 not by_substring and not by_whole_word do
              {:cont, acc}
            else
              target = if s.activates == "", do: code, else: s.activates
              # one signal per country is enough
              {:halt, if(target in acc, do: acc, else: acc ++ [target])}
            end
        end
      end)
    end)
  end

  @doc """
  The patterns those regions switch on, plus the bundle's `alwaysOn` patterns,
  de-duplicated, in registry order.

  Rule 1a: `alwaysOn` patterns (today: `au_tfn`, `au_abn`, `au_medicare`) are
  not gated by region activation and run before the activated country
  patterns, so an activated pattern can still supersede one of them under
  rule 5.
  """
  def patterns_for_regions(regions) do
    c = cache()

    always_on = Enum.filter(Registry.patterns(), & &1.always_on)

    activated =
      regions
      |> Enum.flat_map(fn code -> Map.get(c.country_patterns, String.upcase(code), []) end)
      |> Enum.uniq()
      |> Enum.map(&Map.get(c.by_name, &1))
      |> Enum.reject(&is_nil/1)

    (always_on ++ activated) |> Enum.uniq_by(& &1.name)
  end

  # ── rule 7: the column is the context ───────────────────────────────────────

  defp looks_like_header?(cells, delimiter) do
    minimum = if delimiter == ",", do: Registry.table_min_comma_columns(), else: 2

    length(cells) >= minimum and
      Enum.all?(cells, fn cell ->
        t = String.trim(cell)

        t != "" and byte_size(t) <= Registry.table_max_header_length() and
          Regex.match?(~r/[A-Za-z\x{00C0}-\x{FFFF}]/u, t) and
          not Regex.match?(~r/^\+?[\d\s.\-\/]+$/, t) and
          not Regex.match?(~r/[.?!]/, t) and
          length(String.split(t, ~r/\s+/)) <= Registry.table_max_header_words()
      end)
  end

  @doc "The cells of `content`, when it is a delimited table with a header row."
  def table_scopes(content) do
    lines = String.split(content, "\n")

    if length(lines) < Registry.table_min_rows() do
      []
    else
      do_scopes(content, lines)
    end
  end

  defp do_scopes(_content, lines) do
    offsets =
      lines
      |> Enum.reduce({[], 0}, fn line, {acc, at} -> {[at | acc], at + byte_size(line) + 1} end)
      |> elem(0)
      |> Enum.reverse()

    Enum.reduce_while(Registry.table_delimiters(), [], fn delimiter, _ ->
      header_cells = String.split(hd(lines), delimiter)

      if not looks_like_header?(header_cells, delimiter) do
        {:cont, []}
      else
        width = length(header_cells)

        data_rows =
          lines
          |> Enum.with_index()
          |> Enum.drop(1)
          |> Enum.reject(fn {l, _} -> String.trim(l) == "" end)

        cond do
          Enum.any?(data_rows, fn {l, _} -> length(String.split(l, delimiter)) != width end) ->
            {:halt, []}

          length(data_rows) < Registry.table_min_rows() - 1 ->
            {:cont, []}

          true ->
            {:halt,
             Enum.flat_map(data_rows, fn {line, row} ->
               cells = String.split(line, delimiter)
               row_start = Enum.at(offsets, row)
               row_end = row_start + byte_size(line)

               cells
               |> Enum.with_index()
               |> Enum.reduce({[], row_start}, fn {cell, col}, {acc, cell_start} ->
                 scope = %{
                   start: cell_start,
                   end: cell_start + byte_size(cell),
                   header: header_cells |> Enum.at(col) |> String.trim() |> String.downcase(),
                   row_start: row_start,
                   row_end: row_end
                 }

                 {[scope | acc], cell_start + byte_size(cell) + byte_size(delimiter)}
               end)
               |> elem(0)
               |> Enum.reverse()
             end)}
        end
      end
    end)
  end

  @doc "A whole-word match, not a substring."
  def header_names?(header, keywords) do
    Enum.any?(keywords, fn kw ->
      case :binary.match(header, kw) do
        :nomatch ->
          false

        {i, len} ->
          before_ok = i == 0 or not alnum?(slice(header, i - 1, 1))
          j = i + len
          after_ok = j >= byte_size(header) or not alnum?(slice(header, j, 1))
          before_ok and after_ok
      end
    end)
  end

  @doc "nil when the window should be consulted as usual."
  def column_verdict(_content, [], _start, _stop, _all, _specific), do: nil

  def column_verdict(content, scopes, start, stop, all, specific) do
    case Enum.find(scopes, fn s -> start >= s.start and stop <= s.end end) do
      nil ->
        nil

      cell ->
        # A cell whose own row names the identifier is prose in a delimited block.
        row_text = lower_window(content, cell.row_start, cell.row_end)

        if Enum.any?(all, &String.contains?(row_text, &1)),
          do: nil,
          else: specific != [] and header_names?(cell.header, specific)
    end
  end

  # ── rule 7b: nearest label wins ─────────────────────────────────────────────

  defp closest_before(before, keywords) do
    keywords
    |> Enum.map(fn kw ->
      case :binary.matches(before, kw) do
        [] -> nil
        ms -> ms |> List.last() |> then(fn {i, len} -> byte_size(before) - (i + len) end)
      end
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.min(fn -> nil end)
  end

  defp closest_after(after_, keywords) do
    keywords
    |> Enum.map(fn kw ->
      case :binary.match(after_, kw) do
        :nomatch -> nil
        {i, _} -> i
      end
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.min(fn -> nil end)
  end

  @doc """
  Whether the number is labelled as a commercial reference more closely than as
  an identifier. It can only ever close a gate, never open one.
  """
  def labelled_as_reference?(content, start, stop, identifier_keywords) do
    before = lower_window(content, start - Registry.label_window(), start)
    ref = closest_before(before, Registry.reference_labels())

    cond do
      is_nil(ref) or ref > Registry.label_reach() ->
        false

      identifier_keywords in [nil, []] ->
        true

      true ->
        id_before = closest_before(before, identifier_keywords)
        after_ = lower_window(content, stop, stop + Registry.label_window())
        id_after = closest_after(after_, identifier_keywords)

        cond do
          not is_nil(id_before) and id_before <= ref -> false
          not is_nil(id_after) and id_after <= ref -> false
          true -> true
        end
    end
  end

  # ── the pass ────────────────────────────────────────────────────────────────

  @doc "The span with leading and trailing non-alphanumeric characters removed."
  def trimmed_core(content, start, stop) do
    s = advance(content, start, stop)
    e = retreat(content, s, stop)
    if s == e, do: {start, stop}, else: {s, e}
  end

  defp advance(content, s, e) when s < e do
    if alnum?(slice(content, s, 1)), do: s, else: advance(content, s + 1, e)
  end

  defp advance(_content, s, _e), do: s

  defp retreat(content, s, e) when e > s do
    if alnum?(slice(content, e - 1, 1)), do: e, else: retreat(content, s, e - 1)
  end

  defp retreat(_content, _s, e), do: e

  @doc """
  Country matches for `content`, de-overlapped and ordered by position.

  `patterns` bypasses activation; `existing_ranges` are your own L0 spans, so
  rule 5 can supersede them. Returns `{matches, superseded_ranges}`.
  """
  def detect_with_ranges(content, patterns \\ nil, existing_ranges \\ []) do
    active = patterns || patterns_for_regions(infer_regions(content))

    if active == [] do
      {[], []}
    else
      c = cache()
      tables = table_scopes(content)

      state = %{
        existing: existing_ranges,
        superseded: [],
        claimed: [],
        found: [],
        near: []
      }

      state =
        Enum.reduce(active, state, fn pattern, acc ->
          Regex.scan(Map.fetch!(c.patterns, pattern.name), content, return: :index)
          |> Enum.reduce(acc, fn [{start, len} | _], st ->
            if len == 0, do: st, else: consider(content, tables, pattern, start, start + len, st, c)
          end)
        end)

      # Rule 6, last: a near miss can only ever fill a hole.
      taken = state.existing ++ state.claimed

      {found, _} =
        Enum.reduce(state.near, {state.found, taken}, fn {cs, ce}, {found, taken} ->
          if Enum.any?(taken, fn {rs, re} -> cs < re and ce > rs end) do
            {found, taken}
          else
            {found ++
               [
                 %{
                   name: Registry.near_miss_type(),
                   country: "",
                   label: "NATIONAL_ID",
                   type: Registry.near_miss_type(),
                   redaction: Registry.near_miss_redaction(),
                   start_index: cs,
                   end_index: ce
                 }
               ], [{cs, ce} | taken]}
          end
        end)

      {Enum.sort_by(found, & &1.start_index), Enum.reverse(state.superseded)}
    end
  end

  defp consider(content, tables, pattern, start, stop, st, c) do
    cond do
      # Rules 3, 7 and 7b.
      pattern.requires_keyword and pattern.keywords != [] and
          not gate_open?(content, tables, pattern, start, stop) ->
        st

      pattern.requires_keyword and pattern.keywords != [] and
          labelled_as_reference?(content, start, stop, pattern.keywords) ->
        st

      true ->
        checksum_stage(content, pattern, start, stop, st, c)
    end
  end

  defp gate_open?(content, tables, pattern, start, stop) do
    all = all_keywords_of(pattern)

    has_whole_word_context_around?(content, start, stop, pattern.whole_word_keywords) or
      case column_verdict(content, tables, start, stop, all, specific_keywords(all)) do
        nil -> has_nearby_context?(content, start, stop, pattern.keywords)
        verdict -> verdict
      end
  end

  defp checksum_stage(content, pattern, start, stop, st, c) do
    text = slice(content, start, stop - start)

    fails =
      pattern.checksum_required and not is_nil(pattern.checksum) and
        (case Map.get(Checksums.functions(), pattern.checksum) do
           nil -> false
           fun -> not fun.(text)
         end)

    if fails do
      if pattern.near_miss_fallback do
        extra =
          if pattern.near_miss_keywords != [],
            do: pattern.near_miss_keywords,
            else: pattern.keywords

        vocabulary = c.national_id_words ++ extra

        if has_context_around?(content, start, stop, vocabulary),
          do: %{st | near: st.near ++ [{start, stop}]},
          else: st
      else
        st
      end
    else
      supersede(content, pattern, start, stop, st)
    end
  end

  # Rule 5.
  defp supersede(content, pattern, start, stop, st) do
    overlapping =
      Enum.filter(st.existing ++ st.claimed, fn {rs, re} -> start < re and stop > rs end)

    supersedes_all? =
      Enum.all?(overlapping, fn {rs, re} ->
        {cs, ce} = trimmed_core(content, rs, re)
        start <= cs and stop >= ce
      end)

    cond do
      overlapping != [] and not supersedes_all? ->
        st

      true ->
        st =
          Enum.reduce(overlapping, st, fn o, acc ->
            in_existing? = o in acc.existing

            %{
              acc
              | existing: List.delete(acc.existing, o),
                superseded: if(in_existing?, do: [o | acc.superseded], else: acc.superseded),
                claimed: List.delete(acc.claimed, o),
                found:
                  Enum.reject(acc.found, fn f ->
                    {f.start_index, f.end_index} == o
                  end)
            }
          end)

        %{
          st
          | claimed: st.claimed ++ [{start, stop}],
            found:
              st.found ++
                [
                  %{
                    name: pattern.name,
                    country: pattern.country,
                    label: pattern.label,
                    type: pattern.type,
                    redaction: pattern.redaction,
                    start_index: start,
                    end_index: stop
                  }
                ]
        }
    end
  end

  @doc "Country matches for `content`."
  def detect(content, patterns \\ nil) do
    {matches, _} = detect_with_ranges(content, patterns)
    matches
  end

  @doc """
  Replace every span with its redaction, right to left.

  Right to left is what keeps the earlier indices valid, and splicing whole
  spans in one pass is what guarantees no partial redaction: a digit can never
  be left standing beside a redaction token, because nothing is ever matched
  against text a previous replacement has already rewritten.
  """
  def apply_redactions(text, []), do: text

  def apply_redactions(text, spans) do
    spans
    |> Enum.sort_by(& &1.start_index)
    |> Enum.reverse()
    |> Enum.reduce(text, fn s, acc ->
      slice(acc, 0, s.start_index) <>
        s.redaction <> slice(acc, s.end_index, byte_size(acc) - s.end_index)
    end)
  end
end
