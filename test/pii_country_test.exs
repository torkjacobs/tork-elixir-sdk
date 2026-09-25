defmodule TorkGovernance.PII.CountryTest do
  @moduledoc """
  Country-layer parity tests.

  The fixtures are generated from the cloud's own evidence, not written here:

    `pii_unit_cases.json`  one valid sample per registry pattern, a
                           checksum-broken variant for each pattern whose
                           checksum is a gate, and the Indonesian boundary cases.
    `pii_vectors.json`     all 2,092 inputs of the cloud's golden snapshot:
                           every country-corpus sentence for all 249 ISO
                           jurisdictions, and the whole 1,523-line business
                           false-positive corpus.

  `expectedOutput` is the COUNTRY LAYER alone. Where the cloud's own output
  differs, the case carries `cloudOutput` and a `divergence` naming the cause.
  """

  use ExUnit.Case, async: true

  alias Tork.Governance.Pii.Registry
  alias TorkGovernance.PII.Checksums
  alias TorkGovernance.PII.Country

  @nik "3171010101900001"

  defp fixture(name) do
    Path.join([__DIR__, "fixtures", name]) |> File.read!() |> Jason.decode!()
  end

  defp vectors, do: fixture("pii_vectors.json")
  defp redact(s), do: Country.apply_redactions(s, Country.detect(s))

  # ── the bundle ──────────────────────────────────────────────────────────────

  test "is the version and content the fixtures were generated from" do
    v = vectors()
    assert Registry.version() == v["bundleVersion"]
    assert Registry.content_hash() == v["contentHash"]
  end

  test "carries 54 patterns across 24 profiles, with 51 activation signals" do
    # 54, not 51: bundle 1.2.0 added the three alwaysOn AU patterns
    # (au_tfn, au_abn, au_medicare) without adding new activation signals --
    # they are not gated by activation at all. See "rule 1a" tests below.
    assert length(Registry.patterns()) == 54
    assert length(Registry.countries()) == 24
    assert length(Registry.signals()) == 51
  end

  test "covers Indonesia, added in 1.1.0" do
    id = Enum.find(Registry.countries(), &(&1.code == "ID"))
    assert id, "Indonesia is missing from the bundle"
    assert "id_nik" in id.patterns
    nik = Enum.find(Registry.patterns(), &(&1.name == "id_nik"))
    assert nik.label == "NIK"
    assert "nik" in nik.whole_word_keywords
  end

  test "reads its windows from the bundle, and they are not all the same number" do
    assert Country.keyword_window_before() == 60
    assert Country.keyword_window_after() == 40
    assert Country.context_window() == 60
    refute Country.keyword_window_before() == Country.keyword_window_after()
  end

  test "names a checksum function for every pattern that declares one" do
    fns = Checksums.functions()

    for p <- Registry.patterns(), p.checksum do
      assert is_function(Map.get(fns, p.checksum)), "#{p.name} -> #{p.checksum}"
    end
  end

  test "uses only the portable regex subset" do
    forbidden = [
      {"(?=", "lookahead"},
      {"(?!", "negative lookahead"},
      {"(?<=", "lookbehind"},
      {"(?<!", "negative lookbehind"},
      {"\\p{", "unicode property escape"},
      {"(?>", "atomic group"}
    ]

    sources =
      Enum.map(Registry.patterns(), & &1.regex) ++ Enum.map(Registry.signals(), & &1.regex)

    for src <- sources, {bad, why} <- forbidden do
      refute String.contains?(src, bad), "#{src} uses #{why}"
    end
  end

  # ── per-pattern unit cases ──────────────────────────────────────────────────

  test "per-pattern unit cases detect or reject as the cloud does" do
    by_name = Map.new(Registry.patterns(), &{&1.name, &1})
    cases = fixture("pii_unit_cases.json")
    assert cases != []

    for c <- cases do
      pattern = Map.get(by_name, c["pattern"])
      assert pattern, "#{c["pattern"]} is not in the bundle"
      hit = c["input"] |> Country.detect([pattern]) |> Enum.find(&(&1.name == c["pattern"]))

      if c["expectDetected"] do
        assert hit, "expected #{c["pattern"]} to match #{inspect(c["input"])}"
        assert binary_part(c["input"], hit.start_index, hit.end_index - hit.start_index) == c["sample"]
        assert hit.redaction == c["redaction"]
      else
        refute hit, "expected #{c["pattern"]} NOT to match #{inspect(c["input"])}"
      end
    end
  end

  # ── golden-snapshot parity ──────────────────────────────────────────────────

  test "reproduces the cloud on every corpus vector" do
    corpus = Enum.reject(vectors()["cases"], &(&1["kind"] == "business-fp"))
    assert length(corpus) > 500

    failures =
      Enum.flat_map(corpus, fn c ->
        matches = Country.detect(c["input"])
        out = Country.apply_redactions(c["input"], matches)
        regions = Country.infer_regions(c["input"])
        labels = matches |> Enum.map(& &1.label) |> Enum.uniq()
        names = matches |> Enum.map(& &1.name) |> Enum.uniq()

        []
        |> then(&if regions == c["expectedRegions"], do: &1, else: ["#{c["id"]} activation" | &1])
        |> then(&if out == c["expectedOutput"], do: &1, else: ["#{c["id"]} redaction" | &1])
        |> then(&if labels == c["expectedLabels"], do: &1, else: ["#{c["id"]} labels" | &1])
        |> then(&if names == c["expectedNames"], do: &1, else: ["#{c["id"]} names" | &1])
      end)

    assert failures == []
  end

  test "adds no false positive to the business corpus" do
    business = Enum.filter(vectors()["cases"], &(&1["kind"] == "business-fp"))
    assert length(business) > 1500
    assert Enum.filter(business, &(Country.detect(&1["input"]) != [])) |> Enum.map(& &1["id"]) == []
  end

  test "reproduces the cloud activation on every business-corpus line" do
    business = Enum.filter(vectors()["cases"], &(&1["kind"] == "business-fp"))

    bad =
      business
      |> Enum.reject(&(Country.infer_regions(&1["input"]) == &1["expectedRegions"]))
      |> Enum.map(& &1["id"])

    assert bad == []
  end

  test "diverges from the cloud for one stated reason only, now the bundle gap is closed" do
    diverged = Enum.filter(vectors()["cases"], & &1["divergence"])

    for c <- diverged do
      assert String.starts_with?(c["divergence"], "L0:") or
               String.starts_with?(c["divergence"], "BUNDLE GAP:"),
             "#{c["id"]}: unexplained divergence"
    end

    # Bundle 1.2.0 ships au_tfn, au_abn and au_medicare as `alwaysOn`
    # patterns (see country.ex `patterns_for_regions/1`), so this SDK now
    # reproduces every au_tfn/au_abn/au_medicare corpus case from the country
    # layer alone -- no BUNDLE GAP divergence should remain.
    gaps =
      diverged
      |> Enum.filter(&String.starts_with?(&1["divergence"], "BUNDLE GAP:"))
      |> Enum.map(&(&1["id"] |> String.split("/") |> Enum.at(1)))
      |> Enum.uniq()
      |> Enum.sort()

    assert gaps == []
  end

  test "nothing is ever partially redacted" do
    for c <- vectors()["cases"] do
      matches = Country.detect(c["input"])
      out = Country.apply_redactions(c["input"], matches)
      refute out =~ ~r/\d\[[A-Z_]+_REDACTED\]|\[[A-Z_]+_REDACTED\]\d/, c["id"]

      for m <- matches do
        raw = binary_part(c["input"], m.start_index, m.end_index - m.start_index)
        refute String.contains?(out, raw), "#{c["id"]}: #{raw} survived"
      end
    end
  end

  # ── Indonesia, the rule 1.1.0 added ─────────────────────────────────────────

  test "detects the short spelling, which is a whole-word keyword only" do
    s = "NIK #{@nik} untuk pendaftaran rekening di Jakarta, Indonesia."
    assert Country.infer_regions(s) == ["ID"]
    assert redact(s) == "NIK [NIK_REDACTED] untuk pendaftaran rekening di Jakarta, Indonesia."
  end

  test "detects the long spelling, which is an ordinary substring keyword" do
    assert redact("Nomor Induk Kependudukan #{@nik} untuk pendaftaran.") =~ "[NIK_REDACTED]"
  end

  test "does NOT open the gate on nik inside an ordinary Indonesian word" do
    for word <- ["teknik", "elektronik", "klinik", "pabrik", "piknik"] do
      assert Country.detect("Faktur #{word} #{@nik} untuk pelanggan.") == [],
             "#{word} opened the gate"
    end
  end

  test "a bare NIK with no label is not redacted" do
    assert Country.detect(@nik) == []
  end

  # ── the rules 1.1.0 added to the SDK half of the contract ───────────────────

  test "rule 6: a checksum-failing identifier is redacted generically, not released" do
    out = redact("South African ID number 8001015009088 for the FICA check.")
    refute out =~ "8001015009088"
    assert out =~ "[NATIONAL_ID_REDACTED]"
  end

  test "rule 7: a column header is the context for a bare value cell" do
    csv =
      Enum.join(
        [
          "Name,CNIC,City",
          "Ali,42201-1234567-1,Karachi",
          "Sana,42201-7654321-2,Lahore",
          "Omar,42201-1111111-3,Multan"
        ],
        "\n"
      )

    assert Country.table_scopes(csv) != []
    refute redact(csv) =~ "42201-1234567-1"
  end

  test "rule 7: a generic header does NOT act as context" do
    csv =
      Enum.join(
        [
          "Name,Order ID Number,City",
          "Ali,42201-1234567-1,Karachi",
          "Sana,42201-7654321-2,Lahore",
          "Omar,42201-1111111-3,Multan"
        ],
        "\n"
      )

    assert Country.detect(csv) == []
  end

  test "rule 7b: a commercial label closer than the identifier word closes the gate" do
    s = "Please do not send your CNIC. Use the job number 4220112345671."
    at = :binary.match(s, "4220112345671") |> elem(0)
    assert Country.labelled_as_reference?(s, at, at + 13, ["cnic"])
    assert redact(s) =~ "4220112345671"
  end

  test "rule 7b can only ever close a gate, never open one" do
    assert Country.detect("Order 12345678901234 with no identifier word anywhere.") == []
  end

  test "rule 5: a country match supersedes a wider L0 range it contains" do
    s = "CPF 529.982.247-25 para a nota fiscal no Brasil."
    at = :binary.match(s, "529.982.247-25") |> elem(0)
    {matches, superseded} = Country.detect_with_ranges(s, nil, [{at - 1, at + 14}])
    assert Enum.any?(matches, &(&1.name == "br_cpf"))
    assert length(superseded) == 1
  end

  test "whole-word matching respects a boundary at each end" do
    assert Country.has_whole_word_context_around?("nik 123", 4, 7, ["nik"])
    refute Country.has_whole_word_context_around?("teknik 123", 7, 10, ["nik"])
  end

  # ── rule 1a: alwaysOn, added in 1.2.0 ────────────────────────────────────────
  #
  # au_tfn, au_abn and au_medicare run on every document, unconditionally --
  # not gated by Australia's own activation signals. The ABN's own corpus
  # sentence activates no region at all (see generated/sdk-registry/README.md,
  # rule 1a), so a bug that only wired these through `patterns_for_regions`'s
  # activation path would never catch that sentence.

  test "au_tfn: valid, fires with no region activated by the sentence itself" do
    # "tax number" is one of au_tfn's own gating keywords but, unlike "tfn" and
    # "tax file", is NOT one of AU's activation-signal keywords -- so this
    # sentence only detects at all if alwaysOn bypasses region activation.
    s = "Please quote your tax number 434 900 003 on the form."
    assert Country.infer_regions(s) == []
    assert redact(s) == "Please quote your tax number [TFN_REDACTED] on the form."
  end

  test "au_tfn: checksum-failing is a near miss, not released and not a false negative" do
    s = "Please quote your tax number 434 900 004 on the form."
    out = redact(s)
    refute out =~ "434 900 004"
    assert out =~ "[NATIONAL_ID_REDACTED]"
  end

  test "au_abn: valid, fires with no region activated by the sentence itself" do
    s = "Supplier ABN 51 824 753 556 appears on the Australian invoice."
    assert Country.infer_regions(s) == []
    assert redact(s) == "Supplier ABN [ABN_REDACTED] appears on the Australian invoice."
  end

  test "au_abn: checksum-failing is dropped, not a near miss -- a company number, not a person" do
    s = "Supplier ABN 51 824 753 557 appears on the Australian invoice."
    assert redact(s) == s
  end

  test "au_medicare: valid, fires with no region activated by the sentence itself" do
    # Unspaced, so the digits alone don't also match AU's shape-only,
    # keyword-less activation signal (\d{4}\s\d{5}\s\d{1} -- mandatory
    # spaces) -- keeping this a clean test of the alwaysOn bypass rather
    # than of ordinary country activation.
    s = "Medicare number 2934500011 for the claim."
    assert Country.infer_regions(s) == []
    assert redact(s) == "Medicare number [MEDICARE_REDACTED] for the claim."
  end

  test "au_medicare: checksum is advisory and never blocks detection" do
    s = "Medicare number 2934500021 for the claim."
    out = redact(s)
    refute out =~ "2934500021"
    assert out =~ "[MEDICARE_REDACTED]"
  end

  test "alwaysOn patterns are in patterns_for_regions/1 for every region set, including none" do
    always_on_names = Registry.patterns() |> Enum.filter(& &1.always_on) |> Enum.map(& &1.name)
    assert Enum.sort(always_on_names) == ["au_abn", "au_medicare", "au_tfn"]

    for regions <- [[], ["AU"], ["ZA"]] do
      names = Country.patterns_for_regions(regions) |> Enum.map(& &1.name)
      assert Enum.all?(always_on_names, &(&1 in names)), "missing for regions #{inspect(regions)}"
    end
  end
end
