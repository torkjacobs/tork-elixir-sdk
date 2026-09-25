defmodule TorkGovernance.PII.Checksums do
  @moduledoc """
  Check digits for the country registry.

  The SDK bundle NAMES twenty algorithms and gives weights and a modulus for the
  eleven that reduce to them; the other nine are marked `kind: "custom"` and
  carry no specification, so they are ported here by hand from the cloud's
  `lib/pii/checksums.ts` -- the single implementation the cloud and the country
  corpus both use. Keeping the arithmetic identical is what makes a receipt
  block from this SDK byte-identical to one from the JavaScript SDK.

  Every function is pure: a binary in, a boolean out. No I/O, no clock.
  """

  @digits ~r/\D/

  defp digits_of(s), do: Regex.replace(@digits, s, "")

  defp digit_list(s), do: s |> digits_of() |> String.to_charlist() |> Enum.map(&(&1 - ?0))

  # Remainder of a long decimal digit string modulo m, digit by digit.
  defp mod_digits(digits, m) do
    digits
    |> String.to_charlist()
    |> Enum.reduce(0, fn ch, acc -> rem(acc * 10 + (ch - ?0), m) end)
  end

  defp all_same_digit([]), do: false
  defp all_same_digit([h | t]), do: Enum.all?(t, &(&1 == h))

  defp stripped_upper(s) do
    s |> String.replace(~r/\s/, "") |> String.upcase()
  end

  @doc "Luhn / ISO-IEC 7812-1 mod-10."
  @spec luhn(String.t()) :: boolean()
  def luhn(input) do
    d = digit_list(input)

    if length(d) < 2 do
      false
    else
      {sum, _} =
        d
        |> Enum.reverse()
        |> Enum.reduce({0, false}, fn n, {sum, dbl} ->
          n = if dbl, do: (if n * 2 > 9, do: n * 2 - 9, else: n * 2), else: n
          {sum + n, not dbl}
        end)

      rem(sum, 10) == 0
    end
  end

  @verhoeff_mul {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
    {1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
    {2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
    {3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
    {4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
    {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
    {6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
    {7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
    {8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
    {9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
  }

  @verhoeff_perm {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
    {1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
    {5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
    {8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
    {9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
    {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
    {2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
    {7, 0, 4, 6, 9, 1, 3, 2, 5, 8}
  }

  @doc "Verhoeff, the Aadhaar check digit (UIDAI Circular No. 1 of 2018)."
  @spec verhoeff(String.t()) :: boolean()
  def verhoeff(input) do
    input
    |> digit_list()
    |> Enum.reverse()
    |> Enum.with_index()
    |> Enum.reduce(0, fn {digit, i}, c ->
      p = elem(elem(@verhoeff_perm, rem(i, 8)), digit)
      elem(elem(@verhoeff_mul, c), p)
    end)
    |> Kernel.==(0)
  end

  defp weighted(d, weights), do: Enum.zip(d, weights) |> Enum.map(fn {x, w} -> x * w end) |> Enum.sum()

  @doc "Australian TFN (ATO): weights 1,4,3,7,5,8,6,9,10, sum mod 11 == 0."
  @spec au_tfn(String.t()) :: boolean()
  def au_tfn(input) do
    d = digit_list(input)
    length(d) == 9 and rem(weighted(d, [1, 4, 3, 7, 5, 8, 6, 9, 10]), 11) == 0
  end

  @doc "Australian ABN (ABR): subtract 1 from the first digit, weights 10,1,3..19, mod 89."
  @spec au_abn(String.t()) :: boolean()
  def au_abn(input) do
    d = digit_list(input)

    if length(d) != 11 do
      false
    else
      [first | rest] = d
      rem(weighted([first - 1 | rest], [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19]), 89) == 0
    end
  end

  @doc "Australian Medicare card number (Services Australia)."
  @spec au_medicare(String.t()) :: boolean()
  def au_medicare(input) do
    d = digit_list(input)

    cond do
      length(d) < 10 -> false
      Enum.at(d, 0) not in 2..6 -> false
      true -> rem(weighted(Enum.take(d, 8), [1, 3, 7, 9, 1, 3, 7, 9]), 10) == Enum.at(d, 8)
    end
  end

  @doc "UK NHS number (NHS Data Model and Dictionary): weights 10..2, check = 11 - (sum mod 11)."
  @spec uk_nhs(String.t()) :: boolean()
  def uk_nhs(input) do
    d = digit_list(input)

    if length(d) != 10 do
      false
    else
      sum = weighted(Enum.take(d, 9), Enum.to_list(10..2//-1))
      check = 11 - rem(sum, 11)
      check = if check == 11, do: 0, else: check
      check != 10 and check == Enum.at(d, 9)
    end
  end

  @doc "Brazil CPF (Receita Federal): two sequential mod-11 check digits."
  @spec br_cpf(String.t()) :: boolean()
  def br_cpf(input) do
    d = digit_list(input)

    if length(d) != 11 or all_same_digit(d) do
      false
    else
      calc = fn len ->
        sum =
          Enum.take(d, len)
          |> Enum.with_index()
          |> Enum.map(fn {x, i} -> x * (len + 1 - i) end)
          |> Enum.sum()

        r = rem(sum * 10, 11)
        if r == 10, do: 0, else: r
      end

      calc.(9) == Enum.at(d, 9) and calc.(10) == Enum.at(d, 10)
    end
  end

  @doc "Brazil CNPJ (Receita Federal): two mod-11 check digits with different weight vectors."
  @spec br_cnpj(String.t()) :: boolean()
  def br_cnpj(input) do
    d = digit_list(input)

    if length(d) != 14 or all_same_digit(d) do
      false
    else
      calc = fn weights ->
        r = rem(weighted(d, weights), 11)
        if r < 2, do: 0, else: 11 - r
      end

      calc.([5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]) == Enum.at(d, 12) and
        calc.([6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]) == Enum.at(d, 13)
    end
  end

  @doc "Japan My Number (MIC Ordinance No. 85 of 2014)."
  @spec jp_my_number(String.t()) :: boolean()
  def jp_my_number(input) do
    d = digit_list(input)

    if length(d) != 12 do
      false
    else
      sum =
        Enum.reduce(1..11, 0, fn n, acc ->
          p = Enum.at(d, 11 - n)
          q = if n <= 6, do: n + 1, else: n - 5
          acc + p * q
        end)

      r = rem(sum, 11)
      check = if r <= 1, do: 0, else: 11 - r
      check == Enum.at(d, 11)
    end
  end

  @cn_shape ~r/^\d{17}[\dX]$/

  @doc "China resident ID (GB 11643-1999): ISO 7064 MOD 11-2, check character may be X."
  @spec cn_resident_id(String.t()) :: boolean()
  def cn_resident_id(input) do
    s = stripped_upper(input)

    if Regex.match?(@cn_shape, s) do
      body = s |> String.slice(0, 17) |> String.to_charlist() |> Enum.map(&(&1 - ?0))
      sum = weighted(body, [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2])
      String.at("10X98765432", rem(sum, 11)) == String.at(s, 17)
    else
      false
    end
  end

  @doc """
  Korea RRN, for numbers issued before 20 Oct 2020.

  ADVISORY ONLY, never a gate: numbers issued from 20 Oct 2020 are randomly
  assigned and carry no check digit.
  """
  @spec kr_rrn(String.t()) :: boolean()
  def kr_rrn(input) do
    d = digit_list(input)

    if length(d) != 13 do
      false
    else
      sum = weighted(Enum.take(d, 12), [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5])
      rem(11 - rem(sum, 11), 10) == Enum.at(d, 12)
    end
  end

  @sg_shape ~r/^[STFGM]\d{7}[A-Z]$/

  @doc "Singapore NRIC/FIN (ICA): weights 2,7,6,5,4,3,2 and a prefix-dependent letter table."
  @spec sg_nric(String.t()) :: boolean()
  def sg_nric(input) do
    s = stripped_upper(input)

    if Regex.match?(@sg_shape, s) do
      body = s |> String.slice(1, 7) |> String.to_charlist() |> Enum.map(&(&1 - ?0))
      sum = weighted(body, [2, 7, 6, 5, 4, 3, 2])
      prefix = String.at(s, 0)

      sum =
        cond do
          prefix in ["T", "G"] -> sum + 4
          prefix == "M" -> sum + 3
          true -> sum
        end

      table =
        cond do
          prefix in ["S", "T"] -> "JZIHGFEDCBA"
          prefix == "M" -> "KLJNPQRTUWX"
          true -> "XWUTRQPNMLK"
        end

      String.at(table, rem(sum, 11)) == String.at(s, 8)
    else
      false
    end
  end

  @cf_odd %{
    ?0 => 1, ?1 => 0, ?2 => 5, ?3 => 7, ?4 => 9, ?5 => 13, ?6 => 15, ?7 => 17, ?8 => 19, ?9 => 21,
    ?A => 1, ?B => 0, ?C => 5, ?D => 7, ?E => 9, ?F => 13, ?G => 15, ?H => 17, ?I => 19, ?J => 21,
    ?K => 2, ?L => 4, ?M => 18, ?N => 20, ?O => 11, ?P => 3, ?Q => 6, ?R => 8, ?S => 12, ?T => 14,
    ?U => 16, ?V => 10, ?W => 22, ?X => 25, ?Y => 24, ?Z => 23
  }

  @cf_shape ~r/^[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]$/

  @doc "Italy codice fiscale (Agenzia delle Entrate): odd/even tables, mod 26, check letter."
  @spec it_codice_fiscale(String.t()) :: boolean()
  def it_codice_fiscale(input) do
    s = stripped_upper(input)

    if Regex.match?(@cf_shape, s) do
      chars = String.to_charlist(s)

      sum =
        chars
        |> Enum.take(15)
        |> Enum.with_index()
        |> Enum.map(fn {c, i} ->
          cond do
            rem(i, 2) == 0 -> Map.get(@cf_odd, c, 0)
            c in ?0..?9 -> c - ?0
            true -> c - ?A
          end
        end)
        |> Enum.sum()

      <<?A + rem(sum, 26)>> == String.at(s, 15)
    else
      false
    end
  end

  @nir_shape ~r/^[12]\d{2}\d{2}(\d{2}|2A|2B)\d{3}\d{3}\d{2}$/

  @doc "France NIR (Insee): 97-complement, Corsican 2A/2B mapped to 19/18 first."
  @spec fr_nir(String.t()) :: boolean()
  def fr_nir(input) do
    s = stripped_upper(input)

    if Regex.match?(@nir_shape, s) do
      s = s |> String.replace("2A", "19", global: false) |> String.replace("2B", "18", global: false)
      body = String.slice(s, 0, 13)
      key = s |> String.slice(13, 2) |> String.to_integer()
      97 - mod_digits(body, 97) == key
    else
      false
    end
  end

  @doc "Germany Steuer-IdNr (BZSt): ISO 7064 MOD 11,10 over 10 digits."
  @spec de_steuer_id(String.t()) :: boolean()
  def de_steuer_id(input) do
    d = digit_list(input)

    if length(d) != 11 or Enum.at(d, 0) == 0 do
      false
    else
      product =
        Enum.reduce(0..9, 10, fn i, product ->
          sum = rem(Enum.at(d, i) + product, 10)
          sum = if sum == 0, do: 10, else: sum
          rem(sum * 2, 11)
        end)

      check = 11 - product
      check = if check == 10, do: 0, else: check
      check == Enum.at(d, 10)
    end
  end

  @doc "Thailand national ID (DOPA): weights 13..2, check = (11 - sum mod 11) mod 10."
  @spec th_national_id(String.t()) :: boolean()
  def th_national_id(input) do
    d = digit_list(input)

    if length(d) != 13 do
      false
    else
      sum = weighted(Enum.take(d, 12), Enum.to_list(13..2//-1))
      rem(11 - rem(sum, 11), 10) == Enum.at(d, 12)
    end
  end

  @doc "Canada SIN (Service Canada): Luhn over 9 digits. Advisory -- community-sourced."
  @spec ca_sin(String.t()) :: boolean()
  def ca_sin(input), do: String.length(digits_of(input)) == 9 and luhn(input)

  @doc "South Africa ID (SARS PAYE BRS Appendix B 8.3): Luhn over 13 digits."
  @spec za_id(String.t()) :: boolean()
  def za_id(input), do: String.length(digits_of(input)) == 13 and luhn(input)

  @doc "UAE Emirates ID (ICP): Luhn over 15 digits starting 784. Advisory."
  @spec ae_emirates_id(String.t()) :: boolean()
  def ae_emirates_id(input) do
    d = digits_of(input)
    String.length(d) == 15 and String.starts_with?(d, "784") and luhn(d)
  end

  @doc "Saudi national ID / iqama: Luhn over 10 digits starting 1 or 2. Advisory."
  @spec sa_national_id(String.t()) :: boolean()
  def sa_national_id(input) do
    d = digits_of(input)
    String.length(d) == 10 and String.first(d) in ["1", "2"] and luhn(d)
  end

  @functions %{
    "luhn" => &__MODULE__.luhn/1,
    "verhoeff" => &__MODULE__.verhoeff/1,
    "au_tfn" => &__MODULE__.au_tfn/1,
    "au_abn" => &__MODULE__.au_abn/1,
    "au_medicare" => &__MODULE__.au_medicare/1,
    "uk_nhs" => &__MODULE__.uk_nhs/1,
    "br_cpf" => &__MODULE__.br_cpf/1,
    "br_cnpj" => &__MODULE__.br_cnpj/1,
    "jp_my_number" => &__MODULE__.jp_my_number/1,
    "cn_resident_id" => &__MODULE__.cn_resident_id/1,
    "kr_rrn" => &__MODULE__.kr_rrn/1,
    "sg_nric" => &__MODULE__.sg_nric/1,
    "it_codice_fiscale" => &__MODULE__.it_codice_fiscale/1,
    "fr_nir" => &__MODULE__.fr_nir/1,
    "de_steuer_id" => &__MODULE__.de_steuer_id/1,
    "th_national_id" => &__MODULE__.th_national_id/1,
    "ca_sin" => &__MODULE__.ca_sin/1,
    "za_id" => &__MODULE__.za_id/1,
    "ae_emirates_id" => &__MODULE__.ae_emirates_id/1,
    "sa_national_id" => &__MODULE__.sa_national_id/1
  }

  @doc "Keyed by the bundle's `checksum` field."
  @spec functions() :: %{String.t() => (String.t() -> boolean())}
  def functions, do: @functions

  @doc "The checksum named by the bundle, or nil if it is not implemented."
  @spec get(String.t() | nil) :: (String.t() -> boolean()) | nil
  def get(nil), do: nil
  def get(name), do: Map.get(@functions, name)
end
