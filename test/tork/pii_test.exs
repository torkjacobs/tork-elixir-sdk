defmodule TorkGovernance.PIITest do
  use ExUnit.Case, async: true

  alias TorkGovernance.PII

  # DECIDED-TACT2-V2-C, STEP 0 (SDK-DECLARED-PII-TYPES-WITHOUT-PATTERNS-ACROSS-SDKS).
  # The JS SDK's basic detector (pii.ts PII_PATTERNS) is the TIER 1 vocabulary
  # every SDK is expected to carry. This test fails if this SDK ever declares
  # (in README, in a receipt, in another module) a PII type from that
  # vocabulary without a live pattern backing it in TorkGovernance.PII.
  #
  # Before this port: this list caught 5 gaps (:address, :date_of_birth,
  # :passport, :drivers_license, :bank_account were declared as part of the
  # JS-parity vocabulary this SDK claims but had no Elixir pattern at all).
  @js_basic_pii_types ~w(
    ssn credit_card email phone address ip_address date_of_birth passport
    drivers_license bank_account
  )a

  test "every JS TIER 1 basic PII type has a live pattern in this SDK" do
    implemented = PII.types()
    missing = @js_basic_pii_types -- implemented

    assert missing == [],
           "PII types declared as part of the JS basic vocabulary but with no live " <>
             "pattern in TorkGovernance.PII: #{inspect(missing)}"
  end

  test "PII.types/0 declares exactly the JS basic vocabulary, no more, no less" do
    assert Enum.sort(PII.types()) == Enum.sort(@js_basic_pii_types)
  end

  describe "JS-identical redaction labels" do
    test "ssn" do
      assert PII.redact("SSN: 123-45-6789") == "SSN: [SSN_REDACTED]"
    end

    test "credit_card (JS label is [CARD_REDACTED], not [CREDIT_CARD_REDACTED])" do
      assert PII.redact("Card: 4111-1111-1111-1111") == "Card: [CARD_REDACTED]"
    end

    test "email" do
      assert PII.redact("Email: jane.doe@example.com") == "Email: [EMAIL_REDACTED]"
    end

    test "phone" do
      assert PII.redact("Call 555-123-4567") == "Call [PHONE_REDACTED]"
    end

    test "address" do
      assert PII.redact("123 Main Street") == "[ADDRESS_REDACTED]"
    end

    test "ip_address" do
      assert PII.redact("Server at 192.168.1.1") == "Server at [IP_REDACTED]"
    end

    test "ip_address does not match an out-of-range octet (JS pattern validates 0-255)" do
      refute PII.redact("999.999.999.999") == "[IP_REDACTED]"
    end

    test "date_of_birth" do
      assert PII.redact("DOB 05/12/1990") == "DOB [DOB_REDACTED]"
    end

    test "passport" do
      assert PII.redact("Passport AB1234567") == "Passport [PASSPORT_REDACTED]"
    end

    test "drivers_license (disambiguated from passport with an 11-digit run)" do
      assert PII.redact("DL A12345678901") == "DL [DL_REDACTED]"
    end

    test "bank_account (disambiguated from phone with a 9-digit run)" do
      assert PII.redact("Account 123456789") == "Account [ACCOUNT_REDACTED]"
    end
  end

  test "detect/1 never returns the matched value, only the [REDACTED] placeholder" do
    [match] = PII.detect("SSN: 123-45-6789")
    assert match == %{type: :ssn, match: "[REDACTED]"}
  end
end
