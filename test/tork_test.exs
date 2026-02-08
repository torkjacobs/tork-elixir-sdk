defmodule TorkGovernanceTest do
  use ExUnit.Case, async: true

  describe "govern/1" do
    test "clean text passes through" do
      result = TorkGovernance.govern("Hello, world!")

      assert result.action == :allow
      assert result.output == "Hello, world!"
      assert result.pii_detected == []
    end

    test "detects SSN" do
      result = TorkGovernance.govern("My SSN is 123-45-6789")

      assert result.action == :redact
      assert String.contains?(result.output, "[SSN_REDACTED]")
      refute String.contains?(result.output, "123-45-6789")

      types = Enum.map(result.pii_detected, & &1.type)
      assert :ssn in types
    end

    test "detects email" do
      result = TorkGovernance.govern("Email: test@example.com")

      assert result.action == :redact
      assert String.contains?(result.output, "[EMAIL_REDACTED]")
      refute String.contains?(result.output, "test@example.com")

      types = Enum.map(result.pii_detected, & &1.type)
      assert :email in types
    end

    test "redacts multiple PII types" do
      result = TorkGovernance.govern("SSN: 123-45-6789, email: admin@secret.com")

      assert result.action == :redact
      assert String.contains?(result.output, "[SSN_REDACTED]")
      assert String.contains?(result.output, "[EMAIL_REDACTED]")
      refute String.contains?(result.output, "123-45-6789")
      refute String.contains?(result.output, "admin@secret.com")
    end

    test "generates receipt with hash" do
      result = TorkGovernance.govern("My SSN is 123-45-6789")

      assert is_binary(result.receipt.receipt_id)
      assert String.starts_with?(result.receipt.receipt_id, "rcpt_")
      assert String.starts_with?(result.receipt.input_hash, "sha256:")
      assert String.starts_with?(result.receipt.output_hash, "sha256:")
      assert is_binary(result.receipt.timestamp)
      assert result.receipt.pii_count > 0
      assert result.receipt.action == :redact
    end
  end
end
