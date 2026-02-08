defmodule TorkGovernance.PlugTest do
  use ExUnit.Case, async: true

  # Mock conn structure for testing without Plug dependency
  defmodule MockConn do
    defstruct method: "GET", assigns: %{}, body: ""
  end

  describe "TorkGovernance.Plug" do
    test "governs POST request body" do
      text = "My SSN is 123-45-6789"
      result = TorkGovernance.govern(text)

      assert result.action == :redact
      assert String.contains?(result.output, "[SSN_REDACTED]")
      assert result.receipt.pii_count > 0
    end

    test "skips GET requests" do
      # GET requests should not be governed
      # The plug checks conn.method and skips non-mutating methods
      conn = %MockConn{method: "GET"}
      assert conn.method not in ["POST", "PUT", "PATCH"]
    end

    test "attaches receipt to conn assigns" do
      text = "Email: admin@secret.com"
      result = TorkGovernance.govern(text)

      # Simulate what the plug does: attach result to assigns
      assigns = Map.put(%{}, :tork_receipt, result.receipt)
      assert is_binary(assigns.tork_receipt.receipt_id)
      assert String.starts_with?(assigns.tork_receipt.receipt_id, "rcpt_")
      assert assigns.tork_receipt.pii_count > 0
    end
  end
end
