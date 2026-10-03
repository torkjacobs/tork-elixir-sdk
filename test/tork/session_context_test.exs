defmodule TorkGovernance.SessionContextTest do
  use ExUnit.Case, async: true

  test "all four telemetry fields pass through when set" do
    r =
      TorkGovernance.govern("hello",
        agent_id: "a-1",
        agent_role: "judge",
        session_id: "s-9",
        session_turn: 3
      )

    assert r.session_context == %{
             agent_id: "a-1",
             agent_role: "judge",
             session_id: "s-9",
             session_turn: 3
           }
  end

  test "session_turn is kept as an integer" do
    r = TorkGovernance.govern("hello", session_turn: 2)
    assert r.session_context == %{session_turn: 2}
    assert is_integer(r.session_context.session_turn)
  end

  test "unset fields are omitted, and nil when none are set" do
    assert TorkGovernance.govern("hello").session_context == nil
    r = TorkGovernance.govern("hello", agent_id: "a-1")
    assert r.session_context == %{agent_id: "a-1"}
    refute Map.has_key?(r.session_context, :session_id)
  end

  test "passes through on the redact path too" do
    r = TorkGovernance.govern("SSN 123-45-6789", session_id: "s-1")
    assert r.action == :redact
    assert r.session_context == %{session_id: "s-1"}
  end
end
