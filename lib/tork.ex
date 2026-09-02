defmodule TorkGovernance do
  @moduledoc """
  On-device AI governance with PII detection, redaction, and cryptographic receipts.

  ## Usage

      result = TorkGovernance.govern("My SSN is 123-45-6789")
      result.action   #=> :redact
      result.output   #=> "My SSN is [SSN_REDACTED]"
      result.receipt   #=> %{receipt_id: "...", input_hash: "...", ...}
  """

  alias TorkGovernance.PII
  alias TorkGovernance.Receipt
  alias TorkGovernance.ToolResultScan

  @sdk_version Mix.Project.config()[:version]

  @doc """
  Apply governance rules to the input text.

  Detects PII, applies redaction if found, and generates a cryptographic receipt.

  ## Options

    * `:action` - Override the default action (`:redact`)
    * `:region` - List of regional PII profiles to activate (e.g. `["ae", "in"]`)
    * `:industry` - Industry profile to activate (e.g. `"healthcare"`, `"finance"`, `"legal"`)
    * `:agent_id` - Identifier for the agent making the call
    * `:agent_role` - Role of the agent (`"planner"`, `"worker"`, or `"judge"`)
    * `:session_id` - Groups all calls from the same agent session
    * `:session_turn` - Position in the conversation (1, 2, 3...)

  ## Examples

      iex> result = TorkGovernance.govern("Hello world")
      iex> result.action
      :allow

      iex> result = TorkGovernance.govern("SSN: 123-45-6789")
      iex> result.action
      :redact

      iex> result = TorkGovernance.govern("Emirates ID: 784-1234-1234567-1", region: ["ae"])
      iex> result.region
      ["ae"]

      iex> result = TorkGovernance.govern("Hello", agent_id: "agent-1", agent_role: "worker")
      iex> result.session_context.agent_id
      "agent-1"
  """
  @spec govern(String.t(), keyword()) :: map()
  def govern(text, opts \\ []) do
    pii_matches = PII.detect(text)
    region = Keyword.get(opts, :region)
    industry = Keyword.get(opts, :industry)
    session_context = build_session_context(opts)

    if Enum.empty?(pii_matches) do
      receipt = Receipt.build(text, text, pii_matches, :allow)

      %{
        action: :allow,
        output: text,
        pii_detected: [],
        receipt: receipt,
        region: region,
        industry: industry,
        session_context: session_context
      }
    else
      redacted = PII.redact(text)
      action = Keyword.get(opts, :action, :redact)
      receipt = Receipt.build(text, redacted, pii_matches, action)

      %{
        action: action,
        output: redacted,
        pii_detected: pii_matches,
        receipt: receipt,
        region: region,
        industry: industry,
        session_context: session_context
      }
    end
  end

  @doc """
  Scan a tool result (e.g. an MCP tool call's return payload) for PII and
  prompt injection before it is appended to a model's context, and record
  the scan on a governance receipt (DECIDED-TACT2-V2-C).

  Wraps `TorkGovernance.ToolResultScan.scan/3` -- which does the actual
  work and is directly usable standalone -- and additionally maps the
  outcome to a governance `:action`:

    * `:deny` -- `:block_on_injection` was true and an injection heuristic fired.
    * `:escalate` -- an injection heuristic fired (and blocking was not requested).
    * `:redact` -- only PII was found.
    * `:allow` -- nothing found.

  and attaches a `tool_result_scan` block (`attested_by: "client"`,
  `capture_mode: "edge"`) to the receipt.

  ## Options

    * `:server_uri` - URI of the MCP server (or other origin). Recorded on
      the receipt block when present.
    * `:block_on_injection` - default `false`. See `TorkGovernance.ToolResultScan.scan/3`.
    * `:max_depth` - default 32.

  ## Examples

      iex> result = TorkGovernance.scan_tool_result("lookup_customer", %{"text" => "jane.doe@example.com"})
      iex> result.action
      :redact
  """
  @spec scan_tool_result(String.t(), term(), keyword()) :: map()
  def scan_tool_result(tool_name, payload, opts \\ []) do
    result = ToolResultScan.scan(tool_name, payload, opts)

    action =
      cond do
        result.blocked -> :deny
        ToolResultScan.injection_count(result.findings) > 0 -> :escalate
        ToolResultScan.pii_count(result.findings) > 0 -> :redact
        true -> :allow
      end

    block =
      ToolResultScan.build_receipt_block(tool_name, result, @sdk_version,
        server_uri: Keyword.get(opts, :server_uri)
      )

    receipt = %{
      receipt_id: Receipt.generate_id(),
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      input_hash: Receipt.hash(ToolResultScan.canonicalize(payload)),
      output_hash: Receipt.hash(ToolResultScan.canonicalize(result.sanitized)),
      pii_count: ToolResultScan.pii_count(result.findings),
      pii_types: ToolResultScan.pii_types(result.findings),
      action: action,
      tool_result_scan: block
    }

    %{
      action: action,
      sanitized: result.sanitized,
      findings: result.findings,
      blocked: result.blocked,
      reason: result.reason,
      receipt: receipt
    }
  end

  defp build_session_context(opts) do
    ctx =
      %{
        agent_id: Keyword.get(opts, :agent_id),
        agent_role: Keyword.get(opts, :agent_role),
        session_id: Keyword.get(opts, :session_id),
        session_turn: Keyword.get(opts, :session_turn)
      }
      |> Enum.reject(fn {_k, v} -> is_nil(v) end)
      |> Map.new()

    if map_size(ctx) == 0, do: nil, else: ctx
  end
end
