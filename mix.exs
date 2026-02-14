defmodule TorkGovernance.MixProject do
  use Mix.Project

  def project do
    [
      app: :tork_governance,
      version: "0.1.1",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "On-device AI governance with PII detection and cryptographic receipts",
      package: package(),
      source_url: "https://github.com/torkjacobs/tork-elixir-sdk",
      docs: [main: "TorkGovernance", extras: ["README.md"]]
    ]
  end

  def application, do: [extra_applications: [:logger, :crypto]]

  defp deps do
    [
      {:jason, "~> 1.4", optional: true},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/torkjacobs/tork-elixir-sdk"}
    ]
  end
end
