defmodule ExtendedKey.MixProject do
  use Mix.Project

  @github_url "https://github.com/LanfordCai/extended_key"

  def project do
    [
      app: :extended_key,
      version: "0.3.0",
      elixir: "~> 1.8",
      start_permanent: Mix.env() == :prod,
      description: description(),
      package: package(),
      source_url: @github_url,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:libsecp256k1, "~> 0.1.10"},
      {:basefiftyeight, "~> 0.1.0"},
      {:dialyxir, "~> 1.0.0-rc.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.19", only: :dev}
    ]
  end

  defp description do
    """
    Elixir BIP32 implementation
    """
  end

  defp package do
    [
      licenses: ["MIT"],
      maintainers: ["lanfordcai@outlook.com"],
      links: %{
        "GitHub" => @github_url
      }
    ]
  end
end
