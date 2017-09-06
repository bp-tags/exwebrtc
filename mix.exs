defmodule Exwebrtc.Mixfile do
  use Mix.Project

  def project do
    [app: :exwebrtc,
     version: "0.0.1",
     elixir: "1.5.0",
     deps: deps]
  end

  # Configuration for the OTP application
  #
  # Type `mix help compile.app` for more information
  def application do
    [ 
      applications: [
        :cowboy,
        :crypto,
      ],
      mod: { Exwebrtc, [] }
    ]
  end

  defp deps do
    [
      { :cowboy, "1.1.2" },
      { :exactor, "2.2.3" },
      { :hound, "1.0.4" }
    ]
  end
end
