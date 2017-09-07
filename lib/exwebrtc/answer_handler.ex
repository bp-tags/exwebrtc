defmodule Exwebrtc.AnswerHandler do
  def init(_transport, req, []) do
    {:ok, req, nil}
  end

  def handle(req, state) do
    {:ok, body, req} = :cowboy_req.body(req)
    {:ok, decoded} = Poison.decode(body)
    sdp = Dict.get(decoded, "sdp")
    Exwebrtc.STUNServer.answer_sdp(sdp)

    {:ok, req} = :cowboy_req.reply(200, [], "<response></response>", req)
    {:ok, req, state}
  end

  def terminate(_reason, _req, _state), do: :ok
end
