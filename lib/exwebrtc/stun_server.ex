defmodule Exwebrtc.STUNServer do
  use ExActor.Strict, export: :stun_server

  require Record

  alias Exwebrtc.STUN, as: STUN
  alias Exwebrtc.SDP, as: SDP

  Record.defrecord :ssl_options, protocol: :undefined, versions: :undefined, verify: :undefined,
    verify_fun: :undefined, partial_chain: :undefined,
    fail_if_no_peer_cert: :undefined, verify_client_once: :undefined,
    validate_extensions_fun: :undefined, depth: :undefined, certfile: :undefined,
    cert: :undefined, keyfile: :undefined, key: :undefined, password: :undefined,
    cacerts: :undefined, cacertfile: :undefined, dh: :undefined,
    dhfile: :undefined, user_lookup_fun: :undefined, psk_identity: :undefined,
    srp_identity: :undefined, ciphers: :undefined, reuse_session: :undefined,
    reuse_sessions: :undefined, renegotiate_at: :undefined,
    secure_renegotiate: :undefined, client_renegotiation: :undefined,
    hibernate_after: :undefined, erl_dist: false,
    alpn_advertised_protocols: :undefined, alpn_preferred_protocols: :undefined,
    next_protocols_advertised: :undefined, next_protocol_selector: :undefined,
    log_alert: :undefined, server_name_indication: :undefined,
    sni_hosts: :undefined, sni_fun: :undefined, honor_cipher_order: false,
    padding_check: true, beast_mitigation: :one_n_minus_one, fallback: false,
    crl_check: :undefined, crl_cache: :undefined, signature_algs: :undefined,
    eccs: :undefined, honor_ecc_order: :undefined, v2_hello_compatible: :undefined,
    max_handshake_size: :undefined

  defstart start_link(port_number) do
    {:ok, socket} = :gen_udp.open(port_number, [:binary, {:active, :true}])
    initial_state(%{socket: socket, port: port_number})
  end

  defcast answer_sdp(sdp), state: state do
    state = Dict.put(state, :sdp, sdp)
    if Dict.has_key?(state, :ready_to_probe) do
      probe(state)
    end
    new_state(state)
  end

  defcast active_once(client, pid), state: state do
    IO.puts "Active once"
    new_state(state)
  end

  def probe(%{attributes: attributes, sdp: sdp, ip_addr: ip_addr, in_port_no: in_port_no, socket: socket} = state) do
    {:ok, request} = STUN.build_request(
      ice_controlling: attributes[:ice_controlled],
      priority: attributes[:priority],
      username: reverse_username(attributes[:username]),
      use_candidate: nil,
      message_integrity_key: SDP.password(sdp)
    )
    IO.puts "Send probe response: #{inspect(request)}"
    :gen_udp.send(socket, ip_addr, in_port_no, request)
  end

  def reverse_username(username) do
    username |> String.split(":") |> Enum.reverse() |> Enum.join(":")
  end

  defhandleinfo {:udp, socket, ip_addr, in_port_no, packet} = msg, state: %{ conn_pid: conn_pid } = state do
    IO.puts "DTLS packet ready, send #{inspect(msg)} to #{inspect(conn_pid)}"
    send(conn_pid, msg)
    new_state(state)
  end

  defhandleinfo {:udp, socket, ip_addr, in_port_no, packet} = msg, state: %{ dtls_ready: true } = state do
    IO.puts "DTLS packet ready, not started" 
    client = { ip_addr, in_port_no }
    socket = state[:socket]
    listener_pid = self()
    user_pid = self()

    { :ok, { :config, dtls_options, _, _, _, _, _, _ } } = :ssl.handle_options([], :server)

    dtls_options = ssl_options(dtls_options,
      protocol: :dtls,
      certfile: "certificate.pem",
      keyfile: "key.pem",
      verify: :verify_none
    )

    emulated_options = :dtls_socket.emulated_options()

    cb_info = :dtls_socket.default_cb_info()

    conn_args = [:server, "localhost", state[:port], { listener_pid, { client, socket } },
                 {dtls_options, emulated_options, :udp_listener}, user_pid, cb_info]

    { :ok, conn_pid } = :dtls_connection_sup.start_child(conn_args)
    state = Dict.put(state, :conn_pid, conn_pid)

    send(conn_pid, msg)

    Task.async(fn -> :gen_statem.call(conn_pid, { :start, 100000 }) end)

    new_state(state)
  end

  defhandleinfo {:ssl, _}, state: state do
    IO.puts "SSL packet recv"
  end

  defhandleinfo {:dtls, _}, state: state do
    IO.puts "DTLS packet recv"
  end

  defhandleinfo {:dtls, _}, state: state do
    IO.puts "DTLS packet recv"
  end

  defhandleinfo {:udp, socket, ip_addr, in_port_no, packet}, state: state do
    {:ok, attributes} = STUN.parse(packet, fn x -> "9b4424d9e8c5e253c0290d63328b55b3" end)

    if attributes[:request_type] == :request do      
      {:ok, reply} = STUN.build_reply(
        transaction_id: attributes[:transaction_id], 
        mapped_address: {Enum.join(:erlang.tuple_to_list(ip_addr), "."), in_port_no},
        message_integrity_key: "9b4424d9e8c5e253c0290d63328b55b3",
      )
      :gen_udp.send(socket, ip_addr, in_port_no, reply)

      state = Dict.put(state, :ready_to_probe, true)
      state = Dict.put(state, :ip_addr, ip_addr)
      state = Dict.put(state, :in_port_no, in_port_no)
      state = Dict.put(state, :attributes, attributes)
      if Dict.has_key?(state, :sdp) do
        probe(state)
      end
    else
      # STUN response from client after probe, DTLS begun
      state = Dict.put(state, :dtls_ready, true)
    end

    new_state(state)
  end
end
