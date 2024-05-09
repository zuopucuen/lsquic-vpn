you can build and run LSQUIC-VPN as follows:

1. Get the source code
```
git clone https://github.com/zuopucuen/lsquic-vpn.git
cd lsquic-vpn
git submodule update --init --recursive
```
2. Compile the library
```
cmake . -B
make
```
3. Test 
```
# server
./vpn_server -c www.example.com,./certs/server.crt,./certs/ca-key.pem  -s 0.0.0.0:4433 -L debug

output:
09:59:07.173 [DEBUG] tokgen: TOKGEN2 does not exist: generate
09:59:07.173 [INFO] tokgen: inserted TOKGEN2 of size 110
09:59:07.173 [DEBUG] tokgen: initialized
09:59:07.173 [DEBUG] handshake: generated QUIC server context of 56 bytes for version FF00001B
09:59:07.173 [DEBUG] handshake: max_idle_timeout: 30000; init_max_data: 1572864; init_max_stream_data_bidi_local: 0; init_max_stream_data_bidi_remote: 1048576; init_max_stream_data_uni: 12288; init_max_streams_bidi: 100; init_max_streams_uni: 3; active_connection_id_limit: 8; min_ack_delay: 10000; min_ack_delay_02: 10000; timestamps: 2
09:59:07.173 [DEBUG] handshake: generated QUIC server context of 56 bytes for version FF00001D
09:59:07.173 [DEBUG] handshake: max_idle_timeout: 30000; init_max_data: 1572864; init_max_stream_data_bidi_local: 0; init_max_stream_data_bidi_remote: 1048576; init_max_stream_data_uni: 12288; init_max_streams_bidi: 100; init_max_streams_uni: 3; active_connection_id_limit: 8; min_ack_delay: 10000; min_ack_delay_02: 10000; timestamps: 2
09:59:07.173 [INFO] prq: initialized queue of size 10000
09:59:07.173 [INFO] purga: create purgatory, min life 30000000 usec
09:59:07.173 [INFO] engine: instantiated engine
09:59:07.178 [INFO] socket buffer size: 786896 bytes; max # packets is set to 574
09:59:07.178 [DEBUG] local address: 0.0.0.0:4433
09:59:07.178 [DEBUG] entering event loop


# client
./vpn_client -H www.example.com  -s 127.0.0.1:4433 -L info

output:
Interface: [utun4]
18:03:05.991 [INFO] tokgen: inserted TOKGEN2 of size 110
18:03:05.992 [INFO] engine: instantiated engine
18:03:05.998 [INFO] socket buffer size: 786896 bytes; max # packets is set to 574
18:03:05.999 [INFO] [QUIC:6D1EFA9C12A0302B] cubic: initialized
18:03:06.000 [INFO] [QUIC:6D1EFA9C12A0302B] handshake: update handshake keys to version 6B3343CF
18:03:06.000 [INFO] [QUIC:6D1EFA9C12A0302B] cubic: min_delay: 1109
18:03:06.000 [INFO] [QUIC:6D1EFA9C12A0302B] cubic: CWND: 48180
18:03:06.000 [INFO] [QUIC:6D1EFA9C12A0302B] sendctl: srtt is 1070 usec, which is smaller than or equal to the threshold of 1500 usec: select Cubic congestion controller
18:03:06.001 [INFO] [QUIC:6D1EFA9C12A0302B] conn: applied peer transport parameters
18:03:06.001 [INFO] [QUIC:6D1EFA9C12A0302B] cubic: min_delay: 301
18:03:07.503 [INFO] [QUIC:6D1EFA9C12A0302B] alarmset: ring expired ACK_APP alarm
18:03:08.504 [INFO] [QUIC:6D1EFA9C12A0302B] alarmset: ring expired ACK_APP alarm
```
