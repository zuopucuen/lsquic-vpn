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
# create certs
cd certs
./create.sh
cd ..

# server
sudo ./vpn_server -c certs/server.crt -k certs/ca-key.pem -C certs/ca-cert.crt -s 0.0.0.0:4433 -L info

output:
13:01:25.447 [INFO] local 192.168.101.1, remote 192.168.101.254
13:01:25.448 [INFO] local 192.168.102.1, remote 192.168.102.254
13:01:25.448 [INFO] local 192.168.103.1, remote 192.168.103.254
13:01:25.448 [INFO] local 192.168.104.1, remote 192.168.104.254
13:01:25.448 [INFO] local 192.168.105.1, remote 192.168.105.254
13:01:25.448 [INFO] ca-file: certs/ca-cert.crt, cert_file: certs/server.crt, key_file: certs/ca-key.pem
13:01:25.448 [INFO] tokgen: inserted TOKGEN2 of size 110
13:01:25.448 [INFO] prq: initialized queue of size 10000
13:01:25.448 [INFO] purga: create purgatory, min life 30000000 usec
13:01:25.448 [INFO] engine: instantiated engine
13:01:25.448 [INFO] ca-file: certs/ca-cert.crt, cert_file: certs/server.crt, key_file: certs/ca-key.pem
13:01:25.449 [INFO] socket buffer size: 786896 bytes; max # packets is set to 574
^C13:01:28.166 [NOTICE] Got sigint, stopping engine
13:01:28.166 [NOTICE] Got sigterm, cool down engine
13:01:28.166 [INFO] engine: entering cooldown mode


# client
sudo ./vpn_client -c certs/client.crt -k certs/ca-key.pem -C certs/ca-cert.crt -s 127.0.0.1:4433 -L info

output:
13:02:31.451 [INFO] tokgen: inserted TOKGEN2 of size 110
13:02:31.452 [INFO] engine: instantiated engine
13:02:31.452 [INFO] ca-file: certs/ca-cert.crt, cert_file: certs/client.crt, key_file: certs/ca-key.pem
13:02:31.452 [INFO] socket buffer size: 786896 bytes; max # packets is set to 574
13:02:31.452 [INFO] [QUIC:EF76F28CECADCAE3] cubic: initialized
13:02:31.454 [INFO] [QUIC:EF76F28CECADCAE3] cubic: min_delay: 1346
13:02:31.454 [INFO] [QUIC:EF76F28CECADCAE3] cubic: CWND: 48180
13:02:31.454 [INFO] [QUIC:EF76F28CECADCAE3] sendctl: srtt is 1305 usec, which is smaller than or equal to the threshold of 1500 usec: select Cubic congestion controller
13:02:31.454 [INFO] serialNumber: 61cf80ccc8b8e3d76383e613a297bf6a1009b5ea
13:02:31.455 [INFO] serialNumber: 01c6d9be7d256c827f421a16ba81f8370180daa0
13:02:31.455 [INFO] [QUIC:EF76F28CECADCAE3] conn: applied peer transport parameters
13:02:31.459 [INFO] read from server 0: 30 bytes
13:02:31.459 [INFO] local_ip: 192.168.101.254, remote_ip: 192.168.101.1
13:02:31.459 [INFO] local_ip:192.168.101.254, remote_ip:192.168.101.1
Interface: [utun4]

#ping
ping 192.168.101.1

output:
PING 192.168.101.1 (192.168.101.1): 56 data bytes
64 bytes from 192.168.101.1: icmp_seq=0 ttl=64 time=0.698 ms
64 bytes from 192.168.101.1: icmp_seq=1 ttl=64 time=0.561 ms
64 bytes from 192.168.101.1: icmp_seq=2 ttl=64 time=0.414 ms
64 bytes from 192.168.101.1: icmp_seq=3 ttl=64 time=0.656 ms
64 bytes from 192.168.101.1: icmp_seq=4 ttl=64 time=0.547 ms
^C
--- 192.168.101.1 ping statistics ---
5 packets transmitted, 5 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 0.414/0.575/0.698/0.099 ms
```
