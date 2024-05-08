you can build and run LSQUIC-VPN as follows:

1. Get the source code
```
git clone https://github.com/zuopucuen/lsquic-vpn.git
cd lsquic-vpn
git submodule update --init --recursive
```
2. Compile the library
```
cmake .
make
```
3.Running the server
```
# server
./echo_server -c www.example.com,certs/server.crt,certs/ca-key.pem  -s 0.0.0.0:4433 -L debug


# client
./echo_client -H www.example.com  -s 127.0.0.1:4433
```
