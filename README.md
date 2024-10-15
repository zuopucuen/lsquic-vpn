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
sudo ./vpn_server -c vpn_server.conf


# client
sudo ./vpn_client -c vpn_client.conf
