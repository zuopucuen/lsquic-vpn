#!/bin/bash
# 1.生成私钥
openssl genrsa -out ca-key.pem 2048 # 若不想变更已有的私钥，需注释掉此命令

# 2.生成 server CSR
openssl req -new -key ca-key.pem -out server.csr -config conf/server-openssl.conf

# 3.生成client CSR
openssl req -new -key ca-key.pem -out client.csr -config conf/openssl.conf

# 4.生成 ca 证书
openssl req -x509 -config conf/openssl.conf -new -nodes -key ca-key.pem -days 36500 -out ca-cert.crt

# 5.签发服务器证书
openssl x509 -req -in server.csr -CA ca-cert.crt -CAkey ca-key.pem -CAcreateserial -out server.crt -days 36500 -sha256 -extfile conf/https.ext

# 6.签发客户端证书
openssl x509 -req -in client.csr -CA ca-cert.crt -CAkey ca-key.pem -CAcreateserial -out client.crt -days 36500 -sha256 -extfile conf/https.ext

# 7.将 ca 证书打包为 p12 格式
openssl pkcs12 -export -in ca-cert.crt -inkey ca-key.pem -out ca-cert.p12 -password pass:1234567
base64 ca-cert.p12 > ca-cert-p12.base64
