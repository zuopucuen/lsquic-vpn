#!/bin/bash
./vpn_server -c certs/server.crt -k certs/ca-key.pem -C certs/ca-cert.crt -s 0.0.0.0:4433 -L debug
