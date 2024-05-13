#!/bin/bash
./vpn_client -c certs/client.crt -k certs/ca-key.pem -C certs/ca-cert.crt -s 127.0.0.1:4433 -L debug
