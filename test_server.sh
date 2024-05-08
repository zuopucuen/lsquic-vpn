#!/bin/bash

./echo_server -c www.shanshan666.com,certs/server.crt,certs/ca-key.pem  -s 0.0.0.0:4433 -L debug
