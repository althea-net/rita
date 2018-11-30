#!/usr/bin/env bash
openssl req -newkey rsa:2048 -nodes -keyform pem -keyout bh_key.pem -x509 -days 365 -outform pem -out bh_cert.pem
