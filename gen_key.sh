#!/bin/sh

#generate rsa key as privkey.pem
openssl genrsa -out pkt.pem 2048
openssl genrsa -out pku.pem 2048
#generate U's certificate
openssl req -new -x509 -key pkt.pem -out cert.pem -days 1095
