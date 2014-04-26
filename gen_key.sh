#!/bin/sh

#generate rsa key as ku/kt_priv.pem, and public key as ku/kt_pub.pem
openssl genrsa -out kt_priv.pem 1024
openssl rsa -in kt_priv.pem -pubout -out kt_pub.pem
openssl genrsa -out ku_priv.pem 1024
openssl rsa -in ku_priv.pem -pubout -out ku_pub.pem
#generate U's certificate
openssl req -new -x509 -key kt_priv.pem -out cert.pem -days 1095
