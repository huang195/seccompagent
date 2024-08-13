#!/bin/sh

# Generate server private key
openssl genpkey -algorithm RSA -out server.key

# Generate server certificate signing request
openssl req -new -key server.key -out server.csr

# Generate server certificate
openssl x509 -req -in server.csr -signkey server.key -out server.crt

# Generate client private key
openssl genpkey -algorithm RSA -out client.key

# Generate client certificate signing request
openssl req -new -key client.key -out client.csr

# Generate client certificate
openssl x509 -req -in client.csr -signkey client.key -out client.crt

# Generate a CA certificate (optional)
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 365

# Sign server and client certificates with the CA certificate (optional)
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt

