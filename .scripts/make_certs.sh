#!/bin/bash
# This script generates test & development certificates. Not for production use!

# You can addd an entry to this list to generate a certificate for the given
# actors.
declare -a certs=("notifier-1" "storage-1" "appointments-1")

O="Kiebitz"
ST="Berlin"
L="Berlin"
C="DE"
OU="IT"
CN="Testing-Development"
LEN=2048

openssl ecparam -name prime256v1 -genkey -noout -out root.key
openssl req -x509 -new -nodes -key root.key -sha256 -days 1024 -out root.crt -subj "/C=${C}/ST=${ST}/L=${L}/O=${O}/OU=${OU}/CN=${CN}"
# we export the public key so it can be imported e.g. in JS
openssl x509 -pubkey -noout -in root.crt -outform der  > root.pub

for cert in "${certs[@]}"
do
	echo "Generating TLS certificates for ${cert}...";

	openssl genrsa -out "${cert}.key" ${LEN};
	openssl rsa -in "${cert}.key" -pubout -out "${cert}.pub";
	openssl req -new -sha256 -key "${cert}.key" -subj "/C=${C}/ST=${ST}/L=${L}/O=${O}/OU=${OU}/CN=${cert}" -addext "subjectAltName = DNS:${cert},DNS:*.${cert}.local" -out "${cert}.csr";
	openssl x509 -req -in "${cert}.csr" -CA root.crt -CAkey root.key -CAcreateserial -out "${cert}.crt" -extensions SAN -extfile <(printf "[SAN]\nsubjectAltName = DNS:${cert},DNS:*.${cert}.local") -days 500 -sha256;

done
