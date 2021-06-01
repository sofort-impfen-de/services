#!/bin/bash
# This script generates test & development certificates. Not for production use!

# You can addd an entry to this list to generate a certificate for the given
# actors.
declare -a certs=("mediator-1" "notifier-1" "storage-1" "appointments-1" "master-1")
declare -A groups=(["mediator-1"]="mediators" ["notifier-1"]="notifiers")

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
	echo "Generating signing, encryption & TLS certificates for ${cert}...";

	openssl genrsa -out "${cert}.key" ${LEN};
	openssl rsa -in "${cert}.key" -pubout -out "${cert}.pub";
	openssl req -new -sha256 -key "${cert}.key" -subj "/C=${C}/ST=${ST}/L=${L}/O=${O}/OU=${OU}/CN=${cert}" -addext "subjectAltName = DNS:${cert},DNS:*.${cert}.local" -out "${cert}.csr";
	openssl x509 -req -in "${cert}.csr" -CA root.crt -CAkey root.key -CAcreateserial -out "${cert}.crt" -extensions SAN -extfile <(printf "[SAN]\nsubjectAltName = DNS:${cert},DNS:*.${cert}.local") -days 500 -sha256;

	# Elliptic curve signing & encryption certificates

	openssl ecparam -genkey -name prime256v1 -noout -out "${cert}-sign.key";
	openssl ec -in "${cert}-sign.key" -pubout -out "${cert}-sign.pub";
	openssl req -new -sha256 -key "${cert}-sign.key" -subj "/C=${C}/ST=${ST}/L=${L}/O=${O}/OU=${OU}/CN=${cert}" -addext "keyUsage=digitalSignature" -addext "subjectAltName = URI:kiebitz-name://${cert},URI:kiebitz-group://${groups[${cert}]},DNS:${cert}"  -out "${cert}-sign.csr";
	openssl x509 -req -in "${cert}-sign.csr" -CA root.crt -CAkey root.key -CAcreateserial -out "${cert}-sign.crt"  -extensions SANKey -extfile <(printf "[SANKey]\nsubjectAltName = URI:kiebitz-name://${cert},URI:kiebitz-group://${groups[${cert}]},DNS:${cert}\nkeyUsage = digitalSignature") -days 500 -sha256;
	openssl pkcs8 -topk8 -nocrypt -inform PEM -outform PEM -in "${cert}-sign.key" -out "${cert}-sign.pk8.key"

	openssl ecparam -genkey -name prime256v1 -noout -out "${cert}-encrypt.key";
	openssl ec -in "${cert}-encrypt.key" -pubout -out "${cert}-encrypt.pub";
	openssl req -new -sha256 -key "${cert}-encrypt.key" -subj "/C=${C}/ST=${ST}/L=${L}/O=${O}/OU=${OU}/CN=${cert}" -addext "keyUsage=keyAgreement" -addext "subjectAltName = URI:kiebitz-name://${cert},URI:kiebitz-group://${groups[${cert}]},DNS:${cert}"  -out "${cert}-encrypt.csr";
	openssl x509 -req -in "${cert}-encrypt.csr" -CA root.crt -CAkey root.key -CAcreateserial -out "${cert}-encrypt.crt"  -extensions SANKey -extfile <(printf "[SANKey]\nsubjectAltName = URI:kiebitz-name://${cert},URI:kiebitz-group://${groups[${cert}]},DNS:${cert}\nkeyUsage = keyAgreement") -days 500 -sha256;
done