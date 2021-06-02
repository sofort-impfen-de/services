#!/bin/bash
# This script generates test & development certificates. Not for production use!

# You can addd an entry to this list to generate a certificate for the given
# actors.
declare -a certs=("mediator-1" "notifier-1" "storage-1" "appointments-1" "master-1")
declare -a encryptionKeys=( "encrypt-providerData" )
declare -a signingKeys=("sign-root" "sign-token" )
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

done


for key in "${signingKeys[@]}"
do
	echo "Generating signing keys for ${key}...";

	openssl ecparam -genkey -name prime256v1 -noout -out "${key}.key";
	openssl ec -in "${key}.key" -pubout -out "${key}.pub";
	openssl req -new -sha256 -key "${key}.key" -subj "/C=${C}/ST=${ST}/L=${L}/O=${O}/OU=${OU}/CN=${key}" -addext "keyUsage=digitalSignature" -addext "subjectAltName = URI:kiebitz-name://${key},URI:kiebitz-group://${groups[${key}]},DNS:${key}"  -out "${key}.csr";
	openssl x509 -req -in "${key}.csr" -CA root.crt -CAkey root.key -CAcreateserial -out "${key}.crt"  -extensions SANKey -extfile <(printf "[SANKey]\nsubjectAltName = URI:kiebitz-name://${key},URI:kiebitz-group://${groups[${key}]},DNS:${key}\nkeyUsage = digitalSignature") -days 500 -sha256;
	openssl pkcs8 -topk8 -nocrypt -inform PEM -outform PEM -in "${key}.key" -out "${key}.pk8.key"
done

for key in "${encryptionKeys[@]}"
do
	echo "Generating encryption keys for ${key}...";

	openssl ecparam -genkey -name prime256v1 -noout -out "${key}.key";
	openssl ec -in "${key}.key" -pubout -out "${key}.pub";
	openssl req -new -sha256 -key "${key}.key" -subj "/C=${C}/ST=${ST}/L=${L}/O=${O}/OU=${OU}/CN=${key}" -addext "keyUsage=keyAgreement" -addext "subjectAltName = URI:kiebitz-name://${key},URI:kiebitz-group://${groups[${key}]},DNS:${key}"  -out "${key}.csr";
	openssl x509 -req -in "${key}.csr" -CA root.crt -CAkey root.key -CAcreateserial -out "${key}.crt"  -extensions SANKey -extfile <(printf "[SANKey]\nsubjectAltName = URI:kiebitz-name://${key},URI:kiebitz-group://${groups[${key}]},DNS:${key}\nkeyUsage = keyAgreement") -days 500 -sha256;
	openssl pkcs8 -topk8 -nocrypt -inform PEM -outform PEM -in "${key}.key" -out "${key}.pk8.key"
done