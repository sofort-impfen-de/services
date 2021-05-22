#!/bin/bash

# This script generates example tracing data using curl. It assumes that all
# services (storage, operator and tracing) are running on their standard ports.

STORAGE=9999
TRACING=8888
OPERATOR=7777

RND () {
	head -c $1 </dev/urandom | base64
}

RPC () {
	echo "{
		\"jsonrpc\": \"2.0\",
		\"method\": \"$1\",
		\"params\": $2,
		\"id\": \"1\"
	}"
}

REQ () {
	curl http://localhost:$1/jsonrpc --header "Content-Type: application/json" --data "$2" 2>/dev/null | jq .
}

SETTINGSID=`RND 16`

echo "Storing settings with ID '$SETTINGSID'"

# we generate some random settings data and store it
DATA="{\"data\" : \"`RND 16`\", \"id\": \"$SETTINGSID\"}"
REQ $STORAGE "`RPC 'storeSettings' \"$DATA\"`"
