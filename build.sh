#!/bin/bash

set -e

SCRIPT_DIR="$( dirname -- "$BASH_SOURCE"; )";

export GOROOT=$HOME/go/go1.23.1
export PATH=$GOROOT/bin:$PATH
tinygo build -target wasm -tags "purego noasm" -o node/jscp.wasm ./go/cmd/jscp_wasm/

