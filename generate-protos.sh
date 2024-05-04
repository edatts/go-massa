#!/bin/bash

mkdir proto-gen

# Get protos from massa-proto repo
curl -sSL https://github.com/massalabs/massa-proto/archive/main.zip -o proto-gen/massa-proto.zip

cd proto-gen

unzip massa-proto.zip

cd massa-proto-main

cat > buf.gen.yaml << EOF
version: v1
plugins:
  - plugin: go
    out: gen/go
    opt: paths=source_relative
  - plugin: go-grpc
    out: gen/go
    opt: paths=source_relative,require_unimplemented_servers=false
EOF

arr=("./proto/abis/massa/abi/v1" "./proto/apis/massa/api/v1" "./proto/commons/massa/model/v1")

for dir in "${arr[@]}"
do
    for filename in "$dir"/*.proto; do
        sed -i 's/option go_package = "github.com\/massalabs/option go_package = "github.com\/edatts\/go-massa\/protos/' $filename
    done
done

buf generate

cp -r gen/go/* ../../protos/

cd ../..

rm -rf proto-gen/