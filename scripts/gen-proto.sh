#!/bin/sh

set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
proto_root="$repository_root/refs/EternalTerminal/proto"
output_root="$repository_root/Sources/ETCore/Proto"

if ! command -v protoc >/dev/null 2>&1; then
  echo "error: protoc is required" >&2
  exit 1
fi

if ! command -v protoc-gen-swift >/dev/null 2>&1; then
  echo "error: protoc-gen-swift is required (brew install swift-protobuf)" >&2
  exit 1
fi

protoc \
  --proto_path="$proto_root" \
  --swift_out="$output_root" \
  --swift_opt=Visibility=Public \
  "$proto_root/ET.proto" \
  "$proto_root/ETerminal.proto"
