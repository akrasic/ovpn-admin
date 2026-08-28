#!/usr/bin/env bash

# The UI is server-rendered Go templates embedded via //go:embed, so there is
# no asset build step.

if [[ "$GOOS" == "linux" ]]; then
  if [[ "$GOARCH" == "arm" ]]; then
    CC=arm-linux-gnueabi-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm go build -a -tags netgo -ldflags "-linkmode external -extldflags -static -s -w" $@
  fi
  if [[ "$GOARCH" == "arm64" ]]; then
    CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -a -tags netgo -ldflags "-linkmode external -extldflags -static -s -w" $@
  fi
fi
