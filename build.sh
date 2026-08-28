#!/usr/bin/env bash

# The UI is server-rendered Go templates embedded via //go:embed, so there is
# no asset build step.

CGO_ENABLED=1 GOOS=linux GOARCH=${GOARCH:-amd64} go build -a -tags netgo -ldflags "-linkmode external -extldflags -static -s -w" $@
