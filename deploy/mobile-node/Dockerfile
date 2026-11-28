# ARTEX mobile node (Linux/KVM) — TEMPLATE, validate on a /dev/kvm host.
#
# Builds the node-agent from the ARTEX repo, then layers it plus Frida/Objection
# onto an Android-emulator base. BASE_IMAGE is intentionally left to you: pick an
# emulator image that matches your host architecture and KVM, and PIN it by
# digest before production. Build context must be the repo root (see the compose
# file), because the agent is compiled from ./cmd/mobile-node-agent.
# syntax=docker/dockerfile:1

ARG BASE_IMAGE=budtmo/docker-android:emulator_14.0

FROM golang:1.26-bookworm AS agent
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/mobile-node-agent ./cmd/mobile-node-agent

FROM ${BASE_IMAGE}
# Dynamic instrumentation tooling on the node. frida-server itself is pushed to
# the emulator at runtime by the entrypoint (its version must match the device).
USER root
RUN pip3 install --no-cache-dir frida-tools objection \
    || echo "WARN: install frida-tools/objection manually for your base image"
COPY --from=agent /out/mobile-node-agent /usr/local/bin/mobile-node-agent
COPY deploy/mobile-node/entrypoint.sh /usr/local/bin/mobile-node-entrypoint.sh
RUN chmod +x /usr/local/bin/mobile-node-entrypoint.sh
# Expose nothing: the node dials OUT to core. adb stays on loopback.
ENTRYPOINT ["/usr/local/bin/mobile-node-entrypoint.sh"]
