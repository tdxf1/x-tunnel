#!/usr/bin/env sh
set -eu

version="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
commit="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
build_date="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
out="${OUT:-x-tunnel}"

go build \
  -ldflags "-s -w -X main.buildVersion=${version} -X main.buildCommit=${commit} -X main.buildDate=${build_date}" \
  -o "${out}" \
  .

printf 'built %s version=%s commit=%s build=%s\n' "${out}" "${version}" "${commit}" "${build_date}"
