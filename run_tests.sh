#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Ensure dependencies are present
if [[ ! -x $(command -v git) ]] || [[ ! -x $(command -v docker) ]]; then
    msg_fatal "[-] Dependencies unmet. Please verify that the following are installed and in the PATH: git, docker" >&2
    exit 1
fi

UNAME_OUTPUT=$(uname -s)
case "${UNAME_OUTPUT}" in
    Linux*)
      if [ "$EUID" -eq 0 ]; then
        IF_SUDO=''
      else
        IF_SUDO='sudo'
      fi;;
    *)
      IF_SUDO='';;
esac

export IF_SUDO

function kill_localstack() {
  ${IF_SUDO} docker kill lstack
}

trap kill_localstack EXIT

function start_localstack() {
  cd tests/localstack
  ${IF_SUDO} docker run -d --rm --name lstack -v ${PWD}/initaws.d:/docker-entrypoint-initaws.d -p 4566:4566 localstack/localstack:0.11.5
  cd -
  bash -c '${IF_SUDO} docker logs -f lstack 2>&1 | { sed "/^RUN TESTS NOW$/ q" && kill -9 $$ ;}' || true
}

poetry install
start_localstack
poetry run poe test
