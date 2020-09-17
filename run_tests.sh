#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

function kill_localstack() {
  docker kill lstack
}

trap kill_localstack EXIT

function start_localstack() {
  cd tests/localstack
  docker run -d --rm --name lstack -v ${PWD}/initaws.d:/docker-entrypoint-initaws.d -p 4566:4566 localstack/localstack:0.11.5
  cd -
  bash -c 'docker logs -f lstack 2>&1 | { sed "/^RUN TESTS NOW$/ q" && kill -9 $$ ;}' || true
}

pipenv sync --dev
start_localstack
pipenv run test
