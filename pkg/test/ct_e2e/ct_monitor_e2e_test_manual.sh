#!/usr/bin/env bash
#
# Copyright 2024 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -ex

pushd $HOME

echo "downloading service repos"
for repo in certificate-transparency-go trillian; do
    if [[ ! -d $repo ]]; then
        git clone https://github.com/google/${repo}.git
    fi
done

die() {
  echo "$*" > /dev/stderr
  exit 1
}

collect_vars() {
  # set unset environment variables to defaults
#   [ -z ${MYSQL_ROOT_USER+x} ] && MYSQL_ROOT_USER="test"
  [ -z ${MYSQL_HOST+x} ] && MYSQL_HOST="127.0.0.1"
  [ -z ${MYSQL_PORT+x} ] && MYSQL_PORT="3306"
  [ -z ${MYSQL_DATABASE+x} ] && MYSQL_DATABASE="test"
#   [ -z ${MYSQL_USER+x} ] && MYSQL_USER="test"
#   [ -z ${MYSQL_PASSWORD+x} ] && MYSQL_PASSWORD="zaphod"
#   [ -z ${MYSQL_ROOT_PASSWORD+x} ] && MYSQL_ROOT_PASSWORD="zaphod"
  [ -z ${MYSQL_USER_HOST+x} ] && MYSQL_USER_HOST="127.0.0.1"
  FLAGS=()

  # handle flags
  FORCE=false
  VERBOSE=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --force) FORCE=true ;;
      --verbose) VERBOSE=true ;;
      --help) usage; exit ;;
      *) FLAGS+=("$1")
    esac
    shift 1
  done

  FLAGS+=(-u "${MYSQL_ROOT_USER}")
  FLAGS+=(--host "${MYSQL_HOST}")
  FLAGS+=(--port "${MYSQL_PORT}")

  # Optionally print flags (before appending password)
  [[ ${VERBOSE} = 'true' ]] && echo "- Using MySQL Flags: ${FLAGS[@]}"

  # append password if supplied
#   [ -z ${MYSQL_ROOT_PASSWORD+x} ] || FLAGS+=(-p"${MYSQL_ROOT_PASSWORD}")
}

main() {
  collect_vars "$@"

  readonly TRILLIAN_PATH=$(go list -f '{{.Dir}}' github.com/google/trillian)

  echo "Warning: about to destroy and reset database '${MYSQL_DATABASE}'"
  echo "Resetting DB..."
  mysql "${FLAGS[@]}" -e "DROP DATABASE IF EXISTS ${MYSQL_DATABASE};" || \
  die "Error: Failed to drop database '${MYSQL_DATABASE}'."
  mysql "${FLAGS[@]}" -e "CREATE DATABASE ${MYSQL_DATABASE};" || \
  die "Error: Failed to create database '${MYSQL_DATABASE}'."
#   mysql "${FLAGS[@]}" -e "CREATE USER IF NOT EXISTS ${MYSQL_USER}@'${MYSQL_USER_HOST}' IDENTIFIED BY '${MYSQL_PASSWORD}';" || \
#   die "Error: Failed to create user '${MYSQL_USER}@${MYSQL_USER_HOST}'."
#   mysql "${FLAGS[@]}" -e "GRANT ALL ON ${MYSQL_DATABASE}.* TO ${MYSQL_USER}@'${MYSQL_USER_HOST}'" || \
#   die "Error: Failed to grant '${MYSQL_USER}' user all privileges on '${MYSQL_DATABASE}'."
  mysql "${FLAGS[@]}" -D ${MYSQL_DATABASE} < ./trillian/storage/mysql/schema/storage.sql || \
  die "Error: Failed to create tables in '${MYSQL_DATABASE}' database."
  mysql "${FLAGS[@]}" -D ${MYSQL_DATABASE} < ./certificate-transparency-go/trillian/ctfe/storage/mysql/schema.sql || \
  die "Error: Failed to provision logs in '${MYSQL_DATABASE}' database."
  echo "Reset Complete"
}

main "$@"

pushd ./trillian
go run github.com/google/trillian/cmd/trillian_log_server --mysql_uri="root@tcp(127.0.0.1:3306)/test" --rpc_endpoint=:8080 --http_endpoint=:8081 --logtostderr
go run github.com/google/trillian/cmd/trillian_log_signer --mysql_uri="root@tcp(127.0.0.1:3306)/test" --force_master --rpc_endpoint=:8090 --http_endpoint=:8091 --logtostderr
go run github.com/google/trillian/cmd/createtree --admin_server=:8080
popd

pushd ./certificate-transparency-go/trillian/examples/deployment/docker/ctfe/
TRILLIAN_LOG_SERVER_RPC_ENDPOINT=127.0.0.1:8080
go run github.com/google/certificate-transparency-go/trillian/ctfe/ct_server --log_config ./ct_server.cfg --http_endpoint=127.0.0.1:6966 --log_rpc_server ${TRILLIAN_LOG_SERVER_RPC_ENDPOINT} --logtostderr
popd

docker ps
docker container logs ctfe-db

popd
go test -tags=ct_e2e -v -race ./pkg/test/ct_e2e/...
