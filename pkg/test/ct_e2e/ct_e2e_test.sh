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
        git clone https://github.com/sigstore/${repo}.git
    fi
done

docker_compose="docker compose"

pushd ./certificate-transparency-go/trillian/examples/deployment/docker/ctfe/
docker compose up -d
until [ $(${docker_compose} ps | grep -c "(healthy)") == 1 ];
    do
        if [ $count -eq 6 ]; then
           echo "! timeout reached"
           exit 1
        else
           echo -n "."
           sleep 5
           let 'count+=1'
        fi
    done
popd

docker exec -i ctfe-db mariadb -pzaphod -Dtest < ./trillian/storage/mysql/schema/storage.sql
docker exec -i ctfe-db mariadb -pzaphod -Dtest < ./certificate-transparency-go/trillian/ctfe/storage/mysql/schema.sql

CTFE_CONF_DIR=/tmp/ctfedocker
if [ -d $CTFE_CONF_DIR ]; then
  mkdir ${CTFE_CONF_DIR}
fi

TREE_ID=$(go run github.com/google/trillian/cmd/createtree@master --admin_server=localhost:8090)
sed "s/@TREE_ID@/${TREE_ID}/" ./certificate-transparency-go/trillian/examples/deployment/docker/ctfe/ct_server.cfg > ${CTFE_CONF_DIR}/ct_server.cfg
cp ./certificate-transparency-go/trillian/testdata/fake-ca.cert ${CTFE_CONF_DIR}
docker volume create --driver local --opt type=none --opt device=${CTFE_CONF_DIR} --opt o=bind ctfe_config

pushd ./certificate-transparency-go/trillian/examples/deployment/docker/ctfe/
docker compose down
docker compose --profile frontend up -d
until [ $(${docker_compose} ps | grep -c "(healthy)") == 1 ];
    do
        if [ $count -eq 6 ]; then
           echo "! timeout reached"
            exit 1
        else
           echo -n "."
           sleep 5
           let 'count+=1'
        fi
    done
popd

popd
go test -tags=ct_e2e -v -race ./pkg/test/ct_e2e/...

pushd $HOME
pushd ./certificate-transparency-go/trillian/examples/deployment/docker/ctfe/
docker compose down
popd