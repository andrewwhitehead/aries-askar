#!/usr/bin/env sh
docker run --rm -p 5432:5432 --name aries-test-postgres -e POSTGRES_PASSWORD=mysecretpassword -d postgres
if [ $? != "0" ]; then
  echo "Error starting postgres container"
  exit 1
fi
echo POSTGRES_URL=postgres://postgres:mysecretpassword@localhost:5432/test-db cargo test --features pg_test
