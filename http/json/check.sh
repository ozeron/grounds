#!/bin/sh
# runs http_json's checks: builds examples/todo, serves it on 8081, asks
# each route with curl, then the cold check
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
pid=
trap '[ -n "$pid" ] && kill "$pid" 2>/dev/null; rm -rf "$tmp"' EXIT
bend test.bend
bend PROOF.bend
bend examples/todo.bend -o "$tmp/todo" > /dev/null
"$tmp/todo" &
pid=$!
tries=0
until curl -s -o /dev/null "localhost:8081/todos"; do
  tries=$((tries + 1))
  [ "$tries" -lt 100 ] || { echo "server did not start"; exit 1; }
  python3 -c 'import time; time.sleep(0.05)'
done

# want NAME STATUS BODY CURL_ARGS...: the status and body curl gets
want() {
  name=$1; status=$2; body=$3; shift 3
  got=$(curl -s -o "$tmp/body" -w '%{http_code}' "$@")
  [ "$got" = "$status" ] || { echo "$name: want $status, got $got: $(cat "$tmp/body")"; exit 1; }
  [ "$(cat "$tmp/body")" = "$body" ] || { echo "$name: want '$body', got '$(cat "$tmp/body")'"; exit 1; }
  echo "$name: $status $body"
}

u=localhost:8081
j='content-type: application/json'
want "GET /todos" 200 '[{"id":1,"title":"grind beans","done":true},{"id":2,"title":"brew","done":false},{"id":3,"title":"drink","done":false}]' "$u/todos"
want "GET /todos/2" 200 '{"id":2,"title":"brew","done":false}' "$u/todos/2"
want "GET /todos/9" 404 '{"error":"not found"}' "$u/todos/9"
want "GET /todos/x" 404 '{"error":"not found"}' "$u/todos/x"
want "GET /nope" 404 '{"error":"not found"}' "$u/nope"
want "POST /todos" 201 '{"id":4,"title":"mill","done":false}' -H "$j" -d '{"title": "mill", "done": false}' "$u/todos"
want "POST, charset" 201 '{"id":4,"title":"mill","done":true}' -H 'Content-Type: Application/JSON; charset=utf-8' -d '{"title": "mill", "done": true}' "$u/todos"
want "POST, bad JSON" 400 '{"error":"invalid JSON: 1:11: unexpected end of input"}' -H "$j" -d '{"title": ' "$u/todos"
want "POST, wrong type" 400 '{"error":"$.done: expected bool, found string"}' -H "$j" -d '{"title": "mill", "done": "no"}' "$u/todos"
want "POST, no field" 400 '{"error":"$.title: missing"}' -H "$j" -d '{"done": true}' "$u/todos"
want "POST, form" 415 '{"error":"content-type must be application/json"}' -d 'title=mill' "$u/todos"
want "PUT /todos" 405 '{"error":"method not allowed"}' -X PUT "$u/todos"
curl -s -D - -o /dev/null -X PUT "$u/todos" | grep -qi '^allow: GET, POST' || { echo "PUT /todos: no Allow: GET, POST"; exit 1; }
echo "PUT /todos: Allow: GET, POST"

python3 ../../json/scripts/cold.py "$PWD/examples/todo.bend"
