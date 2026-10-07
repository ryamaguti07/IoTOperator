#!/bin/sh
set -eu

# Credencial vazia faz o boto3 ignorar a cadeia padrão (perfil, role, task role).
for var in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN; do
    eval "val=\${$var-}"
    if [ -z "$val" ]; then
        unset "$var" || true
    fi
done

mkdir -p /data

gunicorn \
    --bind 127.0.0.1:5000 \
    --workers 1 \
    --timeout 120 \
    --access-logfile - \
    --error-logfile - \
    "app:create_app()" &
gpid=$!

nginx -g "daemon off;" &
npid=$!

shutdown() {
    kill "$gpid" "$npid" 2>/dev/null || true
    wait "$gpid" 2>/dev/null || true
    wait "$npid" 2>/dev/null || true
}

trap shutdown TERM INT

while kill -0 "$gpid" 2>/dev/null && kill -0 "$npid" 2>/dev/null; do
    sleep 1
done

shutdown
exit 1
