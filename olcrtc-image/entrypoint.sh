#!/bin/sh
set -e

: "${PROVIDER:=jitsi}"
: "${TRANSPORT:=datachannel}"
: "${DNS:=8.8.8.8:53}"
: "${DEBUG:=false}"

if [ -z "$ROOM_ID" ] || [ -z "$ENC_KEY" ]; then
    echo "ROOM_ID and ENC_KEY env vars are required" >&2
    exit 1
fi

cat > /tmp/server.yaml <<EOF
mode: srv
auth:
  provider: ${PROVIDER}
room:
  id: "${ROOM_ID}"
crypto:
  key: "${ENC_KEY}"
net:
  transport: ${TRANSPORT}
  dns: "${DNS}"
data: /tmp/data
debug: ${DEBUG}
EOF

exec /usr/local/bin/olcrtc /tmp/server.yaml
