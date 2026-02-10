#!/bin/sh
set -e

# Start Next.js dashboard in the background (port 3000 internal)
cd /app/dashboard
HOSTNAME=0.0.0.0 PORT=3000 node server.js &
NEXT_PID=$!

# Wait briefly for Next.js to start
sleep 2

# Start Go server (port 3333, proxies non-API routes to Next.js)
cd /app
export DASHBOARD_URL="http://localhost:3000"
./server &
GO_PID=$!

# Handle shutdown: kill both processes
shutdown() {
  kill "$NEXT_PID" "$GO_PID" 2>/dev/null || true
  wait "$NEXT_PID" "$GO_PID" 2>/dev/null || true
  exit 0
}
trap shutdown SIGTERM SIGINT

# Wait for either process to exit
while kill -0 "$GO_PID" 2>/dev/null && kill -0 "$NEXT_PID" 2>/dev/null; do
  sleep 1
done

# If one dies, stop the other
shutdown
