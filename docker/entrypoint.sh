#!/bin/sh
# Shape egress for this node's region, then start the node. NETEM=0 skips shaping (smoke tests).
set -e
if [ "${NETEM:-1}" = 1 ]; then
  sh "/config/tc/${REGION}.sh"
fi
exec /usr/local/bin/fastsim "$@"
