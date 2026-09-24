#!/usr/bin/env bash
# Start the bot against one or more GPU boxes (already set up with ./deploy.sh).
#   ./run.sh "ssh -p 41234 root@ssh4.vast.ai" ["ssh -p 22 root@1.2.3.4" ...]        live (needs a funded hot wallet)
#   DRY=1 ./run.sh "ssh -p 41234 root@ssh4.vast.ai"                                    dry run: nothing is sent
cd "$(dirname "$0")"
args=()
for b in "$@"; do args+=(--backend "$b"); done
[ ${#args[@]} -gt 0 ] || { echo "usage: $0 \"ssh -p PORT root@HOST\" [...]"; exit 2; }
[ -n "${DRY:-}" ] && args+=(--dry-run --verify-hits)
exec .venv/bin/python bot.py "${args[@]}" ${BOT_ARGS:-}
