#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.frameworks.yml)

write_python() {
  local service="$1"
  local path="$2"
  docker compose "${COMPOSE_FILES[@]}" exec -T "$service" python -c "from pathlib import Path; p=Path('$path/.write-test'); p.write_text('ok', encoding='utf-8'); print(p.read_text(encoding='utf-8'))"
}

write_promptfoo() {
  docker compose "${COMPOSE_FILES[@]}" exec -T promptfoo-worker node -e "const fs=require('fs'); const p='/artifacts/promptfoo/.write-test'; fs.writeFileSync(p, 'ok'); console.log(fs.readFileSync(p, 'utf8'))"
}

write_python native-worker /artifacts/native
write_python garak-worker /artifacts/garak
write_python pyrit-worker /artifacts/pyrit
if [ "${INCLUDE_DEEPTEAM:-0}" = "1" ]; then
  write_python deepteam-worker /artifacts/deepteam
fi
write_promptfoo

echo "All framework workers can write to their own artifact directories."
