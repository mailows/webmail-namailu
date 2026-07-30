#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
  echo "Release se smí stavět jen z čistého pracovního stromu." >&2
  exit 1
fi
if ! command -v trivy >/dev/null 2>&1; then
  echo "Trivy je povinná release brána; bez něj se webmail image nesmí vydat." >&2
  exit 1
fi

head_sha="$(git rev-parse --verify HEAD)"
sha="$(git rev-parse --verify "${1:-HEAD}^{commit}")"
if [[ "$sha" != "$head_sha" ]]; then
  echo "Požadované SHA $sha není aktuální checkout $head_sha." >&2
  exit 1
fi

image="namailu/webmail:git-$sha"
docker build \
  --build-arg "GIT_COMMIT=$sha" \
  --label "org.opencontainers.image.revision=$sha" \
  --tag "$image" \
  .

# Blokují se jen nálezy, pro které dnes existuje oprava. Unfixed nálezy z base
# image zůstávají viditelné ve výstupu a odstraní je nejbližší rebuild po vydání
# opraveného Alpine/Node image.
trivy image \
  --scanners vuln \
  --severity HIGH,CRITICAL \
  --ignore-unfixed \
  --exit-code 1 \
  "$image"

docker image inspect \
  --format 'image={{index .RepoTags 0}} id={{.Id}} revision={{index .Config.Labels "org.opencontainers.image.revision"}}' \
  "$image"
