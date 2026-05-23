#!/bin/bash
# ActPlane agent-policy corpus collector.
# Finds popular *code* projects (not awesome-lists/doc/skill collections) in the
# AI-agent space that ship a CLAUDE.md or AGENTS.md, sorted by stars desc, and saves
# one folder per repo: the raw file(s) + meta.json. Applies a code-project filter and
# a fake-star authenticity filter (the AI-agent niche is heavily star-inflated).
# Reproducible: every API query + every exclusion is logged. See corpus/README.md.
# Usage: bash corpus/collect.sh [TARGET_HITS]
set -u
cd "$(dirname "$0")"
OUT="."
TARGET="${1:-50}"
PROBE_CAP=950
MINSIZE=500   # size floor (bytes): files smaller than this are saved but flagged excluded
CAND="$(mktemp)"; SEEDM="$(mktemp)"
QLOG="$OUT/queries.log"; XLOG="$OUT/exclusions.log"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
: > "$QLOG"; : > "$XLOG"
echo "collection_started=$NOW" >> "$QLOG"

META_JQ='{full_name, stars: .stargazers_count, forks: .forks_count, issues: .open_issues_count, created_at, language, license: (.license.key // null), fork, archived, pushed_at, default_branch, html_url, description, topics}'

emit() {
  gh api -X GET search/repositories -f q="$1" -f sort=stars -f order=desc -f per_page=100 \
    --jq ".items[] | $META_JQ" 2>>"$QLOG"
}

echo ">> gathering candidates via topic/keyword search"
QUERIES=(
  'topic:ai-agent stars:>300' 'topic:ai-agents stars:>300' 'topic:llm-agent stars:>300'
  'topic:autonomous-agents stars:>300' 'topic:agent stars:>1500' 'topic:llm stars:>4000'
  'topic:mcp stars:>800' 'topic:coding-agent stars:>100' 'topic:ai-coding stars:>300'
  'topic:ai-assistant stars:>1000' 'openclaw stars:>200' 'claw agent stars:>500'
  'AI agent framework stars:>3000' 'coding agent stars:>2000'
  'llm agent in:name,description stars:>2500'
)
for q in "${QUERIES[@]}"; do
  echo "search q=[$q] at $(date -u +%H:%M:%S)" >> "$QLOG"
  emit "$q" >> "$CAND"
  sleep 2.2
done

# Known-real agent code projects, probed regardless of the type filter.
# OpenClaw ecosystem (the 2026 breakout platform) + classic agent frameworks/tools.
SEEDS=(
  openclaw/openclaw openclaw/lobster HKUDS/ClawWork HKUDS/ClawTeam HKUDS/nanobot
  NVIDIA/NemoClaw agentscope-ai/HiClaw ValueCell-ai/ClawX BlockRunAI/ClawRouter
  Gen-Verse/OpenClaw-RL Martian-Engineering/lossless-claw zeroclaw-labs/zeroclaw
  farion1231/cc-switch MervinPraison/PraisonAI moeru-ai/airi AstrBotDevs/AstrBot
  zhayujie/CowAgent NousResearch/hermes-agent thedotmack/claude-mem
  OpenHands/OpenHands Aider-AI/aider cline/cline Significant-Gravitas/AutoGPT
  geekan/MetaGPT AntonOsika/gpt-engineer continuedev/continue block/goose
  SWE-agent/SWE-agent langchain-ai/langchain run-llama/llama_index crewAIInc/crewAI
  langgenius/dify microsoft/autogen OpenInterpreter/open-interpreter
  RooCodeInc/Roo-Code anomalyco/opencode QwenLM/qwen-code google-gemini/gemini-cli
  browser-use/browser-use FoundationAgents/OpenManus punkpeye/fastmcp
  modelcontextprotocol/servers
)
echo ">> fetching seed metadata"
for s in "${SEEDS[@]}"; do
  gh api "repos/$s" --jq "$META_JQ + {seed: true}" 2>>"$QLOG" >> "$SEEDM"
done

RANKED="$(mktemp)"
cat "$CAND" "$SEEDM" | jq -s 'map(select(.full_name)) | group_by(.full_name) | map(add) | sort_by(-(.stars // 0))' > "$RANKED"
echo "candidates_unique=$(jq 'length' "$RANKED")" >> "$QLOG"
echo ">> $(jq 'length' "$RANKED") unique candidates ranked by stars"

# --- Filters ---------------------------------------------------------------
# (1) Repo-type filter: drop doc / tutorial / aggregator / skill-collection repos.
EXCL_TYPE='awesome|curated|list-of|^list$|prompt|cheat.?sheet|handbook|tutorial|roadmap|^guide|guides|papers?|reading|^book|course|interview|leetcode|^resources?|collection|beginners|best.?practice|skills?$|skill-|curriculum|cookbook|examples?$|samples?$|starter|boilerplate|template|demos?$|for-beginners|directory|registry|claw.?hub|skill.?hub|/agents$|/prompts$'
# (2) Manually adjudicated exclusions: confirmed fake-star / SEO-hype repos
#     (impossible velocity, mass-fork, zero engagement, "fastest repo ever" spam),
#     plus doc/skill collections that slip the regex. Lowercased, full match.
read -r -d '' EXCLUDE_LIST <<'EOF'
affaan-m/ecc
juliusbrussee/caveman
mempalace/mempalace
nexu-io/open-design
santifer/career-ops
zhulinsen/daily_stock_analysis
ultraworkers/claw-code
ultraworkers/claw-code-parity
microsoft/ai-agents-for-beginners
shanraisshan/claude-code-best-practice
addyosmani/agent-skills
wshobson/agents
voltagent/awesome-openclaw-skills
kepano/obsidian-skills
openclaw/clawhub
safishamsi/graphify
EOF

is_code_project() { # name(lower) language seed
  [ "$3" = "true" ] && return 0
  case "$2" in null|Markdown|"") return 1;; esac
  echo "$1" | grep -Eiq "$EXCL_TYPE" && return 1
  return 0
}
# (3) Fake-star authenticity filter (conservative; seeds bypass).
is_authentic() { # stars forks issues created seed
  [ "$5" = "true" ] && return 0
  local s="$1" f="$2" i="$3" c="$4" yr mo age
  yr="${c:0:4}"; mo="${c:5:2}"
  age=$(( (2026 - 10#${yr:-2026})*12 + 5 - 10#${mo:-05} ))
  [ "$s" -gt 10000 ] && [ "$f" -gt $(( s*8/10 )) ] && return 1   # mass-fork bots
  [ "$s" -gt 40000 ] && [ "$i" -lt 20 ] && return 1             # no engagement at scale
  [ "$age" -le 2 ] && [ "$s" -gt 40000 ] && return 1           # impossible star velocity
  return 0
}

echo ">> probing for CLAUDE.md / AGENTS.md (target $TARGET hits)"
hits=0; probed=0
MANIFEST="$OUT/manifest.jsonl"; : > "$MANIFEST"

probe_file() { # full path dir family
  local full="$1" path="$2" dir="$3" family="$4" meta sha size lc lcsha lcdate csha
  meta="$(gh api "repos/$full/contents/$path" --jq '.sha+" "+(.size|tostring)' 2>/dev/null)" || return 1
  sha="${meta%% *}"; size="${meta##* }"
  mkdir -p "$dir"
  gh api "repos/$full/contents/$path" -H "Accept: application/vnd.github.raw" > "$dir/$path" 2>/dev/null || { rm -f "$dir/$path"; return 1; }
  lc="$(gh api "repos/$full/commits?path=$path&per_page=1" --jq '.[0].sha+" "+.[0].commit.committer.date' 2>/dev/null)"
  lcsha="${lc%% *}"; lcdate="${lc##* }"
  csha="$(sha256sum "$dir/$path" | cut -d' ' -f1)"
  jq -nc --arg family "$family" --arg path "$path" --arg blob "$sha" --arg size "$size" \
        --arg lcsha "$lcsha" --arg lcdate "$lcdate" --arg csha "$csha" \
        --arg raw "https://raw.githubusercontent.com/$full/${lcsha:-HEAD}/$path" \
    '{family:$family,path:$path,blob_sha:$blob,byte_size:($size|tonumber),last_commit_sha:$lcsha,last_commit_date:$lcdate,content_sha256:$csha,raw_url:$raw}' >> "$dir/.files.ndjson"
}

while read -r row; do
  [ "$hits" -ge "$TARGET" ] && break
  [ "$probed" -ge "$PROBE_CAP" ] && break
  probed=$((probed+1))
  full="$(jq -r '.full_name' <<<"$row")"
  name="$(jq -r '.full_name|ascii_downcase' <<<"$row")"
  lang="$(jq -r '.language // "null"' <<<"$row")"
  seed="$(jq -r '.seed // false' <<<"$row")"
  stars="$(jq -r '.stars // 0' <<<"$row")"
  forks="$(jq -r '.forks // 0' <<<"$row")"
  issues="$(jq -r '.issues // 0' <<<"$row")"
  created="$(jq -r '.created_at // "2026-05"' <<<"$row")"
  if grep -qixF "$name" <<<"$EXCLUDE_LIST"; then echo "$full reason=manual-exclude(fake/doc)" >>"$XLOG"; continue; fi
  is_code_project "$name" "$lang" "$seed" || { echo "$full reason=type-filter lang=$lang" >>"$XLOG"; continue; }
  is_authentic "$stars" "$forks" "$issues" "$created" "$seed" || { echo "$full reason=authenticity stars=$stars forks=$forks issues=$issues created=$created" >>"$XLOG"; continue; }
  dir="$OUT/${full//\//__}"; rm -f "$dir/.files.ndjson"
  probe_file "$full" "CLAUDE.md" "$dir" "CLAUDE.md"
  probe_file "$full" "AGENTS.md" "$dir" "AGENTS.md"
  if [ -f "$dir/.files.ndjson" ]; then
    files="$(jq -s '.' "$dir/.files.ndjson")"; rm -f "$dir/.files.ndjson"
    bytes=$(cat "$dir"/CLAUDE.md "$dir"/AGENTS.md 2>/dev/null | wc -c)
    ex=false; rsn=""
    if [ "$bytes" -lt "$MINSIZE" ]; then ex=true; rsn="size<${MINSIZE}B (${bytes}B)"; echo "$full reason=$rsn" >>"$XLOG"; fi
    jq -n --argjson r "$row" --argjson files "$files" --arg now "$NOW" --argjson ex "$ex" --arg rsn "$rsn" \
      '{repo:$r.full_name, owner:($r.full_name|split("/")[0]), name:($r.full_name|split("/")[1]),
        stars:$r.stars, forks:$r.forks, open_issues:$r.issues, created_at:$r.created_at,
        language:$r.language, license:$r.license, fork:$r.fork, archived:$r.archived,
        pushed_at:$r.pushed_at, default_branch:$r.default_branch, html_url:$r.html_url,
        description:$r.description, topics:$r.topics, seed:($r.seed//false),
        domain:"", retrieved_at:$now, excluded:$ex, exclude_reason:$rsn, files:$files}' > "$dir/meta.json"
    jq -c '.' "$dir/meta.json" >> "$MANIFEST"
    if [ "$ex" = false ]; then
      hits=$((hits+1))
      printf '  [%2d] %-44s ★%-7s %s\n' "$hits" "$full" "$stars" "$(jq -r '[.files[].family]|join(",")' "$dir/meta.json")"
    fi
  else
    rmdir "$dir" 2>/dev/null
  fi
done < <(jq -c '.[]' "$RANKED")

echo "collection_finished=$(date -u +%Y-%m-%dT%H:%M:%SZ) hits=$hits probed=$probed excluded=$(wc -l <"$XLOG")" >> "$QLOG"
echo ">> done: $hits repos saved (probed $probed, excluded $(wc -l <"$XLOG")). manifest=$MANIFEST exclusions=$XLOG"
rm -f "$CAND" "$SEEDM" "$RANKED"
