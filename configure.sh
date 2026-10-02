#!/usr/bin/env bash
# Interactive secret setup. Asks each key one by one (hidden input), explains
# where to get it, optionally validates it, and writes it into .env.
# Secrets are never echoed nor logged. Press Enter to keep the current value.
source "$(dirname "$0")/scripts/_common.sh"
ensure_env

# Write KEY=value into .env without interpreting special characters.
set_env() {
  local key="$1" tmp
  tmp="$(mktemp)"
  K="$key" V="$2" awk 'BEGIN{k=ENVIRON["K"]; v=ENVIRON["V"]; done=0}
    index($0, k"=")==1 {print k"="v; done=1; next} {print}
    END{if(!done) print k"="v}' .env >"$tmp" && cat "$tmp" >.env && rm -f "$tmp"
}

current() { grep -E "^$1=" .env | head -1 | cut -d= -f2-; }

# HTTP status of a request whose auth header is passed via stdin (keeps the
# secret out of the process list).
http_code_with_header() {
  local header="$1" url="$2"
  printf '%s' "$header" | curl -s -m 20 -o /dev/null -w '%{http_code}' -H @- "$url" || echo "000"
}

validate() {
  local key="$1" v="$2" code
  case "$key" in
    ANTHROPIC_API_KEY)
      code=$(printf 'x-api-key: %s\nanthropic-version: 2023-06-01' "$v" \
        | curl -s -m 20 -o /dev/null -w '%{http_code}' -H @- https://api.anthropic.com/v1/models) ;;
    GITHUB_TOKEN)   code=$(http_code_with_header "Authorization: Bearer $v" https://api.github.com/rate_limit) ;;
    NVD_API_KEY)    code=$(http_code_with_header "apiKey: $v" "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1") ;;
    BRAVE_SEARCH_API_KEY) code=$(http_code_with_header "X-Subscription-Token: $v" "https://api.search.brave.com/res/v1/web/search?q=cve&count=1") ;;
    SHODAN_API_KEY) code=$(printf 'url = "https://api.shodan.io/api-info?key=%s"' "$v" | curl -s -m 20 -o /dev/null -w '%{http_code}' -K - ) ;;
    *) return 0 ;;
  esac
  if [[ "$code" == "200" ]]; then echo "    ✔ clé valide (HTTP 200)"
  else echo "    ✘ échec de validation (HTTP $code) — valeur enregistrée quand même, à vérifier"; fi
}

ask() {
  local key="$1" help="$2" secret="${3:-yes}" value cur
  cur="$(current "$key")"
  echo
  echo "── $key ${cur:+(déjà renseigné)}"
  echo -e "$help" | sed 's/^/   /'
  if [[ "$secret" == "yes" ]]; then read -r -s -p "   Valeur (Entrée = inchangé) : " value; echo
  else read -r -p "   Valeur (Entrée = inchangé) : " value; fi
  if [[ -z "$value" ]]; then
    if [[ -n "$cur" ]]; then echo "    → inchangé"; else echo "    → vide : source/canal désactivé"; fi
    return
  fi
  set_env "$key" "$value"
  echo "    → enregistré"
  validate "$key" "$value"
}

cat <<'EOF'
==========================================================
 Configuration des clés API — CTI Vuln Watch
 Toute clé laissée vide désactive seulement la source ou le
 canal concerné. Relançable à tout moment : ./configure.sh
==========================================================
EOF

echo; echo "### Essentiel"
ask ANTHROPIC_API_KEY "Claude (résumé FR + extraction JSON). https://console.anthropic.com/settings/keys\nCréer une clé dédiée à ce projet, avec une limite de dépense."
ask NVD_API_KEY "NVD API 2.0 — gratuit, reçu par email. https://nvd.nist.gov/developers/request-an-api-key\nSans clé : 5 requêtes / 30 s (fonctionne, mais lent)."
ask GITHUB_TOKEN "GitHub — Security Advisories + recherche de dépôts PoC (métadonnées seulement).\nhttps://github.com/settings/personal-access-tokens > Fine-grained, 'Public repositories (read-only)', aucune permission supplémentaire."

echo; echo "### Notifications (vide = mode dry-run : logs + interface web)"
ask TEAMS_WEBHOOK_URL_FR "Teams, canal équipe France : dans le canal > ... > Workflows >\n'Post to a channel when a webhook request is received' > copier l'URL." yes
ask TEAMS_WEBHOOK_URL_KR "Teams, canal équipe Corée (même procédure). Vide = tout part sur le canal France." yes

echo; echo "### Optionnel (phase 2) — Entrée pour passer"
ask BRAVE_SEARCH_API_KEY "Brave Search API (recherche large). https://api-dashboard.search.brave.com/ — offre gratuite limitée."
ask SHODAN_API_KEY "Shodan (exposition passive). https://account.shodan.io/ — la recherche par net:/hostname: nécessite un compte payant (Membership)."
ask CENSYS_API_ID "Censys — https://search.censys.io/account/api (l'accès API gratuit est très limité)." no
ask CENSYS_API_SECRET "Censys secret."
ask VULNCHECK_API_KEY "VulnCheck KEV — https://vulncheck.com/ (offre communautaire gratuite)."
ask ATTACKERKB_API_KEY "AttackerKB (Rapid7) — https://attackerkb.com/ > profil > API key."

echo
echo "SMTP et JIRA seront demandés en phase 2. Terminé : secrets écrits dans .env (non versionné)."
