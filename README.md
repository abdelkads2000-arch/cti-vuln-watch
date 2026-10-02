# CTI Vuln Watch

Agent de veille vulnérabilités / CTI pour SOC MSSP.
- Collecte les vulnérabilités auprès de sources de référence, CERT et PSIRT.
- Qualifie la criticité réelle avec des niveaux de preuve **déterministes et sourcés**.
- Croise les vulnérabilités avec le parc clients.
- Détecte les révisions de bulletins et les signaux de contournement de patch.
- Notifie sur Teams, ou en dry-run tant qu'aucun webhook n'est configuré.

> **État : phase 1 (MVP).** Architecture : [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Démonstration : [docs/DEMO.md](docs/DEMO.md).

## Démarrage

Prérequis : un moteur Docker avec Compose v2 (Docker Desktop, **Rancher Desktop** en mode « dockerd (moby) », ou Docker Engine sous Linux). Sous Windows, les scripts se lancent depuis **Git Bash**. Aucune autre dépendance n'est à installer : Python, PostgreSQL et les librairies tournent dans les conteneurs.

```bash
./configure.sh   # (optionnel) saisie des clés API une par une, saisie masquée
./start.sh       # construit et démarre tout, attend les healthchecks
```

## Commandes

| Action | Commande |
|---|---|
| Saisir / modifier les clés API | `./configure.sh` |
| Tout démarrer | `./start.sh` |
| Tout arrêter (données conservées) | `./stop.sh` |
| Suivre les logs | `./logs.sh [worker\|db\|backup]` |
| Réinitialiser la base (destructif, confirmation) | `./reset.sh` |
| Lancer les tests (dans un conteneur, sans réseau) | `./test.sh` |
| CLI de l'agent | `./cti <commande>` |

### CLI (`./cti ...`)

| Commande | Rôle |
|---|---|
| `run [--source NOM] [--no-notify]` | Collecte immédiate + traitement |
| `status` | Santé des sources, volumes, alertes 24 h, latence de détection |
| `show CVE-AAAA-NNNN` | Fiche détaillée : niveau de preuve, preuves et citations, versions corrigées, clients, provenance de chaque champ |
| `watchlist add CVE --days 30 --reason "..."` / `remove` / `list` | Surveillance renforcée |
| `source list` / `test NOM` / `add NOM URL --type rss --role press --tier 3` | Registre des sources (`test` = collecte à blanc) |
| `source enable NOM` / `disable NOM` / `observe NOM` | Validation humaine (une source ajoutée démarre en « observation ») |
| `test-notify [--team fr\|kr]` | Notification de test |
| `digest` | Envoi immédiat du digest P3 |

## Fonctionnement en bref

1. **Collecte** : un job par source, à l'intervalle défini dans [config/sources.yaml](config/sources.yaml). Les requêtes conditionnelles (ETag/If-Modified-Since), le backoff et robots.txt sont gérés pour les pages HTML.
2. **Preuves** : chaque affirmation (exploitée, PoC, contournement, révision) est une ligne `evidence` avec une **URL obligatoire** et la citation exacte.
3. **Niveau de preuve** : il est calculé par des règles fixes à partir du *type* de source (éditeur/CERT = confirmé ; recherche/presse = rapporté). Le LLM ne décide jamais du niveau.
4. **Confiance** : `1 − Π(1 − fiabilité)` sur les domaines indépendants, avec une pénalité si l'éditeur dément. Les contradictions sont signalées, jamais arbitrées.
5. **Matching** : la comparaison se fait par alias et par CPE, puis par version **branche par branche** (« 13.1-64.23 » n'est pas jugée vulnérable parce que « < 14.1-73.37 »). Une version inconnue donne « version à confirmer ».
6. **Priorité** : les règles sont déclaratives ([config/priority.yaml](config/priority.yaml)). Des signaux faibles seuls ne déclenchent jamais de P1/P2.
7. **Notification** : le routage follow-the-sun est défini dans [config/routing.yaml](config/routing.yaml), en FR ou EN. La déduplication stricte repose sur une empreinte d'état (niveau, clients, révisions, patch, contournement).

### Premier démarrage (historique)
Au premier passage d'une source, son historique est chargé (par exemple les ~1 700 entrées KEV). Ces données n'alertent **que si elles sont récentes** (`backfill_notify_days`, 7 jours par défaut) ou si la CVE est dans la watchlist. Cela évite une avalanche d'alertes sur d'anciennes CVE.

### Clés API (toutes optionnelles)
Une clé absente désactive seulement la fonction concernée.

| Clé | Effet si absente |
|---|---|
| `ANTHROPIC_API_KEY` | Pas de résumé FR ni d'extraction LLM (IoC, mitigations) ; le pipeline déterministe fonctionne |
| `NVD_API_KEY` | NVD limité à 5 requêtes / 30 s (fonctionne, plus lentement) |
| `GITHUB_TOKEN` | GitHub Advisories et cvelistV5 limités à 60 requêtes/h |
| `TEAMS_WEBHOOK_URL_FR` / `_KR` | Mode **dry-run** : alertes dans les logs (`./logs.sh worker`) et en base |

### Inventaire clients
- [config/inventory.example.yaml](config/inventory.example.yaml) est **fictif**.
- L'inventaire réel se place dans `config/inventory.yaml`, **exclu du dépôt** par `.gitignore`. S'il existe, il est utilisé à la place de l'exemple.
- Les alias produits sont dans [config/product_aliases.yaml](config/product_aliases.yaml).

### Ajouter une source sans code
```bash
./cti source add monblog https://exemple.org/feed.xml --type rss --role research --tier 2
./cti source test monblog     # aperçu, rien n'est enregistré
./cti source enable monblog   # validation humaine : la source peut désormais alerter
```
Types génériques disponibles :
- `rss`, avec les options `fetch_article` et `content_selector` ;
- `json_api`, avec `items_path` et un mapping `fields`.

## Sauvegardes
- Les sauvegardes quotidiennes sont écrites dans `./backups/cti_AAAAMMJJ_HHMMSS.dump` (format pg_dump custom).
- La rétention se règle avec `BACKUP_RETENTION_DAYS`.
- Restauration :
```bash
docker compose exec -T db pg_restore -U cti -d cti --clean < backups/<fichier>.dump
```

## Sécurité
- **Aucun code d'exploit** n'est cloné, téléchargé ni exécuté ; seules des métadonnées sont collectées.
- Tout contenu collecté est traité comme une **donnée non fiable** :
  - le HTML est nettoyé (contenu masqué, caractères invisibles) ;
  - le contenu est balisé avant d'être envoyé au LLM ;
  - le LLM n'a aucun outil et sa sortie JSON est validée ;
  - toute citation est **vérifiée mot pour mot**.
- Les conteneurs tournent en utilisateur non-root, avec un système de fichiers en lecture seule et `no-new-privileges`.
- Les secrets ne vont que dans `.env` (non versionné) et sont **masqués dans les logs**.
- Aucun scan actif.

## Dépannage
- **« Docker introuvable »** : installer un moteur Docker. Sous Windows, WSL2 et le moteur demandent des **droits administrateur**. Docker Desktop est payant au-delà de 250 salariés ; Rancher Desktop est gratuit.
- **« Le démon Docker ne répond pas »** : démarrer Docker Desktop ou Rancher Desktop.
- **Port 5432 déjà utilisé** : modifier le mapping de `db` dans `docker-compose.yml`, ou le supprimer (seuls les conteneurs utilisent la base).
- **Une source reste en erreur** : `./cti status`, puis `./cti source test <nom>`. Après 3 échecs consécutifs, une alerte technique est émise ; les autres sources continuent.
- **Linux : `cti source add` refusé (permission)** : le conteneur (uid 10001) doit pouvoir écrire dans `config/`. Lancer `sudo chown -R 10001 config` ou éditer `config/sources.yaml` à la main.
- **Scripts `.sh` en erreur `\r`** : les fins de ligne ont été converties en CRLF. `.gitattributes` force LF ; refaire `git checkout -- .`.
