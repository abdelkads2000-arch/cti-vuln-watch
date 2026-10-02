# CTI Vuln Watch

Agent de veille vulnérabilités / CTI pour SOC MSSP : collecte, qualification sourcée
(niveaux de preuve déterministes), corrélation avec le parc clients, détection de
contournement de patch, notifications Teams / email / JIRA.

> État : **étape 0** (squelette : PostgreSQL 16 + pgvector, sauvegardes). Architecture
> proposée dans [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), en attente de validation.

## Prérequis
- Un moteur Docker avec Compose v2 : Docker Desktop, **Rancher Desktop** (moteur « dockerd (moby) ») ou Docker Engine sous Linux.
- Git Bash sous Windows (fourni avec Git for Windows) pour lancer les scripts `.sh`.

Aucune autre dépendance : Python, PostgreSQL et les librairies tournent dans les conteneurs.

## Commandes
| Action | Commande |
|---|---|
| Saisir les clés API (une par une, saisie masquée) | `./configure.sh` |
| Tout démarrer | `./start.sh` |
| Tout arrêter (données conservées) | `./stop.sh` |
| Suivre les logs | `./logs.sh [service]` |
| Réinitialiser la base (destructif, confirmation demandée) | `./reset.sh` |
| CLI de l'agent (phase 1) | `./cti <commande>` |

Au premier `./start.sh`, `.env` est créé depuis `.env.example`, avec un mot de passe
PostgreSQL et un mot de passe web générés aléatoirement. Toute clé API absente
désactive uniquement la source ou le canal concerné.

Sauvegardes : `./backups/cti_AAAAMMJJ_HHMMSS.dump` (format custom de pg_dump), rétention
réglée par `BACKUP_RETENTION_DAYS`.
Restauration : `docker compose exec -T db pg_restore -U cti -d cti --clean < backups/<fichier>.dump`

## Dépannage
- **« Docker introuvable »** : installer un moteur Docker. Sous Windows, WSL2 et le
  moteur demandent des **droits administrateur** ; faire la demande au support IT.
- **« Le démon Docker ne répond pas »** : démarrer Docker Desktop ou Rancher Desktop et
  attendre que le moteur soit prêt.
- **Port 5432 déjà utilisé** : un autre PostgreSQL tourne localement ; l'arrêter ou
  changer le mapping dans `docker-compose.yml`.
- **Scripts `.sh` en erreur `\r`** : les fins de ligne ont été converties en CRLF ; le
  fichier `.gitattributes` force LF (refaire `git checkout -- .`).
