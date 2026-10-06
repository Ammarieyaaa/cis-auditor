# RAM Security - Application d'audit CIS

Application web pour auditer la configuration d'un système Windows ou Linux/Unix, en local ou à distance, à partir de règles inspirées des CIS Benchmarks.

## Fonctionnalités

- Interface web Flask, entièrement en français, et CLI (`presentation/cli.py`) pour scripter les audits
- Authentification avec 3 rôles : administrateur, technicien, DSI
  - **Administrateur** : crée/supprime les comptes technicien et DSI
  - **Technicien** : lance des audits, consulte l'historique et les rapports
  - **DSI** : accès en lecture seule aux rapports et à l'historique (ne lance pas d'audit)
- Choix du système à auditer : Windows ou Linux/Unix
- Chargement des règles depuis des fichiers JSON, centrées sur la catégorie
  "Comptes et mots de passe" (pertinente pour une mission d'audit de sécurité)
- Exécution de contrôles en local (commande système, lecture de fichier,
  lecture du registre Windows) ou à distance (SSH, WinRM, HTTP/API)
- Comparaison automatique avec la valeur attendue
- Résultats réussi/échec avec gravité et recommandation
- Historique SQLite des audits
- Export d'un rapport HTML

## Installation

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Sur Linux/macOS :

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Lancement

```bash
python -m presentation.app
```

Puis ouvrir :

```text
http://127.0.0.1:5000
```

Au premier démarrage, un compte administrateur est créé automatiquement :

```text
Identifiant : admin
Mot de passe : admin123
```

Connectez-vous avec ce compte puis créez les comptes technicien et DSI depuis
la page **Administration**. Pensez à changer le mot de passe admin par défaut.

## Utilisation en ligne de commande

Pour scripter des audits sans passer par le web (`presentation/cli.py`, basé sur `Click`) :

```bash
python -m presentation.cli rule-sets                                  # referentiels disponibles
python -m presentation.cli categories --os linux                       # categories et effectifs
python -m presentation.cli audit --os linux --level 2                  # lance un audit local, l'enregistre
python -m presentation.cli audit --os linux --category "Comptes utilisateurs et umask"
python -m presentation.cli history --limit 10                           # derniers audits enregistres
python -m presentation.cli report 12 --output rapport-12.json            # export JSON d'un audit
```

La CLI partage le meme moteur, les memes connecteurs et le meme stockage que
l'interface web (SQLite ou PostgreSQL selon `DATABASE_URL`) ; un audit lance
en CLI apparait dans l'historique web et inversement. L'audit distant
(SSH/WinRM) et l'export HTML/PDF restent pour l'instant reserves a
l'interface web.

## Architecture

L'application suit une architecture modulaire en couches :

1. **Couche Présentation** (`presentation/`) : application web Flask + Jinja2
   (`presentation/app.py`, `templates/`) et CLI (`presentation/cli.py`, via
   `Click`).
2. **Couche Métier** (`core/`) : moteur d'audit et profils CIS
   (`core/engine.py`), calcul de score (`core/scoring.py`), comparaison
   d'audits (`core/comparison.py`), construction des rapports
   (`core/reporting.py`).
3. **Couche Collecte** (`collectors/`) : connecteurs locaux — commandes
   système (`collectors/local.py`, PowerShell/bash), fichiers
   (`collectors/filesystem.py`), registre Windows (`collectors/registry.py`,
   via `winreg`) et processus système (`collectors/process.py`, via `psutil`)
   — et connecteurs distants — SSH (`collectors/ssh.py`, via `paramiko`),
   WinRM (`collectors/winrm.py`, via `pywinrm`) et HTTP/API générique
   (`collectors/http.py`, via `requests`).
4. **Couche Données** (`data/database.py`) : stockage SQLite par défaut, ou
   PostgreSQL si la variable d'environnement `DATABASE_URL` est définie (voir
   `.env.example`). Historique des audits et de leurs résultats dans les deux cas.

Deux modules transverses complètent ces couches : `security/auth.py`
(authentification et rôles) et `config/env_file.py` (chargement de `.env`).

**Écart assumé** : le PDF est généré avec `xhtml2pdf` plutôt que WeasyPrint.
WeasyPrint a été testé mais échoue sous Windows sans le runtime GTK3 natif
(dépendance système hors pip) ; `xhtml2pdf` produit le même résultat (HTML→PDF)
sans dépendance externe.

## Structure

```text
RAM_SECURITY/
  presentation/
    app.py                 # Routes Flask
    cli.py                  # Commandes Click
  core/
    engine.py             # Metier : chargement des regles, profils CIS, execution d'un controle
    scoring.py             # Metier : score global et par categorie
    comparison.py           # Metier : comparaison de deux audits
    reporting.py             # Metier : construction du contenu des rapports, labels partages
  collectors/
    local.py              # Collecte locale : execution de commande (PowerShell / bash)
    filesystem.py          # Collecte locale : lecture directe d'un fichier
    registry.py             # Collecte locale : lecture directe du registre Windows
    process.py                # Collecte locale : etat d'un processus (psutil)
    ssh.py                      # Collecte distante : commande via une session SSH
    winrm.py                     # Collecte distante : commande PowerShell via WinRM
    http.py                       # Collecte distante : requete HTTP/API generique
  data/
    database.py            # SQLite par defaut, PostgreSQL si DATABASE_URL est definie
    audit_history.db        # Base SQLite (creee au premier lancement)
  security/
    auth.py                # Hachage des mots de passe, sessions, decorateurs de role
  config/
    env_file.py             # Chargement de .env
  assistant/                # Assistant conversationnel (RAG), complementaire a l'audit CIS
    chatbot.py               # Appels au modele (Ollama ou NVIDIA NIM), embeddings
    document_store.py         # Ingestion et cache des PDF importes
    knowledge.py               # Recherche (BM25 + semantique) et redaction de reponse
  rules/
    windows.json         # Regles CIS Windows (comptes et mots de passe)
    linux.json           # Regles CIS Linux (comptes et mots de passe)
    explanations.json     # Vulgarisation de chaque regle
  templates/             # Pages HTML (dont login.html, admin.html)
  static/
    styles.css           # Design de l'interface
  docs/
    cis-benchmarks/       # PDF des benchmarks CIS officiels utilises comme reference
    explication_regles_cis.txt  # Note de conception sur le perimetre des regles
  assets/                # Logos et visuels de marque
  tests/                 # pytest : moteur, connecteurs, CLI, base de donnees, routes web
  requirements.txt
  requirements-dev.txt
  .env.example
```

## Ajouter une règle

Modifier un fichier dans `rules/`, par exemple `rules/linux.json`. Par défaut
le contrôle exécute une commande (`connector` peut être omis) :

```json
{
  "id": "LIN-004",
  "title": "Exemple de controle",
  "severity": "medium",
  "description": "Description du controle.",
  "check": {
    "type": "contains",
    "command": "commande_a_executer",
    "expected": "valeur attendue"
  },
  "recommendation": "Action recommandee."
}
```

Autres connecteurs disponibles pour `check.connector` :

- `file` : lecture directe d'un fichier — `{"connector": "file", "path": "/etc/ssh/sshd_config", "type": "contains", "expected": "..."}`
- `registry` : lecture directe du registre Windows — `{"connector": "registry", "hive": "HKLM", "key": "...", "name": "...", "type": "equals", "expected": "..."}`
- `process` : un processus est-il en cours (via `psutil`) — `{"connector": "process", "name": "sshd", "type": "equals", "expected": "RUNNING"}` (ou `"STOPPED"`)
- `http` : requête HTTP/API — `{"connector": "http", "url": "https://...", "json_path": "champ.imbrique", "type": "equals", "expected": "..."}`

`file`, `registry` et `process` ne fonctionnent qu'en audit local (ils lisent
la machine qui exécute le code, pas une cible distante) ; utilisés avec
`mode=remote`, ils renvoient une erreur explicite plutôt qu'un faux résultat.

Le transport (local, SSH ou WinRM) est choisi automatiquement selon le mode
d'audit ; il n'a pas à être précisé dans la règle.

Types de comparaison disponibles :

- `equals`
- `contains`
- `regex`
- `numeric_min`
- `numeric_max`
- `command_success`

## Limites connues

- Sous-ensemble de règles CIS actuellement couvert, centré sur "Comptes et mots de passe"
- Certaines commandes Windows peuvent nécessiter PowerShell et des droits adaptés
- Le connecteur HTTP/API est générique : il ne cible aucun produit particulier tant qu'un besoin précis n'est pas exprimé
