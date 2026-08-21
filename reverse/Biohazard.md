# Biohazard — Writeups (rev_cyberpsychosis + ARMs race)

Writeups de deux challenges de reverse engineering rencontrés dans la room **Biohazard** :

1. [`rev_cyberpsychosis`](#1-rev_cyberpsychosis--diamorphine-rootkit-patché) — analyse statique d'un rootkit LKM (Diamorphine) patché
2. [`ARMs race`](#2-arms-race--50-niveaux-de-code-arm32-à-émuler) — service TCP à 50 niveaux nécessitant l'émulation de bytecode ARM32

---

## 1. rev_cyberpsychosis — Diamorphine rootkit patché

### Contexte

```
root@exegol:~/rev_cyberpsychosis# file diamorphine.ko
diamorphine.ko: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV),
BuildID[sha1]=e6a635e5bd8219ae93d2bc26574fff42dc4e1105, with debug_info, not stripped
```

**[Diamorphine](https://github.com/m0nad/Diamorphine)** est un rootkit LKM (Loadable Kernel Module) open-source bien connu, capable de :
- cacher un processus, un fichier ou le module lui-même
- élever les privilèges d'un processus au root
- le tout via des signaux "magiques" envoyés à `kill()`

Le binaire fourni est une version **patchée** — objectif : identifier ce qui a changé par rapport à l'original.

### Méthodologie

Outils : `radare2` (`r2 -e bin.relocs.apply=true -e asm.bits=64 -A diamorphine.ko`), `strings`.

```
[0x080000a0]> afl
0x080000a0   sym.hacked_getdents
0x08000440   sym.hacked_getdents64
0x080002c0   sym.hacked_kill
0x08000740   sym.give_root
...
```

#### `hacked_kill` — signaux magiques modifiés

Désassemblage de la fonction (`pdf @ sym.hacked_kill`) :

| Signal | Comportement | Vs. original |
|---|---|---|
| `0x1f` (**31**) | toggle invisibilité d'un PID | identique |
| `0x2e` (**46**, `.`) | toggle visibilité du **module** | **modifié** (original : 63) |
| `0x40` (**64**, `@`) | `prepare_creds` + `commit_creds` → donne le **root** | identique |

#### `hacked_getdents` — préfixe magique des fichiers cachés

```
movabs r9, 0x69736f6863797370   ; little-endian = "psychosi"
...
cmp    qword [rbx + 0x12], r9   ; compare les 8 premiers octets du nom
jne    0x80001dd
cmp    byte [rdi + 8], 0x73     ; compare le 9e octet à 's'
jne    0x80001dd
```

→ **Préfixe magique : `psychosis`** (tout fichier/dossier commençant par ce préfixe est masqué de `getdents`/`getdents64`).

### Résultats

| Élément | Valeur originale | Valeur patchée |
|---|---|---|
| Signal cache processus | 31 | 31 (inchangé) |
| Signal cache module | 63 | **46** |
| Signal give root | 64 | 64 (inchangé) |
| Préfixe magique fichiers | `diamorphine_secret` | **`psychosis`** |

### Note sur l'exécution

Le module cible `vermagic=5.15.0-82-generic` — il ne peut pas être chargé (`insmod`) sur un kernel différent (ex: WSL2 `6.18.x`) : les offsets de structures kernel (`init_task`, `commit_creds`, table de syscalls) sont spécifiques à chaque build. Ce challenge est conçu pour être résolu en **analyse purement statique**.

---

## 2. ARMs race — 50 niveaux de code ARM32 à émuler

### Contexte

> *"The famous hacker Script K. Iddie has finally been caught... he released a server sending mysterious data... Can you be the one to solve Iddie's puzzle?"*

Un service TCP envoie, à chaque niveau (`Level N/50`), un blob hexadécimal de bytecode machine, puis attend la valeur finale du registre `r0` après exécution — avec un **timeout serré**.

```
Level 1/50: 370301e379110ae335134de371250ae31b2f49e3010000e0...
Register r0:
```

### Identification du format

Désassemblage rapide avec Capstone (`CS_ARCH_ARM`, mode ARM little-endian) :

```python
from capstone import *
md = Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
for i in md.disasm(data, 0x1000):
    print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
```

```
0x1000: movw  r0, #0x1337
0x1004: movw  r1, #0xa179
0x1008: movt  r1, #0xd335
0x100c: movw  r2, #0xa571
0x1010: movt  r2, #0x9f1b
0x1014: and   r0, r0, r1
0x1018: and   r0, r0, r2
...
```

→ Confirmé : **ARM32, mode ARM (pas Thumb)**, code en ligne droite (`movw`/`movt` pour charger des constantes 16 bits, puis opérations logiques/arithmétiques `and`/`orr`/`rsb`/`eor`...). Pas de branchement — le résultat de `r0` dépend uniquement de la séquence d'instructions.

Vu les 50 niveaux et le timeout serré, seule une **automatisation complète** (connexion, parsing, émulation, réponse) permet de passer le challenge.

### Stratégie : émulation avec Unicorn Engine

- **pwntools** pour la communication réseau (`remote`, `recvline`, `sendline`)
- **Unicorn Engine** pour émuler réellement l'exécution ARM32 et calculer `r0`
- Registres initialisés à **0**, pile mappée par précaution (bien que non utilisée dans les blobs observés)

### ⚠️ Bug rencontré : timeout Unicorn en microsecondes

Premier essai avec :
```python
mu.emu_start(CODE_BASE, CODE_BASE + len(code), timeout=2000)
```

Résultat : les 14 premiers niveaux passent, puis échec aléatoire sur un niveau avec `r0 = 0` (= valeur d'initialisation, donc **aucune instruction exécutée**).

**Cause :** le paramètre `timeout` d'Unicorn est en **microsecondes**, pas en millisecondes. `2000` = **2 ms seulement**. Sous la charge du script (I/O réseau concurrente, logs), ce timeout pouvait expirer avant même la première instruction — comportement non déterministe.

**Correction :** exécuter un nombre exact d'instructions plutôt que de dépendre du temps réel, puisque le code est en ligne droite et de longueur connue :

```python
n_instructions = len(code) // 4   # 4 octets par instruction ARM32
mu.emu_start(CODE_BASE, CODE_BASE + len(code), timeout=0, count=n_instructions)
```

→ Déterministe à 100 %, plus aucune dépendance à la charge machine.

### Résultat

```
Level 50/50: r0 final = 201588737 (0xc040001)
Register r0:
HTB{un1c0Rn_0R_C4p5T0nE_0R_qeMU_5ubPR0cE55_0r_F0r90TTen_0Ld_R45berry_4NyTH1N9_BUt_n0_M4nu4LLy}
```

**Flag : `HTB{un1c0Rn_0R_C4p5T0nE_0R_qeMU_5ubPR0cE55_0r_F0r90TTen_0Ld_R45berry_4NyTH1N9_BUt_n0_M4nu4LLy}`**

Le flag lui-même confirme les approches possibles : Unicorn (utilisé ici), Capstone+émulation manuelle, QEMU en subprocess, un vieux Raspberry Pi ARM physique — tout sauf le calcul manuel niveau par niveau.

### Script complet (`arm_solver.py`)

```python
#!/usr/bin/env python3
"""
Solveur pour le challenge "ARMs race" (Script K. Iddie) - 50 niveaux.
Le serveur envoie du bytecode ARM32 (little-endian, mode ARM) a chaque niveau,
il faut l'emuler et renvoyer la valeur finale de r0.

Usage: python3 arm_solver.py <HOST> <PORT>
"""

import sys
import re
from pwn import remote, context, log

from unicorn import *
from unicorn.arm_const import *

context.log_level = 'info'

CODE_BASE = 0x10000
CODE_SIZE = 0x10000     # 64KB pour le code, largement suffisant
STACK_BASE = 0x80000
STACK_SIZE = 0x10000


def emulate_arm(code: bytes) -> int:
    """Emule le blob de code ARM32 et retourne la valeur finale de r0."""
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

    # Mappe la zone de code
    mu.mem_map(CODE_BASE, CODE_SIZE)
    mu.mem_write(CODE_BASE, code)

    # Mappe une pile au cas ou le code fait des push/pop/accès mémoire
    mu.mem_map(STACK_BASE, STACK_SIZE)
    mu.reg_write(UC_ARM_REG_SP, STACK_BASE + STACK_SIZE // 2)

    # Registres a zero au depart
    for reg in [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
                UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
                UC_ARM_REG_R12, UC_ARM_REG_LR]:
        mu.reg_write(reg, 0)

    try:
        # IMPORTANT : on execute un nombre EXACT d'instructions plutot que
        # de se fier a un timeout (le parametre timeout d'Unicorn est en
        # MICROSECONDES, pas en millisecondes -- une valeur trop petite ou
        # une charge systeme concurrente peut couper l'emulation avant la
        # premiere instruction et renvoyer un r0 errone).
        n_instructions = len(code) // 4
        mu.emu_start(CODE_BASE, CODE_BASE + len(code), timeout=0, count=n_instructions)
    except UcError as e:
        log.warning(f"Emulation stopped early: {e}")

    return mu.reg_read(UC_ARM_REG_R0)


def parse_level_line(line: str):
    """Extrait le numero de niveau et le blob hex d'une ligne du type
    'Level 1/50: 370301e3...'"""
    m = re.search(r"Level\s+(\d+)/(\d+):\s*([0-9a-fA-F]+)", line)
    if not m:
        return None
    level, total, hexblob = m.groups()
    if len(hexblob) % 2 != 0:
        hexblob = hexblob[:-1]
    return int(level), int(total), bytes.fromhex(hexblob)


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <HOST> <PORT>")
        sys.exit(1)

    host, port = sys.argv[1], int(sys.argv[2])
    io = remote(host, port)

    solved = 0
    while True:
        line = io.recvline(timeout=5).decode(errors='replace').strip()
        if not line:
            continue
        log.info(f"RECV: {line}")

        parsed = parse_level_line(line)
        if parsed is None:
            if any(k in line.lower() for k in ["flag", "htb{", "thm{", "congrat"]):
                log.success(f"FLAG TROUVE: {line}")
                try:
                    rest = io.recvall(timeout=3).decode(errors='replace')
                    if rest:
                        print(rest)
                except Exception:
                    pass
                break
            if any(k in line.lower() for k in ["wrong", "incorrect", "timeout", "fail"]):
                log.warning(f"Reponse rejetee par le serveur: {line}")
            continue

        level, total, code = parsed
        r0 = emulate_arm(code)
        log.info(f"Level {level}/{total}: r0 final = {r0} (0x{r0:x})")

        prompt = io.recvuntil(b":", timeout=5).decode(errors='replace')
        log.info(f"PROMPT: {prompt.strip()}")

        answer = str(r0)
        io.sendline(answer.encode())
        solved += 1
        # Pas de recv() supplementaire ici : ca volerait la ligne du niveau
        # suivant et ferait planter le niveau d'apres (timeout cote serveur).

    log.success(f"Termine. {solved} niveaux traites.")


if __name__ == "__main__":
    main()
```

### Reproduire

```bash
pip install pwntools unicorn capstone --break-system-packages
python3 arm_solver.py <HOST> <PORT>
```

---

## Outils utilisés

- [radare2](https://github.com/radareorg/radare2) — désassemblage / analyse statique
- [pwntools](https://github.com/Gallopsled/pwntools) — communication réseau CTF
- [Unicorn Engine](https://www.unicorn-engine.org/) — émulation CPU (ARM32)
- [Capstone](https://www.capstone-engine.org/) — désassemblage pour identification rapide du jeu d'instructions
