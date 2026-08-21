Markdown# Coffee Invocation - HTB Reverse Engineering

**Catégorie :** Reverse Engineering  
**Difficulté :** Medium / Hard  
**Flag :** `HTB{1_c4nt_c4ptur3_fl4g5_unt17_1v3_h4d_a1l_my_0xCAFEBABE}`

## Description
Our new crazy conspiracy theorist intern has blocked everyone from the coffee machine
because he saw that aliens were trying to steal the "out of the world" secret recipe.
Your mission is to unveil the secrets that lie behind his profound madness and teach
him a javaluable lesson.
textLe binaire `coffee_invocation` simule une machine à café. L’option `[REDACTED]` (3) est protégée et affiche le flag uniquement si on lui passe le bon mot de passe en argument.

## Analyse initiale

```bash
$ file coffee_invocation
ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped

$ strings coffee_invocation | grep -E "HTB|password|Verify|coffee|Access|alien"
No coffee for you!
Access granted.
Enjoy!
Also here is your flag: HTB{
Can't access secret coffee without providing the password!
Verifying user is of terrestrial origin...
=> User might be an alien!!!
Verifying user has authorization...
Verify1
Verify2
Tinfoil
Le binaire utilise JNI (JNI_CreateJavaVM, libjvm.so) pour exécuter du code Java embarqué.
On trouve deux class files Java :
Bash$ xxd coffee_invocation | grep -a "cafebabe"
00005180: cafe babe ...
00005680: cafe babe ...
Extraction des classes Java
Pythondata = open("coffee_invocation", "rb").read()
open("Verify1.class", "wb").write(data[0x5180:0x5680])
open("Verify2.class", "wb").write(data[0x5680:0x5680+0x2000])
Bashjavap -c -p Verify1.class
javap -c -p Verify2.class
Verify1 – Vérification « terrestrial origin »

Reçoit deux arguments : source et target
Compare caractère par caractère après conversion Byte / Short
Le target hard-codé est : ~PL{A;PL{?;:=|PIC{HzP:A;~x (26 caractères)

Le code natif override Byte.valueOf et Short.valueOf.
Le remap utilisé est :
Pythondef remap(x):
    return ((~x + 1) - 0x51) & 0xFF
En appliquant l’inverse sur le target :
Pythontarget = b"~PL{A;PL{?;:=|PIC{HzP:A;~x"
plain = bytes([((~c + 1) - 0x51) & 0xFF for c in target])
print(plain.decode())   # 1_c4nt_c4ptur3_fl4g5_unt17
→ Première partie du flag : 1_c4nt_c4ptur3_fl4g5_unt17
Verify2 – Vérification « authorization »

Prend la suite de l’argument (encore 26 caractères)
Pour chaque paire de caractères :
Applique complexSort (qui peut trier selon un Boolean overridé)
Compare avec des paires d’une longue chaîne de caractères
En cas d’égalité → System.exit(i+3) → change la table de mapping de Character.valueOf


Il y a 13 tables de mapping de 95 caractères (plage printable) dans le binaire.
Après analyse des tables et inversion du mapping + tri, on obtient la deuxième partie :
text_1v3_h4d_a1l_my_0xCAFEBABE
Reconstruction du flag
Le binaire prend l’argument complet (sans HTB{...}) :
text1_c4nt_c4ptur3_fl4g5_unt17_1v3_h4d_a1l_my_0xCAFEBABE
Il ajoute ensuite le préfixe/suffixe pour l’affichage.
Validation
Bashexport LD_LIBRARY_PATH=/usr/lib/jvm/java-17-openjdk-amd64/lib/server./coffee_invocation '1_c4nt_c4ptur3_fl4g5_unt17_1v3_h4d_a1l_my_0xCAFEBABE'
animate-gaussianPuis choisir l’option **3** :
Verifying user is of terrestrial origin...
Verifying user has authorization...
Access granted.
...
Also here is your flag: HTB{1_c4nt_c4ptur3_fl4g5_unt17_1v3_h4d_a1l_my_0xCAFEBABE}
animate-gaussian## Flag final
HTB{1_c4nt_c4ptur3_fl4g5_unt17_1v3_h4d_a1l_my_0xCAFEBABE}
animate-gaussian---

**Points clés du challenge :**
- Utilisation de JNI pour exécuter du Java depuis du natif
- Override de méthodes Java (`valueOf`, `System.exit`) pour obfuscation
- Deux vérifications successives avec mappings différents
- Le flag n’est pas chiffré dans le binaire : c’est l’argument que l’on donne qui est validé puis affiché
