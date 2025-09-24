# Write-up — <Nom de la machine/room>
**Date :** YYYY-MM-DD  
**Source :** TryHackMe / HackTheBox — <lien si public>  
**Difficulté :** easy / medium / hard

---

## Contexte
Brève phrase sur la cible / objectif.

## Notes à chaud (commandes & outputs)
- `nmap -sC -sV -oN nmap.txt 10.10.10.5` → ports 22,80,139
- `gobuster dir -u http://10.10.10.5 -w common.txt` → /uploads

## Accès initial (PoC)
Étapes précises pour obtenir l’accès initial (commande + output).  
Ex : `curl -F "file=@shell.php" http://10.10.10.5/uploads` → upload succeeded → hit reverse-shell.

**Preuve** : ![screenshot1](./screenshots/xxx.png)

## Post-exploitation / Escalade
- Actions faites après le shell : `whoami`, `id`, etc.  
- Méthode d’escalade : expliquer la logique et commandes.  
- Preuve montée en privilèges (ex : contenu /root/root.txt)

## Impact
Courte description business : quelles données exposées, conséquences.

## Recommandations / Remédiations
1. Action prioritaire (ex: désactiver upload anonymes).  
2. Patch/version/update.  
3. Hardening (ex: disable SUID, config change).

## Annexes
- Commandes complètes (copier la session bash).  
- Liens utiles / références (CVE, docs).
