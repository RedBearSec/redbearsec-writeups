# Write-up — <fakebank/OffensivesecurityIntro>
**Date :** 2025-09-24 
**Source :** TryHackMe  
**Difficulté :** easy 

---

## Contexte
Une page web d'une banque fake vaec un compte debiteur

## Notes à chaud (commandes & outputs)
- dirb http://fakebank.thm 
    > .../images
    > .../bank-accounting

## Accès initial (PoC)
Ouverture du lien http://fakebank.thm/bank-accounting
> Accès a une page permettant de faire des virements vers le compte selectionné

**Preuve** : flag : BANK-HACKED

## Post-exploitation / Escalade
> Ajout de $1M sur le compte 8881 

## Impact
>Compte en banque a fond illimité

## Recommandations / Remédiations
1. Bloquer la page .../bank_accounting

## Annexes

