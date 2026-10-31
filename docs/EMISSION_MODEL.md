# AURORA — émission proportionnelle `proportional-remaining-1e6-v1`

**État : implémentée pour la testnet expérimentale** sur `feature/emission-schedule-v0`. La formule est une règle de consensus du prototype; la politique économique reste à valider par le porteur du projet et par une revue indépendante avant tout usage public.

## Plafond et lancement équitable

- Précision : 8 décimales; 1 AUR = 100 000 000 unités.
- Plafond strict d’émission brute : 500 000 000 AUR.
- La genèse est vide et ne crée aucun solde : l’émission commence avec le premier bloc miné.
- L’offre brute historique comprend uniquement les unités émises. Les frais brûlés ne réduisent jamais l’offre historique et ne rouvrent pas le plafond.

## Émission lissée

Pour chaque bloc, le consensus lit l’émission brute cumulée avant ce bloc. En unités minimales :

```text
remaining = 500_000_000 * 100_000_000 - gross_issued
issuance  = min(remaining, max(1, floor(remaining / 1_000_000)))
```

Le taux théorique est un millionième de l’offre restante par bloc (0,0001 %), calculé uniquement avec des entiers. L’arrondi inférieur donne une baisse graduelle sans paliers ni halvings. Le plancher d’une unité (0,00000001 AUR) permet au calendrier d’atteindre exactement le plafond; l’émission du dernier bloc est toujours tronquée au reliquat. Le premier bloc émet 500 AUR. Chaque branche calcule son émission à partir de l’offre de son propre parent, y compris pendant une réorganisation.

À titre indicatif, avec la cible testnet actuelle de 60 secondes, la formule diminue jusqu’au plancher d’une unité après environ 25,2 millions de blocs; le reliquat sous 0,01 AUR demande ensuite au plus un million de blocs. Cela correspond à plusieurs décennies à la cadence cible, mais ce n’est pas une prévision de temps réel : les horodatages, forks, blocs orphelins et cadence réelle changent la durée écoulée.

## Trésorerie et frais

Pour l’émission brute `R`, en unités :

```text
treasury       = floor(R / 20)   # 5 %
miner_issuance = R - treasury   # 95 %
```

Pour les frais validés `F` :

```text
miner_fees = floor(F / 2)       # 50 %
burned     = F - miner_fees     # 50 %
```

Les arrondis résiduels vont au mineur. Les frais brûlés disparaissent du solde total, mais ne changent pas l’émission brute.

La trésorerie reçoit les fonds à l’identifiant testnet fixe `[0xA0; 32]`. Dans le code actuel, il s’agit d’un compte de consensus crédité automatiquement, pas d’un smart contract : il n’y a ni gouvernance, ni règles de dépense, ni procédure de financement des audits. Cette capacité de dépense doit être conçue avant d’attribuer une valeur réelle à la trésorerie.

Quand le plafond est atteint, l’émission est nulle et la rémunération du mineur provient uniquement des frais. Le partage actuel des frais reste 50 % au mineur / 50 % brûlés; ainsi, « 100 % par les frais » décrit la source du revenu du mineur après l’émission, pas une allocation de 100 % de tous les frais au mineur.

## Simulation des hauteurs extrêmes (sans minage ni écriture disque)

Le simulateur Python indépendant `scripts/emission_sim.py` propose une
commande de contrôle des jalons, sans fabriquer de blocs, ni envoyer de
transactions, ni réserver des centaines de millions d'entrées en mémoire :

```sh
python3 scripts/emission_sim.py --heights 10000000 100000000 500000000
python3 -m unittest discover -s scripts -p 'test_emission_sim.py'
```

Le calcul utilise des entiers et saute les intervalles où la récompense par
bloc est constante. **Chaque part de trésorerie est toujours arrondie par
bloc avant addition**, comme dans `scheduled_issuance` et
`apply_block_reward` ; un arrondi global à 5 % serait incorrect.

Selon le profil testnet `proportional-remaining-1e6-v1` actuellement codé
(plafond **500 millions AUR**, à distinguer des **500 millions de blocs**) :

| Hauteur simulée | Émission brute totale (AUR) | Émission restante (AUR) |
| ---: | ---: | ---: |
| 10 000 000 | 499 977 300,14361895 | 22 699,85638105 |
| 100 000 000 | 500 000 000,00000000 | 0 |
| 500 000 000 | 500 000 000,00000000 | 0 |

La dernière unité d'émission est atteinte au bloc **26 212 491** selon la
récurrence entière simulée. Tous les blocs suivants ont une émission nouvelle
nulle, sans que cela interdise les transactions ou les frais. À la cible
théorique de **60 secondes par bloc**, ce jalon serait à ~49,8 ans ; la
durée réelle n'est pas déduite d'un test de consensus ou de réseau.

**Ce que ce test ne démontre pas :** traitement de 10 M, 100 M ou 500 M de blocs
par un nœud, consommation de RAM/disque, débit P2P, temps de validation,
sécurité sur très longue durée, ni disponibilité réelle des mineurs. Ces
performances demandent des campagnes matérielles et réseau distinctes. Aucun
paramètre de consensus n'est changé par ce simulateur.

## Vérifications et changements de protocole

Les tests vérifient le démarrage à 500 AUR, la décroissance entière, l’absence de saut autour d’anciens seuils, le plancher, le plafond, le partage 5/95, les frais impairs et les réorganisations. L’identifiant `proportional-remaining-1e6-v1` est inclus dans l’empreinte P2P afin que les pairs exécutant une autre règle d’émission soient incompatibles.

Tout changement à cette formule change le consensus et crée un réseau incompatible. Les anciens répertoires testnet contenant les blocs à paliers doivent être remplacés avant de rejoindre ce testnet; ne supprime pas de données dont tu as besoin sans en garder une copie. Cette formule n’est pas un engagement de valeur et reste expérimentale.
