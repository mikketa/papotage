# Modèle de menace

Papotage est un outil de **confidentialité de loisir**. Il empêche la lecture
occasionnelle et le traitement automatisé du contenu ; il ne résiste pas à un
adversaire déterminé qui vous cible personnellement. Ce document dit précisément
contre quoi il protège et contre quoi il ne protège pas, pour que personne ne s'en
serve en croyant avoir mieux.

## Ce que Papotage protège

| Adversaire | Résultat |
|---|---|
| Un autre membre du salon, sans le plugin | Ne voit qu'une phrase banale. |
| Un autre membre du salon, avec le plugin mais sans le mot de passe | Ne voit qu'une phrase banale : le tag GCM rejette la trame. |
| Discord (stockage, modération automatique, fuite de base) | N'obtient que du chiffré. Le contenu n'est pas récupérable sans le mot de passe. |
| Quelqu'un qui compromet un salon | N'obtient que ce salon : la clé est dérivée du mot de passe **et** de l'identifiant du salon. |

## Ce que Papotage ne protège pas

- **Les métadonnées.** Qui parle à qui, quand, à quelle fréquence, dans quel salon :
  tout reste visible pour Discord et pour les membres du salon. C'est souvent plus
  révélateur que le contenu.
- **La longueur.** Le padding arrondit à 16 octets près, mais un message de 800
  caractères reste visiblement plus long qu'un message de 20.
- **La présence de chiffrement.** Un scan automatique repère des caractères
  zero-width ou une longue traînée de sélecteurs de variation. Il ne peut pas lire
  le contenu, mais il peut signaler « cette personne utilise un canal caché ».
- **Le poste client.** Le texte est en clair au moment où on le tape et quand il
  s'affiche. Le mot de passe est stocké **en clair** dans les réglages Vencord
  (`settings.json`) : quiconque a accès au disque le lit.
- **La compromission d'un participant.** Le mot de passe est partagé : un seul
  participant qui le divulgue expose tout l'historique du salon, passé et futur.
- **La confidentialité persistante.** Pas de renouvellement de clé : le mot de passe
  déchiffre aussi les messages d'il y a six mois. Changer de mot de passe rend
  l'ancien historique illisible pour tout le monde.
- **Le déni.** Les messages ne sont pas répudiables : quiconque a la clé peut prouver
  qu'un message chiffré s'y déchiffre.

## Choix cryptographiques

| Élément | Valeur | Pourquoi |
|---|---|---|
| Dérivation | PBKDF2-SHA256, 600 000 itérations | Aligné sur les recommandations OWASP. Coût amorti par un cache de clé. |
| Sel | `SHA-256("papotage-v2\|<salon>")` | Pas de sel constant partagé par tous les utilisateurs, donc pas de précalcul unique qui casserait tout le monde. Sépare aussi les salons entre eux. |
| Chiffrement | AES-GCM 256 | Chiffrement authentifié : une trame modifiée est rejetée, pas déchiffrée de travers. |
| Nonce | 12 octets aléatoires | Taille native de GCM. Une collision de nonce sur une clé fixe ne fuite pas seulement le XOR des clairs, elle expose la clé d'authentification GHASH. |
| Tag | 128 bits (complet) | Pas de troncature : pas de limite d'invocations à surveiller, pas de récupération accélérée de GHASH. |
| Compression | deflate-raw, avant chiffrement | Le drapeau voyage **dans** le clair chiffré : la compressibilité du message ne fuite pas. |
| Padding | ISO/IEC 7816-4, blocs de 16 octets | Découple la longueur envoyée de la longueur exacte du secret. |

### Compression et chiffrement

Comprimer avant de chiffrer expose en principe à une attaque à texte choisi de type
CRIME/BREACH : la taille du chiffré révèle la redondance entre une partie connue et
une partie secrète du message. Cette attaque suppose que l'adversaire puisse injecter
du texte de son choix **dans le message chiffré** et observer la taille de sortie de
façon répétée. Ce n'est pas le cas ici : chaque message est chiffré une fois, à partir
d'un texte que seul l'expéditeur compose. Le padding par blocs de 16 octets réduit
encore le signal. Le compromis est assumé, mais il est réel : ne collez pas dans un
message Papotage du texte fourni par quelqu'un d'autre à côté d'un secret.

## Fail-closed

Le plugin annule l'envoi plutôt que de publier en clair, dans tous les cas suivants :
mot de passe absent, échec du chiffrement, message trop long une fois chiffré. Il
bloque aussi l'**édition** d'un message déchiffré : le contenu affiché ayant été
remplacé par le texte en clair, éditer sans garde-fou republierait le secret dans le
salon.

## Signaler un problème

Ouvrir une issue sur le dépôt. Pour un problème qui exposerait des utilisateurs,
préférer un contact direct au mainteneur avant toute publication.
