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
  caractères reste visiblement plus long qu'un message de 20. Le réglage *Length
  Hiding* rembourre par paliers et casse cette corrélation, au prix de la place.
- **La présence de chiffrement.** Un scan qui compte les caractères invisibles d'un
  message les trouvera. Il ne peut pas lire le contenu, mais il peut signaler
  « cette personne utilise un canal caché ». C'est une limite de fond du procédé :
  voir la section *Dissimulation* pour ce qui a été fait et ce qui reste hors de
  portée.
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
| Sel | `SHA-256("papotage-v4\|<salon>")` | Pas de sel constant partagé par tous les utilisateurs, donc pas de précalcul unique qui casserait tout le monde. Sépare aussi les salons entre eux. |
| Chiffrement | AES-GCM 256 | Chiffrement authentifié : une trame modifiée est rejetée, pas déchiffrée de travers. |
| Nonce | 12 octets aléatoires | Taille native de GCM. Une collision de nonce sur une clé fixe ne fuite pas seulement le XOR des clairs, elle expose la clé d'authentification GHASH. |
| Tag | 128 bits (complet) | Pas de troncature : pas de limite d'invocations à surveiller, pas de récupération accélérée de GHASH. |
| Compression | deflate-raw, avant chiffrement | Le drapeau voyage **dans** le clair chiffré : la compressibilité du message ne fuite pas. |
| Padding | ISO/IEC 7816-4, blocs de 16 octets, paliers en option | Découple la longueur envoyée de la longueur exacte du secret. |
| Domaine | `papotage-v4` | Sépare les versions de protocole : un message d'une autre version échoue au tag, il n'est jamais interprété de travers. |

## Dissimulation

Le chiffrement protège le contenu ; la dissimulation protège le fait qu'il y ait un
contenu. Ce sont deux problèmes distincts, et le second est le plus faible des deux.

**Ce qui a été supprimé.**

- *Le marqueur fixe.* Jusqu'en v2, le payload s'ouvrait par un `U+2060` constant.
  C'était une signature publique : `U+2060` suivi de caractères invisibles
  identifiait Papotage avec une précision parfaite, en une ligne de code. Le
  décodeur ramasse désormais les symboles de son alphabet où qu'ils soient, sans
  aucun repère de début.
- *La traînée d'un seul tenant.* Le payload était collé à la fin du message, en un
  bloc de plusieurs centaines de caractères — exactement ce que cherchent les
  heuristiques génériques sur les caractères de formatage. Il est maintenant réparti
  dans les intervalles de la couverture, avec des tailles de paquets tirées au sort.
  Sur un secret de 200 caractères, la plus longue série contiguë passe de 588
  symboles à environ 90, et la découpe diffère à chaque envoi du même texte.
- *L'en-tête de densité.* v3 ouvrait le payload par un symbole constant annonçant
  2 ou 3 bits. Résultat mesuré : le premier caractère invisible de **tout** message
  valait `ZW[1]` en 3 bits, 400 fois sur 400. Le marqueur avait changé de place, pas
  disparu. La densité se déduit désormais des symboles eux-mêmes — un symbole ≥ 4 ne
  peut venir que de l'alphabet 3 bits — et le premier symbole balaie tout l'alphabet.
- *Le début invisible.* La dispersion pouvait poser des symboles **avant** le premier
  caractère de la couverture, et le faisait dans 90 % des cas (mesuré sur 500
  messages). Or un message Discord ordinaire ne commence jamais par un caractère
  invisible : `/^[\u200B-\u2064]/` suffisait à trier. Le payload commence maintenant
  après le premier caractère visible, mesuré 0 sur 500.
- *La répétition des couvertures.* Un pool de 15 phrases tirées uniformément
  reproduisait la même phrase au bout de quelques messages : le motif le plus facile
  à remarquer, et il n'exige aucun outil, juste un humain qui lit le salon. Les
  phrases sont maintenant composées par gabarits (plus de 1 100 sorties, longueurs de
  2 à 59 caractères) avec une mémoire des 16 derniers tirages.

**Ce qui reste vrai.**

- Un adversaire qui **compte** les caractères invisibles d'un message trouvera le
  canal. La dispersion élève le coût de la détection, elle ne l'annule pas. Rien dans
  ce projet ne prétend le contraire.
- Le pool de couvertures intégré est **dans le code source**, donc connu. Le réglage
  *Cover Pool* existe pour ceux que ça dérange.
- La longueur du message reste corrélée à celle du secret. Le mode paliers casse
  cette corrélation au prix de la place (un secret de 20 octets passe de 60 à 92
  octets envoyés) ; il est optionnel pour cette raison.
- La dissimulation ne dit rien du **rythme** : qui poste, quand, à quelle fréquence.

**Compromis assumé.** Les symboles de la couverture ne doivent pas se mêler au flux de
données. En mode compact, le payload est posé après le dernier sélecteur de la
couverture, ce qui préserve intégralement les emojis composés. En mode invisible, le
liant `U+200D` appartient à l'alphabet 3 bits : une couverture contenant un emoji à
liant (`👨‍👩‍👧`) le voit se décomposer à l'écran. L'alternative — laisser le liant —
corromprait le payload.

### Compression et chiffrement

Comprimer avant de chiffrer expose en principe à une attaque à texte choisi de type
CRIME/BREACH : la taille du chiffré révèle la redondance entre une partie connue et
une partie secrète du message. Cette attaque suppose que l'adversaire puisse injecter
du texte de son choix **dans le message chiffré** et observer la taille de sortie de
façon répétée. Ce n'est pas le cas ici : chaque message est chiffré une fois, à partir
d'un texte que seul l'expéditeur compose. Le padding par blocs de 16 octets réduit
encore le signal. Le compromis est assumé, mais il est réel : ne collez pas dans un
message Papotage du texte fourni par quelqu'un d'autre à côté d'un secret.

## Vérification de bout en bout

Le codec repose sur une hypothèse qu'aucun test local ne peut confirmer : que
Discord conserve intégralement les caractères invisibles d'un message, y compris
insérés au milieu d'un texte. Seul un aller-retour par ses serveurs peut trancher.

Le plugin ne la suppose donc pas, il la mesure. Chaque message chiffré envoyé est
retenu ; quand Discord le renvoie (`MESSAGE_CREATE`), il est comparé à l'original.
S'il diffère, l'expéditeur est prévenu immédiatement : le destinataire ne pourra pas
le lire. Le secret n'est pas exposé pour autant — un message altéré n'est plus
déchiffrable, il ne devient pas lisible.

La comparaison exige l'identité de l'auteur. Un message dépouillé de tous ses
caractères invisibles est indiscernable d'un message où quelqu'un d'autre aurait
simplement tapé la même phrase que notre couverture : sans vérifier que le message
vient bien de nous, l'alerte se déclencherait à tort.

## Fail-closed

Le plugin annule l'envoi plutôt que de publier en clair, dans tous les cas suivants :
mot de passe absent, échec du chiffrement, message trop long une fois chiffré. Il
bloque aussi l'**édition** d'un message déchiffré : le contenu affiché ayant été
remplacé par le texte en clair, éditer sans garde-fou republierait le secret dans le
salon.

Ce garde-fou tient à un détail du gestionnaire de Vencord, vérifié dans sa source :

```ts
try {
    const result = await listener(...);
    if (result?.cancel) return true;
} catch (e) {
    MessageEventsLogger.error("... unknown error\n", e);   // journalise
}
return false;                                              // = ne pas annuler
```

Une exception qui s'échappe d'un listener n'annule donc **pas** l'envoi : Vencord la
journalise et le message part. Le corps des deux listeners est pour cette raison
intégralement enveloppé dans un `try`, pré-filtre compris, avec `{ cancel: true }`
comme unique issue en cas d'erreur.

## Mot de passe

600 000 itérations PBKDF2 ne rachètent pas un mot de passe court : deviner le mot de
passe reste la façon la plus réaliste de casser Papotage, loin devant toute attaque
sur AES-GCM. Le réglage refuse les mots de passe de moins de 12 caractères avec une
explication.

Le cache de clés dérivées est borné à 16 entrées, avec éviction du moins récemment
utilisé. Une dérivation coûte **104 ms de CPU** (mesuré) : sans borne, parcourir cent
salons en dérivait cent et les gardait toutes en mémoire jusqu'au rechargement de
Discord. La pré-dérivation à l'ouverture d'un salon ne se déclenche plus que là où le
chiffrement est effectivement armé ; ailleurs la clé est dérivée à la demande.

## Messages illisibles

Un message chiffré qu'on ne sait pas lire — mauvais mot de passe, autre salon, autre
version du format — est signalé par un 🔒 devant la phrase de couverture. Sans ce
marqueur, l'échec est parfaitement silencieux : on voit une réponse anodine et on
ignore qu'un message nous a échappé. Le seuil de détection étant très au-dessus de ce
qu'un humain tape, un faux positif est hors d'atteinte.

Le marqueur est un ajout d'affichage : il est retiré si l'auteur édite le message, il
ne part jamais dans le salon.

## Signaler un problème

Ouvrir une issue sur le dépôt. Pour un problème qui exposerait des utilisateurs,
préférer un contact direct au mainteneur avant toute publication.
