# Papotage

Plugin Vencord qui chiffre les messages Discord et cache le résultat dans du texte
invisible. Sans le plugin, un message ressemble à une réponse quelconque
(« ok ça marche 👍 ») ; avec le plugin et le bon mot de passe, il s'affiche en clair.

## Fonctionnement

1. Le message est chiffré en AES-GCM 256. La clé est dérivée du mot de passe partagé
   (PBKDF2-SHA256, 600 000 itérations) **et de l'identifiant du salon** : le même mot
   de passe donne une clé différente dans chaque conversation.
2. Les octets chiffrés sont encodés en caractères Unicode invisibles, **dispersés
   dans** une courte phrase de couverture plutôt que collés à la fin. Discord les
   préserve.
3. À la réception, le plugin repère la partie invisible, la déchiffre et remplace le
   contenu affiché par le vrai message. Les autres ne voient que la couverture.
4. Chaque message envoyé est comparé à celui que Discord renvoie. S'il a été modifié
   en route, l'expéditeur est prévenu tout de suite : le destinataire ne pourra pas
   le lire.
5. Un message chiffré qu'on ne sait **pas** lire (mauvais mot de passe, autre salon,
   autre version) est préfixé d'un 🔒. Sans ça, on ne verrait que la phrase de
   couverture et on ignorerait qu'un message nous a échappé.

Le chiffrement s'active salon par salon avec le cadenas de la barre de message
(gris = off, vert = on, orange = armé mais sans mot de passe).

## Utilisation

- **Mot de passe** : à définir dans les réglages du plugin, identique chez tous les
  participants. À transmettre par un autre canal.
- **Phrase de couverture** : par défaut une phrase est composée au hasard parmi plus
  de 1 100 combinaisons, avec des formes variées (du « ok » sec à la question) et une
  mémoire qui évite de répéter la même phrase à quelques messages d'écart. Le pool
  intégré étant public, le réglage *Cover Pool* permet d'utiliser ses propres phrases.
  Pour écrire soi-même la façade et garder une conversation cohérente, utiliser
  `phrase visible | message secret`.
  Exemple : `ouais tranquille et toi ? | rdv à 20h` affiche « ouais tranquille et
  toi ? » pour tout le monde, et le vrai message pour ceux qui ont le plugin.

### Réglages

| Réglage | Rôle |
|---|---|
| Passphrase | Mot de passe partagé (obligatoire) |
| Encodage | Mode d'encodage du secret (voir ci-dessous) |
| Auto Decrypt | Déchiffrer automatiquement les messages reçus |
| Show 🔓 | Préfixer les messages déchiffrés pour les repérer |
| Mark Unreadable | Préfixer d'un 🔒 les messages chiffrés qu'on ne peut PAS lire |
| Custom Cover | Phrase de couverture par défaut |
| Cover Pool | Tes propres phrases de couverture, une par ligne (le pool intégré est public) |
| Length Hiding | Rembourre par paliers au lieu de blocs de 16 o : masque la longueur, coûte de la place |
| Separator | Délimiteur entre couverture et secret (par défaut ` &#124; `) |

### Modes d'encodage

| Mode | Coût par octet | Capacité (1 message) | Remarque |
|---|---|---|---|
| **Invisible dense** (défaut) | 2,67 car. | ≈ 865 car. de secret | 8 symboles zero-width |
| Invisible sûr | 4 car. | ≈ 550 car. | 4 symboles seulement, le jeu le plus universel |
| Compact | 1 car. | ≈ 1 225 car. | Sélecteurs de variation, accrochés à la couverture |
| Emoji | 2 emojis | ≈ 550 car. | Visible et bizarre : réservé aux messages courts |

Capacités **mesurées** sur du texte aléatoire (le pire cas) avec la plus longue
couverture automatique. Un message en français ordinaire se compresse et va
plusieurs fois plus loin. Le budget est compté en unités UTF-16, plus prudent que
les points de code — la limite réelle de Discord ne sera donc jamais dépassée par
surprise. Au-delà, **l'envoi est annulé** avec une erreur indiquant le dépassement
exact : le message n'est jamais avalé silencieusement par Discord.

## Limites

- **Mot de passe partagé** : quiconque a la clé lit tout le salon. Pas de secret
  individuel, pas de confidentialité persistante (*forward secrecy*).
- **Métadonnées** : Discord voit toujours qui parle à qui et quand. Seul le contenu
  est caché.
- **Détectabilité** : invisible à la lecture. Un scan qui *compte* les caractères
  invisibles d'un message les trouvera toujours — c'est une limite de fond, pas un
  réglage. Ce qui a été supprimé, ce sont les signatures faciles : plus de marqueur
  fixe annonçant le payload, et plus de traînée d'un seul tenant (sur un secret de
  200 caractères, la plus longue série contiguë passe de 588 symboles à 90). La
  longueur du message reste corrélée à celle du secret, sauf en mode paliers.
- **Confiance dans le client** : le texte est en clair dans le client au moment où on
  le tape, et le mot de passe est stocké en clair dans les réglages Vencord
  (`settings.json`).
- **Pas un remplacement de Signal.** Voir [SECURITY.md](SECURITY.md) pour le modèle
  de menace détaillé.

## Compatibilité

Le format **v4 est incompatible avec les versions antérieures** : tous les participants doivent mettre
à jour en même temps. Un message d'une autre version reste affiché comme une phrase
banale, il ne se déchiffre pas.

## Installation

1. Placer le dossier dans `Vencord/src/userplugins/papotage/`.
2. Compiler Vencord : `pnpm build` (ou `node scripts/build/build.mjs`).
3. Activer **Papotage** dans les réglages des plugins, puis définir le mot de passe.

Sur **Vesktop**, faire pointer `state.json` (`vencordDir`) sur le dossier `dist` de la
compilation, et s'assurer qu'il contient un `package.json` (sinon Vesktop retélécharge
Vencord par-dessus).

## Développement

Le cœur (chiffrement + stéganographie + logique du plugin) ne dépend pas de Discord et
se teste en local :

```bash
npm test        # Node >= 20
npm run bench   # mesures de performance
```

109 tests couvrent l'aller-retour des trois encodages, la séparation des clés par
salon, le padding, l'authentification, le rejet d'entrées hostiles (fuzzing), les
règles d'envoi du plugin, les propriétés de discrétion (absence de marqueur fixe,
dispersion du payload, intégrité des emojis de couverture, variété des phrases) et la
détection d'un message altéré par Discord.

Les tests qui portent sur des grandeurs aléatoires (dispersion, variété des
couvertures) affirment des statistiques d'échantillon avec des seuils tirés de
mesures, pas des tirages uniques : la suite est passée de 2 échecs sur 120 à 0 sur
200 exécutions.

Les chemins chauds sont mesurés, pas devinés (`npm run bench`). Le pré-filtre tourne
sur chaque message de chaque scan de salon : il rejette un message ordinaire en
**0,1 µs** contre 57 µs auparavant, et scanner un salon de 500 messages est passé de
550 µs à 49 µs.

Les API Vencord utilisées (`addChatBarButton`, `addMessagePreSendListener`,
`addMessagePreEditListener`, `updateMessage`, `OptionType.SELECT`, `Toasts`,
`UserStore`) ont été vérifiées contre la source du dépôt Vencord, pas de mémoire. La
CI compile `index.tsx` avec esbuild à chaque changement.

## Structure

- `src/codec.mjs` — chiffrement AES-GCM, encodages (invisible, compact, emoji) et dispersion
- `src/covers.mjs` — génération des phrases de couverture
- `src/random.mjs` — tirage aléatoire uniforme partagé
- `src/plugin-core.mjs` — règles d'envoi et de réception, sans dépendance Vencord
- `src/index.tsx` — câblage Vencord (bouton, événements, toasts)
- `test/` — suite de tests (`node:test`)
- `bench/` — mesures de performance

## Licence

MIT.
