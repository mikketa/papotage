# Papotage

Plugin Vencord qui chiffre les messages Discord et cache le résultat dans du texte
invisible. Sans le plugin, un message ressemble à une réponse quelconque
(« ok ça marche 👍 ») ; avec le plugin et le bon mot de passe, il s'affiche en clair.

## Fonctionnement

1. Le message est chiffré en AES-GCM 256. La clé est dérivée du mot de passe partagé
   (PBKDF2-SHA256, 600 000 itérations) **et de l'identifiant du salon** : le même mot
   de passe donne une clé différente dans chaque conversation.
2. Les octets chiffrés sont encodés en caractères Unicode invisibles, accrochés
   derrière une courte phrase de couverture. Discord les préserve.
3. À la réception, le plugin repère la partie invisible, la déchiffre et remplace le
   contenu affiché par le vrai message. Les autres ne voient que la couverture.

Le chiffrement s'active salon par salon avec le cadenas de la barre de message
(gris = off, vert = on, orange = armé mais sans mot de passe).

## Utilisation

- **Mot de passe** : à définir dans les réglages du plugin, identique chez tous les
  participants. À transmettre par un autre canal.
- **Phrase de couverture** : par défaut une phrase est tirée au hasard parmi plus de
  500 combinaisons. Pour écrire soi-même la façade et garder une conversation
  cohérente, utiliser `phrase visible | message secret`.
  Exemple : `ouais tranquille et toi ? | rdv à 20h` affiche « ouais tranquille et
  toi ? » pour tout le monde, et le vrai message pour ceux qui ont le plugin.

### Réglages

| Réglage | Rôle |
|---|---|
| Passphrase | Mot de passe partagé (obligatoire) |
| Encodage | Mode d'encodage du secret (voir ci-dessous) |
| Auto Decrypt | Déchiffrer automatiquement les messages reçus |
| Show 🔓 | Préfixer les messages déchiffrés pour les repérer |
| Custom Cover | Phrase de couverture par défaut |
| Separator | Délimiteur entre couverture et secret (par défaut ` &#124; `) |

### Modes d'encodage

| Mode | Coût par octet | Capacité (1 message) | Remarque |
|---|---|---|---|
| **Invisible dense** (défaut) | 2,67 car. | ≈ 890 car. de secret | 8 symboles zero-width |
| Invisible sûr | 4 car. | ≈ 550 car. | 4 symboles seulement, le jeu le plus universel |
| Compact | 1 car. | ≈ 1 260 car. | Sélecteurs de variation, accrochés à la couverture |
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
- **Détectabilité** : invisible à la lecture, mais un scan automatique repère la
  présence de caractères zero-width (sans pouvoir lire le contenu chiffré). La
  longueur du message reste observable, arrondie par blocs de 16 octets.
- **Confiance dans le client** : le texte est en clair dans le client au moment où on
  le tape, et le mot de passe est stocké en clair dans les réglages Vencord
  (`settings.json`).
- **Pas un remplacement de Signal.** Voir [SECURITY.md](SECURITY.md) pour le modèle
  de menace détaillé.

## Compatibilité

Le format **v2 est incompatible avec la v1** : tous les participants doivent mettre à
jour en même temps. Un message v1 reçu par un plugin v2 (et l'inverse) reste affiché
comme une phrase banale, il ne se déchiffre pas.

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
```

82 tests couvrent l'aller-retour des trois encodages, la séparation des clés par
salon, le padding, l'authentification, le rejet d'entrées hostiles (fuzzing), et les
règles d'envoi du plugin.

## Structure

- `src/codec.mjs` — chiffrement AES-GCM et encodages (invisible, compact, emoji)
- `src/covers.mjs` — génération des phrases de couverture
- `src/plugin-core.mjs` — règles d'envoi et de réception, sans dépendance Vencord
- `src/index.tsx` — câblage Vencord (bouton, événements, toasts)
- `test/` — suite de tests (`node:test`)

## Licence

MIT.
