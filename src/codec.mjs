// Encodages de Papotage : transforme des octets scellés en caractères que
// Discord transporte sans les afficher, et l'inverse.
//
// Ce module ne chiffre rien — voir `envelope.mjs` — et ne choisit pas ce que dit
// la phrase de couverture : elle lui est fournie. Il ne connaît que des octets,
// des graphèmes et trois alphabets.
//
// Rien de constant n'annonce le payload : ni marqueur de début, ni en-tête de
// densité, ni octet de repère, et il ne touche ni le premier ni le dernier
// caractère du message. Chacune de ces régularités a existé ici, a été mesurée,
// puis supprimée : l'historique et le raisonnement sont dans SECURITY.md,
// section « Dissimulation ». Toute modification de ce fichier doit la relire.
//
// À dire clairement : rien de tout cela ne rend le canal indétectable. Un
// scanner qui COMPTE les caractères invisibles d'un message les trouvera
// toujours. Ce qui change, c'est qu'il faut le faire exprès. `npm run audit`
// vérifie sur 600 messages par mode qu'aucune régularité facile n'est revenue.

import { FRAME_HEAD, PAD_BLOCK, plausibleFrame, seal, unseal } from "./envelope.mjs";
import { graphemes } from "./graphemes.mjs";
import { randomInts } from "./random.mjs";

// ===========================================================================
// Les trois alphabets
// ===========================================================================
// Chacun expose la même paire : `…Char(valeur)` pour encoder, `…Value(point de
// code)` pour décoder, -1 quand ce n'est pas un des siens. Les plages sont
// déclarées une seule fois et l'arithmétique n'est écrite qu'ici : la réécrire
// à la main ailleurs cassait le décodage en silence dès qu'on réordonnait.

// Zero-width : deux plages contiguës du plan de base. Plus il y a de symboles,
// moins on envoie de caractères : 4 = 2 bits/car (mode « sûr », le jeu le plus
// universellement préservé), 8 = 3 bits/car (défaut, -33 %).
//   - index 0-3 : préservés par Discord (ZWSP, ZWNJ, ZWJ, word-joiner) ;
//   - index 4-7 : opérateurs invisibles, même famille Cf que le word-joiner.
const ZW_LOW = 0x200b, ZW_LOW_N = 3;   // U+200B..U+200D
const ZW_HIGH = 0x2060, ZW_HIGH_N = 5; // U+2060..U+2064

const ZW_CHAR = Array.from({ length: ZW_LOW_N + ZW_HIGH_N },
    (_, v) => String.fromCharCode(v < ZW_LOW_N ? ZW_LOW + v : ZW_HIGH + v - ZW_LOW_N));

function zwValue(cp) {
    if (cp >= ZW_LOW && cp < ZW_LOW + ZW_LOW_N) return cp - ZW_LOW;
    if (cp >= ZW_HIGH && cp < ZW_HIGH + ZW_HIGH_N) return cp - ZW_HIGH + ZW_LOW_N;
    return -1;
}

// Sélecteurs de variation du mode compact : 256 valeurs, donc 1 octet = 1
// caractère. Ils se collent au caractère visible qui les précède.
const vsChar = b => String.fromCodePoint(b < 16 ? 0xfe00 + b : 0xe0100 + b - 16);

function vsValue(cp) {
    if (cp >= 0xfe00 && cp <= 0xfe0f) return cp - 0xfe00;
    if (cp >= 0xe0100 && cp <= 0xe01ef) return cp - 0xe0100 + 16;
    return -1;
}

// Mode emoji : 16 emojis = les 16 valeurs hexa. Tous single-codepoint, sans
// sélecteur de variation ni modificateur de teinte.
export const EMOJI = ["😀", "😂", "😅", "😍", "🤔", "😎", "😭", "😡", "👍", "🔥", "🎉", "💀", "👀", "🚀", "🍕", "💯"];
const EMOJI_VALUE = new Map(EMOJI.map((e, v) => [e.codePointAt(0), v]));
const emojiValue = cp => EMOJI_VALUE.get(cp) ?? -1;

// ===========================================================================
// Parcours d'un message
// ===========================================================================
// Ces boucles tournent sur chaque message de chaque scan de salon, d'où deux
// règles tenues partout : parcours par unité UTF-16 avec `charCodeAt` plutôt que
// `for...of`, qui alloue une chaîne par caractère (74 µs contre 5 µs sur un
// message de 1300 unités, mesuré), et rien d'alloué en régime normal.

// Point de code de la paire de substituts commençant à `i`, ou -1 : ni `c` seul
// ni un demi-codet orphelin ne sont donc jamais interprétés comme un symbole.
// `maybePair` filtre en une comparaison le cas courant, où il n'y a rien à
// calculer : `String.prototype.codePointAt` ferait le même travail mais coûte
// 25 % de plus sur le pré-filtre (mesuré), n'ayant pas ce raccourci.
const maybePair = c => c >= 0xd800 && c <= 0xdbff;

function pairAt(s, i, c) {
    if (!maybePair(c) || i + 1 >= s.length) return -1;
    const lo = s.charCodeAt(i + 1);
    if (lo < 0xdc00 || lo > 0xdfff) return -1;
    return (c - 0xd800) * 0x400 + (lo - 0xdc00) + 0x10000;
}

// Rejet rapide. Un message de salon ordinaire — même accentué — ne contient
// aucun caractère susceptible d'appartenir à un alphabet : ni zero-width, ni
// sélecteur de variation, ni demi-codet haut (donc aucun emoji ni sélecteur
// supplémentaire). Le moteur d'expressions régulières tranche ça en 0,03 µs
// contre 8,4 µs pour la boucle sur 1900 caractères — mesuré, soit 280x.
// Pas de drapeau `u` : on raisonne en unités UTF-16, demi-codets compris.
// Le même raisonnement vaut À L'INTÉRIEUR des boucles : la plus basse unité
// UTF-16 qu'un alphabet puisse employer est U+200B (les sélecteurs commencent à
// U+FE00, les paires à U+D800), donc une seule comparaison écarte des trois
// alphabets à la fois tout caractère écrit courant — lettres, chiffres, accents,
// ponctuation. Sans ce plancher, chacun d'eux payait huit comparaisons.
const MAYBE_SYMBOL = /[\u200b-\u200d\u2060-\u2064\ufe00-\ufe0f\ud800-\udbff]/;
const SYMBOL_FLOOR = ZW_LOW;

// Retire d'une chaîne les symboles des alphabets demandés. Deux usages :
//   - `visibleText` : ce que voit un humain, pour reconnaître nos propres
//     messages quand Discord nous les renvoie ;
//   - avant d'encoder : une couverture ne doit porter aucun symbole de
//     l'alphabet utilisé, sinon il se mélangerait au payload une fois dispersé.
// Conséquence assumée sur une couverture perso : un emoji composé avec un liant
// (👨‍👩‍👧) ou un sélecteur (❤️) y perd sa composition. Les couvertures
// automatiques n'en contiennent pas.
const ZW = 1, VS = 2; // drapeaux combinables : quel(s) alphabet(s) retirer

function strip(s, alphabets) {
    if (!MAYBE_SYMBOL.test(s)) return s;
    let out = "";
    for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        if (c < SYMBOL_FLOOR) { out += s[i]; continue; }
        const cp = maybePair(c) ? pairAt(s, i, c) : -1;
        if (cp < 0) {
            if ((alphabets & ZW) && zwValue(c) >= 0) continue;
            if ((alphabets & VS) && vsValue(c) >= 0) continue;
            out += s[i];
        } else if ((alphabets & VS) && vsValue(cp) >= 0) {
            i++;                    // paire retirée
        } else {
            out += s[i] + s[i + 1]; // paire gardée entière
            i++;
        }
    }
    return out;
}

export const visibleText = message => strip(message, ZW | VS);

// Un seul passage pour tout ce dont le pré-filtre a besoin : combien de symboles
// de chaque alphabet invisible, et la plus longue série d'emojis du dictionnaire.
// Les seuils de `stop` permettent de sortir dès qu'ils sont atteints ; ils ne
// sont testés que dans les branches qui incrémentent, donc un message ordinaire
// n'en paie jamais le prix.
const NOTHING = Object.freeze({ hidden: 0, compact: 0, emojiRun: 0 });

export function scanSymbols(message, stop = {}) {
    if (!MAYBE_SYMBOL.test(message)) return NOTHING;
    const maxHidden = stop.hidden ?? Infinity;
    const maxCompact = stop.compact ?? Infinity;
    const maxEmoji = stop.emoji ?? Infinity;
    let hidden = 0, compact = 0, run = 0, bestRun = 0;

    for (let i = 0; i < message.length; i++) {
        const c = message.charCodeAt(i);
        if (c < SYMBOL_FLOOR) { run = 0; continue; }
        const cp = maybePair(c) ? pairAt(message, i, c) : -1;
        if (cp >= 0) {
            i++;
            // Un emoji du dictionnaire d'abord : c'est la paire qu'un message de
            // salon ordinaire contient vraiment. Les plages sont disjointes,
            // l'ordre ne change que le coût.
            if (EMOJI_VALUE.has(cp)) {
                if (++run > bestRun) bestRun = run;
                if (bestRun >= maxEmoji) break;
                continue;
            } else if (vsValue(cp) >= 0) {
                if (++compact >= maxCompact) break;
            }
        } else if (zwValue(c) >= 0) {
            if (++hidden >= maxHidden) break;
        } else if (vsValue(c) >= 0) {
            if (++compact >= maxCompact) break;
        }
        run = 0;
    }
    return { hidden, compact, emojiRun: bestRun };
}

// ===========================================================================
// Dispersion
// ===========================================================================
// Le payload est réparti dans les intervalles de la couverture, avec des tailles
// de paquets tirées au hasard : ni traînée d'un seul tenant, ni découpe
// reproductible d'un envoi à l'autre. Trois contraintes, chacune corrigeant un
// détecteur d'une ligne qui a réellement fonctionné ici (SECURITY.md) :
//
//   - par GRAPHÈMES et non par points de code : insérer un caractère au milieu
//     de « ❤️ » (U+2764 U+FE0F) ou d'un emoji composé casserait son rendu et
//     rendrait la couverture visiblement bizarre — l'inverse du but ;
//   - placement strictement INTÉRIEUR : un message Discord ordinaire ne commence
//     ni ne finit par un caractère invisible (90 % au début, 91 % à la fin quand
//     ces positions étaient ouvertes, mesurés) ;
//   - `from` protège une portion de tête, où le mode compact laisse les
//     sélecteurs de variation que porte déjà la couverture.

// Positions intérieures disponibles. Ce n'est pas une longueur de chaîne : « ok »
// fait deux caractères et n'offre qu'un seul intervalle, où le payload forme
// alors un bloc unique.
const innerSlots = (gs, from) => gs.length - from - (from > 0 ? 0 : 1);

function scatter(gs, symbols, from = 0) {
    const slots = innerSlots(gs, from);
    // Aucune position intérieure : la seule issue serait d'accoler le payload à
    // un bord, c'est-à-dire de produire exactement les régularités que ce module
    // dit avoir supprimées. On refuse plutôt que de dégrader en silence ;
    // l'appelant a vérifié la couverture avant d'arriver ici.
    if (slots < 1) throw new RangeError("couverture trop courte pour disperser le payload");

    // Composition aléatoire uniforme de symbols.length en `slots` parts : les
    // coupes triées donnent les frontières des paquets.
    const cuts = randomInts(slots - 1, symbols.length + 1).sort((a, b) => a - b);
    const first = Math.max(from, 1); // jamais avant le premier graphème
    let out = "", placed = 0;
    for (let g = 0; g < gs.length; g++) {
        if (g >= first) {
            const upTo = g - first < cuts.length ? cuts[g - first] : symbols.length;
            while (placed < upTo) out += symbols[placed++];
        }
        out += gs[g];
    }
    return out;
}

// La couverture est fournie par l'appelant : choisir ce qu'elle dit est une
// décision de produit, pas d'encodage. Mais le codec doit vérifier ce dont IL a
// besoin — des positions où poser des symboles — et renvoie les graphèmes pour
// que l'appelant ne les redécoupe pas.
function coverGraphemes(cover) {
    if (typeof cover !== "string" || cover.length === 0) {
        throw new TypeError("Papotage : une phrase de couverture est requise pour encoder.");
    }
    const gs = graphemes(cover);
    if (innerSlots(gs, 0) < 1) {
        throw new RangeError(
            `Papotage : couverture trop courte pour dissimuler un message (« ${cover} »). `
            + "Il faut au moins deux caractères visibles pour répartir la partie invisible.");
    }
    return gs;
}

// ===========================================================================
// Mode invisible (zero-width) — le mode par défaut.
// ===========================================================================
// `bits` = 2 (sûr, 4 symboles) ou 3 (dense, 8 symboles). Le flux d'octets est
// ré-empaqueté en groupes de `bits` bits (pas d'alignement octet requis).
export async function encodeHidden(text, passphrase, { cover, bits = 3, context = "", padding } = {}) {
    if (bits !== 2 && bits !== 3) bits = 3;
    const bytes = await seal(text, passphrase, context, padding);
    const mask = (1 << bits) - 1;
    const syms = [];
    let acc = 0, accBits = 0;
    for (const byte of bytes) {
        acc = (acc << 8) | byte;
        accBits += 8;
        while (accBits >= bits) {
            accBits -= bits;
            syms.push(ZW_CHAR[(acc >> accBits) & mask]);
        }
    }
    if (accBits > 0) syms.push(ZW_CHAR[(acc << (bits - accBits)) & mask]); // bits de fin
    return scatter(coverGraphemes(strip(cover, ZW)), syms);
}

// Dépaquette un flux de symboles en octets pour une densité donnée. Renvoie null
// si un symbole sort de l'alphabet supposé. La taille de sortie étant connue
// d'avance, on écrit directement dans un Uint8Array (mesuré 5,5 -> 1,6 µs sur
// 550 octets).
function unpackBits(syms, bits) {
    const alpha = 1 << bits;
    const bytes = new Uint8Array((syms.length * bits) >> 3);
    let acc = 0, accBits = 0, n = 0;
    for (const v of syms) {
        if (v >= alpha) return null;
        acc = (acc << bits) | v;
        accBits += bits;
        if (accBits >= 8) {
            accBits -= 8;
            bytes[n++] = (acc >> accBits) & 0xff;
        }
    }
    return n ? bytes.subarray(0, n) : null; // bits restants = padding
}

// Ouvre une trame candidate, ou null : mauvaise clé, mauvais contexte, message
// d'un inconnu, longueur impossible. Les trois décodeurs s'en servent — un
// message illisible n'est jamais une exception, c'est le cas courant.
async function open(bytes, passphrase, context) {
    if (!plausibleFrame(bytes.length)) return null;
    try {
        return await unseal(bytes, passphrase, context);
    } catch {
        return null;
    }
}

// Renvoie le texte clair, ou null si pas de payload / mauvaise clé / mauvais
// contexte. Les symboles sont ramassés dans l'ordre du texte, où qu'ils soient :
// aucun marqueur de début n'est nécessaire, et du texte ajouté après coup
// (message édité, signature de bot) ne gêne pas.
//
// La densité se déduit au lieu d'être annoncée : un symbole >= 4 ne peut venir
// que de l'alphabet 3 bits. Un payload 3 bits fait au moins 118 symboles tirés
// uniformément sur 8 valeurs, donc la probabilité qu'aucun n'atteigne 4 est de
// 2^-118 — en pratique une seule densité est jamais essayée.
export async function decodeHidden(message, passphrase, { context = "" } = {}) {
    const syms = [];
    let max = 0;
    for (let i = 0; i < message.length; i++) {
        const v = zwValue(message.charCodeAt(i));
        if (v >= 0) {
            syms.push(v);
            if (v > max) max = v;
        }
    }
    if (syms.length < 8) return null;
    for (const bits of max >= 4 ? [3] : [2, 3]) { // >= 4 : forcément l'alphabet 3 bits
        const bytes = unpackBits(syms, bits);
        const texte = bytes && await open(bytes, passphrase, context);
        if (texte != null) return texte;
    }
    return null;
}

// ===========================================================================
// Mode compact (sélecteurs de variation) : 1 octet = 1 caractère invisible,
// soit ~2,7x plus court que le mode zero-width dense. Rendu invisible garanti,
// pas de carré vide, pas de débordement à la sélection.
// Contrepartie : encodage moins universel que les zero-width, à réserver aux
// interlocuteurs qui ont la même version du plugin.
// ===========================================================================
const HAS_VS = /[\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}]/u;

// Décalage maximal admis entre le début des sélecteurs et celui de la trame :
// ceux que la couverture porte légitimement (❤️, drapeaux) précèdent les nôtres.
const MAX_SKEW = 8;

// Indice du premier graphème après lequel poser le payload : juste derrière le
// dernier graphème de la couverture qui porte déjà un sélecteur. Ceux de « ❤️ »
// ou « 🏳️‍🌈 » se retrouvent ainsi tous avant la trame, donc absorbés par le
// décalage calculé au décodage — la couverture garde son rendu exact.
function firstFreeSlot(gs) {
    let at = 0;
    for (let i = 0; i < gs.length; i++) if (HAS_VS.test(gs[i])) at = i + 1;
    return at;
}

export async function encodeCompact(text, passphrase, { cover, context = "", padding } = {}) {
    const body = await seal(text, passphrase, context, padding);
    const syms = Array.from(body, vsChar);
    // Le balayage des graphèmes ne sert que si la couverture porte vraiment un
    // sélecteur — un test d'expression régulière coûte 0,03 µs contre 20 µs de
    // segmentation (mesuré), et le cas courant est « aucun ».
    let gs = coverGraphemes(cover);
    let from = HAS_VS.test(cover) ? firstFreeSlot(gs) : 0;
    // Plus de place après eux : on préfère alors amputer l'emoji de la couverture
    // (« ❤️ » rendu « ❤ ») plutôt que de coller le payload en fin de message. Le
    // rendu se dégrade, la dissimulation non.
    if (innerSlots(gs, from) < 1) {
        gs = coverGraphemes(strip(cover, VS));
        from = 0;
    }
    return scatter(gs, syms, from);
}

// Renvoie le texte clair, ou null. Sans marqueur de départ, le décalage ne
// s'essaie pas : il se CALCULE. La trame ayant une longueur congrue à 0 modulo
// PAD_BLOCK une fois l'en-tête retiré, et le décalage restant sous PAD_BLOCK,
// une seule valeur est possible — donc un seul déchiffrement, y compris pour
// rejeter un message qui n'est pas pour nous.
export async function decodeCompact(message, passphrase, { context = "" } = {}) {
    const bytes = [];
    for (let i = 0; i < message.length; i++) {
        const c = message.charCodeAt(i);
        const cp = maybePair(c) ? pairAt(message, i, c) : -1;
        const v = vsValue(cp < 0 ? c : cp);
        if (v >= 0) bytes.push(v);
        if (cp >= 0) i++;
    }
    const skew = ((bytes.length - FRAME_HEAD) % PAD_BLOCK + PAD_BLOCK) % PAD_BLOCK;
    if (skew > MAX_SKEW) return null;
    return open(new Uint8Array(bytes.slice(skew)), passphrase, context);
}

// ===========================================================================
// Mode emoji : les emojis VISIBLES portent le secret. 16 emojis = les 16 valeurs
// hexa -> 1 octet = 2 emojis. Le message ressemble à un délire d'emojis mais
// c'est le secret chiffré. Beaucoup moins discret que les modes invisibles (une
// longue traînée d'emojis se voit) : réservé aux messages courts.
// ===========================================================================
// Ce mode garde un octet de repère : sa traînée d'emojis est de toute façon
// visible, la discrétion n'est pas son argument.
const EMOJI_MAGIC = 0xc7;
const ATTEMPT_CAP = 32; // borne le travail sur une entrée hostile

export async function encodeEmoji(text, passphrase, { cover, context = "", padding } = {}) {
    const body = await seal(text, passphrase, context, padding);
    let seq = "";
    for (const b of [EMOJI_MAGIC, ...body]) seq += EMOJI[b >> 4] + EMOJI[b & 0x0f];
    // La couverture est optionnelle ici : la traînée d'emojis est déjà le message.
    return (cover && cover.trim() ? cover.trim() + " " : "") + seq;
}

export async function decodeEmoji(message, passphrase, { context = "" } = {}) {
    const nibbles = [];
    for (let i = 0; i < message.length; i++) {
        const c = message.charCodeAt(i);
        const cp = maybePair(c) ? pairAt(message, i, c) : -1;
        if (cp < 0) continue;
        i++;
        const v = emojiValue(cp);
        if (v >= 0) nibbles.push(v);
    }
    let tries = 0;
    // Deux alignements possibles si un emoji parasite précède la séquence, et
    // une couverture peut contenir un faux MAGIC (0xC7 se rend 👀😡).
    for (const off of [0, 1]) {
        const bytes = [];
        for (let i = off; i + 1 < nibbles.length; i += 2) bytes.push((nibbles[i] << 4) | nibbles[i + 1]);
        for (let s = bytes.indexOf(EMOJI_MAGIC); s >= 0; s = bytes.indexOf(EMOJI_MAGIC, s + 1)) {
            if (++tries > ATTEMPT_CAP) return null;
            const texte = await open(new Uint8Array(bytes.slice(s + 1)), passphrase, context);
            if (texte != null) return texte; // sinon : MAGIC suivant, autre alignement
        }
    }
    return null;
}
