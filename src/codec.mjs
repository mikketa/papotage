// Encodages de Papotage : transforme des octets scellés en caractères que
// Discord transporte sans les afficher, et l'inverse.
//
// Ce module ne chiffre rien — voir `envelope.mjs` — et ne choisit pas ce que dit
// la phrase de couverture : elle lui est fournie. Il ne connaît que des octets,
// des graphèmes et trois alphabets.
//
// Ce que les versions successives ont changé, côté DISSIMULATION :
//   - plus de marqueur fixe (v3). v2 annonçait le payload par un U+2060 : une
//     constante publique, donc la signature parfaite pour un détecteur. Le
//     décodeur ramasse désormais les symboles de son alphabet où qu'ils soient.
//   - payload dispersé dans la couverture au lieu d'un bloc collé à la fin (v3).
//   - plus d'en-tête de densité (v4) : c'était une constante en tête de payload,
//     donc le premier caractère invisible de tout message valait toujours la même
//     valeur, mesuré 400 fois sur 400. La densité se déduit des symboles.
//   - plus d'octet de repère en mode compact (v4), pour la même raison. Le
//     décalage se calcule au lieu de se chercher.
//   - le payload ne touche ni le début ni la fin du message (v4) : un message
//     Discord ordinaire ne commence ni ne finit par un caractère invisible.
//
// À dire clairement : rien de tout cela ne rend le canal indétectable. Un
// scanner qui COMPTE les caractères invisibles d'un message les trouvera
// toujours. Ce qui change, c'est qu'il faut le faire exprès. `npm run audit`
// vérifie sur 600 messages par mode qu'aucune régularité facile n'est revenue.

import { FRAME_HEAD, PAD_BLOCK, plausibleFrame, seal, unseal } from "./envelope.mjs";
import { randomInts } from "./random.mjs";

// ===========================================================================
// Dispersion
// ===========================================================================
// Au lieu de coller le payload en fin de message, on le répartit dans les
// intervalles de la couverture. Deux signatures disparaissent : le marqueur
// fixe qui annonçait le début, et la traînée d'un seul tenant.
//
// Le découpage se fait par GRAPHÈMES et non par points de code : insérer un
// caractère au milieu de « ❤️ » (U+2764 U+FE0F) ou d'un emoji composé casserait
// son rendu et rendrait la couverture visiblement bizarre — l'inverse du but.
const SEGMENTER = typeof Intl !== "undefined" && Intl.Segmenter ? new Intl.Segmenter() : null;

function graphemes(s) {
    if (!SEGMENTER) return [...s]; // repli : points de code
    const out = [];
    for (const { segment } of SEGMENTER.segment(s)) out.push(segment);
    return out;
}

// Répartit `symbols` (tableau de chaînes) dans les intervalles entre graphèmes.
// Les tailles de paquets sont tirées au hasard : deux messages de même longueur
// ne produisent pas la même découpe.
//
// Placement strictement INTÉRIEUR : jamais avant le premier caractère visible,
// jamais après le dernier. Un message Discord ordinaire ne commence ni ne finit
// par un caractère invisible — laisser l'une ou l'autre position ouverte donnait
// un détecteur d'une ligne (90 % au début, 91 % à la fin, mesurés).
//
// `fromGrapheme` protège une portion de tête : le mode compact y laisse les
// sélecteurs de variation que porte déjà la couverture.
function scatter(cover, symbols, { fromGrapheme = 0 } = {}) {
    const all = graphemes(cover);
    const head = all.slice(0, fromGrapheme).join(""); // zone laissée intacte
    const gs = all.slice(fromGrapheme);

    // Un intervalle après `head` reste intérieur au message si head n'est pas
    // vide. Sinon on ne dispose que des intervalles entre graphèmes.
    const leading = head.length > 0;
    const slots = gs.length - (leading ? 0 : 1);
    if (slots < 1) {
        // Couverture d'un seul graphème : aucune position intérieure n'existe.
        // On refuse de perdre des symboles ; l'appelant garantit une couverture
        // assez longue pour que ce cas ne se produise pas en pratique.
        return head + gs.join("") + symbols.join("");
    }

    // Composition aléatoire uniforme de symbols.length en `slots` parts.
    const cuts = randomInts(slots - 1, symbols.length + 1);
    cuts.sort((a, b) => a - b);
    const parts = [];
    let prev = 0;
    for (const c of cuts) { parts.push(symbols.slice(prev, c).join("")); prev = c; }
    parts.push(symbols.slice(prev).join(""));

    let out = head, i = 0;
    if (leading) out += parts[i++];
    for (let k = 0; k < gs.length; k++) {
        out += gs[k];
        if (k < gs.length - 1 && i < parts.length) out += parts[i++]; // jamais après le dernier
    }
    return out;
}

// La couverture est fournie par l'appelant : choisir ce qu'elle dit est une
// décision de produit, pas d'encodage. Le codec exige seulement qu'elle existe
// et qu'elle ait de quoi accueillir des symboles entre deux caractères.
function requireCover(cover) {
    if (typeof cover !== "string" || cover.length === 0) {
        throw new TypeError("Papotage : une phrase de couverture est requise pour encoder.");
    }
    return cover;
}

// ===========================================================================
// Mode invisible (zero-width) — le mode par défaut.
// ===========================================================================
// Alphabet zero-width extensible. Plus il y a de symboles, moins on envoie de
// caractères : 4 symboles = 2 bits/car, 8 symboles = 3 bits/car (-33 %).
// - index 0-3 : sûrs, préservés par Discord (ZWSP, ZWNJ, ZWJ, word-joiner).
// - index 4-7 : opérateurs invisibles (même famille Cf que le word-joiner), très
//   probablement préservés -> activés par la densité 3 bits.
// Aucun en-tête n'annonce la densité : ce serait une constante en tête de
// payload. Elle se déduit — un symbole >= 4 ne peut venir que de l'alphabet
// 3 bits — donc le récepteur s'adapte seul, sans rien qui le trahisse.
const ZW_ALL = ["​", "‌", "‍", "⁠", "⁡", "⁢", "⁣", "⁤"];
const ZW_VAL = new Map(ZW_ALL.map((c, i) => [c, i]));

// Alphabet du mode emoji : 16 emojis = les 16 valeurs hexa. Tous
// single-codepoint, sans sélecteur de variation ni modificateur de teinte.
// Déclaré ici avec les autres alphabets : le pré-filtre en a besoin bien avant
// la section qui encode.
export const EMOJI = ["😀", "😂", "😅", "😍", "🤔", "😎", "😭", "😡", "👍", "🔥", "🎉", "💀", "👀", "🚀", "🍕", "💯"];
const EMOJI_INDEX = new Map(EMOJI.map((e, i) => [e, i]));

// Sélecteurs de variation du mode compact (256 valeurs disponibles).
function byteToVS(b) { return b < 16 ? 0xfe00 + b : 0xe0100 + (b - 16); }
function vsToByte(cp) {
    if (cp >= 0xfe00 && cp <= 0xfe0f) return cp - 0xfe00;
    if (cp >= 0xe0100 && cp <= 0xe01ef) return cp - 0xe0100 + 16;
    return null;
}

// Une couverture ne doit porter aucun symbole de l'alphabet utilisé, sinon il
// se mélangerait au payload une fois dispersé. Conséquence assumée : un emoji
// composé avec un liant (👨‍👩‍👧) ou un sélecteur (❤️) fourni dans une couverture
// perso perd sa composition. Les couvertures automatiques n'en contiennent pas.
function stripHidden(s) {
    let out = "";
    for (const ch of s) if (!ZW_VAL.has(ch)) out += ch;
    return out;
}

// Indice du premier graphème après lequel on peut poser le payload compact :
// juste derrière le dernier graphème de la couverture qui porte déjà un
// sélecteur de variation. Ceux de « ❤️ » ou « 🏳️‍🌈 » se retrouvent ainsi tous avant
// la trame, donc absorbés par le décalage calculé au décodage — la couverture
// garde son rendu exact au lieu d'être amputée.
function firstCompactSlot(cover) {
    const gs = graphemes(cover);
    let idx = 0;
    for (let i = 0; i < gs.length; i++) {
        for (const ch of gs[i]) {
            if (vsToByte(ch.codePointAt(0)) !== null) { idx = i + 1; break; }
        }
    }
    return idx;
}

// Ce qu'un humain voit : le message débarrassé des symboles de nos alphabets.
// Sert à reconnaître nos propres messages quand Discord nous les renvoie.
export function visibleText(message) {
    let out = "";
    for (const ch of message) {
        if (ZW_VAL.has(ch)) continue;
        if (vsToByte(ch.codePointAt(0)) !== null) continue;
        out += ch;
    }
    return out;
}

// Un seul passage pour tout ce dont le pré-filtre a besoin : combien de
// symboles de chaque alphabet invisible, et la plus longue série d'emojis du
// dictionnaire. Appelé sur CHAQUE message de CHAQUE scan de salon, donc écrit
// pour ne rien allouer :
//   - itération par unité UTF-16 avec charCodeAt, pas `for...of` qui construit
//     une chaîne par caractère ;
//   - sortie anticipée dès qu'un seuil est atteint, testée seulement dans les
//     branches qui incrémentent — un message ordinaire n'en paie jamais le prix.
const EMOJI_CP = new Set(EMOJI.map(e => e.codePointAt(0)));

// Rejet rapide. Un message de salon ordinaire — même accentué — ne contient
// aucun caractère susceptible d'alimenter les compteurs : ni zero-width, ni
// sélecteur de variation, ni demi-codet haut (donc aucun emoji ni sélecteur
// supplémentaire). Le moteur d'expressions régulières tranche ça en 0,03 µs,
// contre 8,4 µs pour la boucle sur 1900 caractères — mesuré, soit 280x.
// Pas de drapeau `u` : on veut raisonner en unités UTF-16, demi-codets compris.
const MAYBE_SYMBOL = /[\u200b-\u200d\u2060-\u2064\ufe00-\ufe0f\ud800-\udbff]/;
const NOTHING = Object.freeze({ hidden: 0, compact: 0, emojiRun: 0 });

export function scanSymbols(message, stop = {}) {
    if (!MAYBE_SYMBOL.test(message)) return NOTHING;
    const stopHidden = stop.hidden ?? Infinity;
    const stopCompact = stop.compact ?? Infinity;
    const stopEmoji = stop.emoji ?? Infinity;
    let hidden = 0, compact = 0, run = 0, bestRun = 0;

    for (let i = 0; i < message.length; i++) {
        const c = message.charCodeAt(i);
        if (c >= 0xd800 && c <= 0xdbff && i + 1 < message.length) {
            const cp = (c - 0xd800) * 0x400 + (message.charCodeAt(i + 1) - 0xdc00) + 0x10000;
            i++;
            if (cp >= 0xe0100 && cp <= 0xe01ef) {
                if (++compact >= stopCompact) break;
            } else if (EMOJI_CP.has(cp)) {
                run++;
                if (run > bestRun) {
                    bestRun = run;
                    if (bestRun >= stopEmoji) break;
                }
                continue;
            }
        } else if ((c >= 0x200b && c <= 0x200d) || (c >= 0x2060 && c <= 0x2064)) {
            if (++hidden >= stopHidden) break;
        } else if (c >= 0xfe00 && c <= 0xfe0f) {
            if (++compact >= stopCompact) break;
        }
        run = 0;
    }
    return { hidden, compact, emojiRun: bestRun };
}

// Compteurs simples, pour les tests et les mesures.
export function countHiddenSymbols(message) {
    return scanSymbols(message).hidden;
}

export function countCompactSymbols(message) {
    return scanSymbols(message).compact;
}

// `bits` = 2 (sûr, 4 symboles) ou 3 (dense, 8 symboles). Le flux d'octets est
// ré-empaqueté en groupes de `bits` bits (pas d'alignement octet requis).
export async function encodeHidden(text, passphrase, { cover, bits = 3, context = "", padding } = {}) {
    if (bits !== 2 && bits !== 3) bits = 3;
    const bytes = await seal(text, passphrase, context, padding);
    const mask = (1 << bits) - 1;
    const syms = []; // aucun en-tête : ce serait une constante en tête de payload
    let acc = 0, accBits = 0;
    for (const byte of bytes) {
        acc = (acc << 8) | byte;
        accBits += 8;
        while (accBits >= bits) {
            accBits -= bits;
            syms.push(ZW_ALL[(acc >> accBits) & mask]);
        }
    }
    if (accBits > 0) syms.push(ZW_ALL[(acc << (bits - accBits)) & mask]); // bits de fin
    // Pas de position de tête : sinon 90 % des messages commençaient par un
    // caractère invisible (mesuré), ce qu'un message Discord ordinaire ne fait
    // jamais. C'est le même défaut que l'en-tête de densité — une régularité
    // qui suffit à trier, sans rien décoder.
    return scatter(stripHidden(requireCover(cover)), syms, { allowLeading: false });
}

// Dépaquette un flux de symboles en octets pour une densité donnée.
// Renvoie null si un symbole sort de l'alphabet annoncé.
function unpackBits(syms, bits) {
    const alpha = 1 << bits;
    let acc = 0, accBits = 0;
    const bytes = [];
    for (const v of syms) {
        if (v >= alpha) return null;
        acc = (acc << bits) | v;
        accBits += bits;
        if (accBits >= 8) {
            accBits -= 8;
            bytes.push((acc >> accBits) & 0xff);
        }
    }
    return bytes.length ? new Uint8Array(bytes) : null; // bits restants = padding
}

// Renvoie le texte clair, ou null si pas de payload / mauvaise clé / mauvais
// contexte. Les symboles sont ramassés dans l'ordre du texte, où qu'ils soient :
// aucun marqueur de début n'est nécessaire, et du texte ajouté après coup
// (message édité, signature de bot) ne gêne pas.
//
// La densité n'est plus annoncée, elle se déduit : un symbole >= 4 ne peut venir
// que de l'alphabet 3 bits. Un payload 3 bits fait au moins 118 symboles tirés
// uniformément sur 8 valeurs, donc la probabilité qu'aucun n'atteigne 4 est de
// 2^-118 — en pratique une seule densité est jamais essayée.
export async function decodeHidden(message, passphrase, { context = "" } = {}) {
    // Itération par unité UTF-16 : `for...of` construit une chaîne par
    // caractère, ce qui domine le coût sur un message de plusieurs centaines de
    // symboles. Les huit symboles sont tous dans le plan de base, en deux plages
    // contiguës — leur valeur se calcule sans table.
    const syms = [];
    let max = 0;
    for (let i = 0; i < message.length; i++) {
        const c = message.charCodeAt(i);
        let v = -1;
        if (c >= 0x200b && c <= 0x200d) v = c - 0x200b;          // ZW[0..2]
        else if (c >= 0x2060 && c <= 0x2064) v = c - 0x2060 + 3; // ZW[3..7]
        if (v >= 0) {
            syms.push(v);
            if (v > max) max = v;
        }
    }
    if (syms.length < 8) return null;
    for (const bits of max >= 4 ? [3] : [2, 3]) {
        const bytes = unpackBits(syms, bits);
        if (!bytes || !plausibleFrame(bytes.length)) continue;
        try {
            return await unseal(bytes, passphrase, context);
        } catch { /* densité suivante */ }
    }
    return null;
}

// ===========================================================================
// Mode compact (sélecteurs de variation) : 1 octet = 1 caractère invisible,
// soit ~2,7x plus court que le mode zero-width dense. Les sélecteurs se collent
// au caractère visible qui les précède : rendu invisible garanti, pas de carré
// vide, pas de débordement à la sélection.
// Contrepartie : encodage moins universel que les zero-width, à réserver aux
// interlocuteurs qui ont la même version du plugin.
// ===========================================================================
const ATTEMPT_CAP = 32;    // borne le travail sur une entrée hostile

// Décalage maximal admis entre le début des sélecteurs et celui de la trame :
// ceux que la couverture porte légitimement (❤️, drapeaux) précèdent les nôtres.
// Il n'y a plus d'octet MAGIC pour marquer le départ — c'était une constante,
// donc le premier sélecteur du message valait toujours la même valeur, mesuré
// 100 % sur 600 messages : exactement le défaut de l'ancien en-tête de densité.
const MAX_SKEW = 8;

export async function encodeCompact(text, passphrase, { cover, context = "", padding } = {}) {
    const body = await seal(text, passphrase, context, padding);
    const syms = [];
    for (const b of body) syms.push(String.fromCodePoint(byteToVS(b)));
    const base = requireCover(cover);
    return scatter(base, syms, { allowLeading: false, fromGrapheme: firstCompactSlot(base) });
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
        if (c >= 0xfe00 && c <= 0xfe0f) {
            bytes.push(c - 0xfe00);
        } else if (c >= 0xdb40 && c <= 0xdb43 && i + 1 < message.length) {
            // Plage supplémentaire U+E0100-E01EF : demi-codet haut U+DB40.
            const cp = (c - 0xd800) * 0x400 + (message.charCodeAt(i + 1) - 0xdc00) + 0x10000;
            if (cp >= 0xe0100 && cp <= 0xe01ef) { bytes.push(cp - 0xe0100 + 16); i++; }
        }
    }
    const skew = ((bytes.length - FRAME_HEAD) % PAD_BLOCK + PAD_BLOCK) % PAD_BLOCK;
    if (skew > MAX_SKEW || !plausibleFrame(bytes.length - skew)) return null;
    try {
        return await unseal(new Uint8Array(bytes.slice(skew)), passphrase, context);
    } catch {
        return null;
    }
}

// ===========================================================================
// Mode emoji : les emojis VISIBLES portent le secret. 16 emojis = les 16
// valeurs hexa -> 1 octet = 2 emojis. Le message ressemble à un délire d'emojis
// mais c'est le secret chiffré. Beaucoup moins discret que les modes invisibles
// (une longue traînée d'emojis se voit) : réservé aux messages courts.
// ===========================================================================
// Le mode emoji garde un octet de repère : sa traînée d'emojis est de toute
// façon visible, la discrétion n'est pas son argument.
const EMOJI_MAGIC = 0xc7;

// La couverture est facultative ici, et n'est qu'un préfixe : la traînée
// d'emojis est déjà visible, aucune phrase ne la dissimule.
export async function encodeEmoji(text, passphrase, { cover, context = "", padding } = {}) {
    const body = await seal(text, passphrase, context, padding);
    let seq = EMOJI[EMOJI_MAGIC >> 4] + EMOJI[EMOJI_MAGIC & 0x0f];
    for (const b of body) seq += EMOJI[b >> 4] + EMOJI[b & 0x0f];
    // La couverture est optionnelle ici : la traînée d'emojis est déjà le message.
    const prefix = cover && cover.trim() ? cover.trim() + " " : "";
    return prefix + seq;
}

export async function decodeEmoji(message, passphrase, { context = "" } = {}) {
    const nibbles = [];
    for (const ch of message) {
        const i = EMOJI_INDEX.get(ch);
        if (i !== undefined) nibbles.push(i);
    }
    let tries = 0;
    // Deux alignements possibles si un emoji parasite précède la séquence, et
    // une couverture peut contenir un faux MAGIC (0xC7 se rend 👀😡).
    for (const off of [0, 1]) {
        const bytes = [];
        for (let i = off; i + 1 < nibbles.length; i += 2) bytes.push((nibbles[i] << 4) | nibbles[i + 1]);
        for (let s = bytes.indexOf(EMOJI_MAGIC); s >= 0; s = bytes.indexOf(EMOJI_MAGIC, s + 1)) {
            if (++tries > ATTEMPT_CAP) return null;
            try {
                return await unseal(new Uint8Array(bytes.slice(s + 1)), passphrase, context);
            } catch { /* MAGIC suivant / autre alignement */ }
        }
    }
    return null;
}
