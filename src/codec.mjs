// Papotage — chiffre un texte puis le cache dans un message d'apparence banale.
// Fonctionne dans Node (>=20) et dans le navigateur : utilise globalThis.crypto.
//
// ===========================================================================
// Format v4 (incompatible avec les versions antérieures : la séparation est
// assurée par le domaine de dérivation, un message d'une autre version se
// décode en null).
// ===========================================================================
//
//   clair ──▶ [flags(1)] ──▶ deflate? ──▶ padding ──▶ AES-GCM ──▶ octets
//                                                                   │
//                          ┌────────────────────────────────────────┘
//                          ▼
//   octets = nonce(12 o) || ciphertext || tag(16 o)
//
// Chiffrement (inchangé depuis v2) : nonce de 12 octets aléatoires, tag GCM
// complet de 128 bits, sel PBKDF2 dérivé du salon, drapeau de compression
// placé DANS le clair chiffré pour ne pas fuiter la compressibilité.
//
// Ce que v3 et v4 ont changé, côté DISSIMULATION :
//   - plus de marqueur fixe. v2 annonçait le payload par un U+2060 : une
//     constante publique, donc la signature parfaite pour un détecteur ("le
//     premier word-joiner suivi de caractères invisibles"). Le décodeur
//     ramasse désormais les symboles de son alphabet où qu'ils soient.
//   - payload dispersé dans la couverture au lieu d'un bloc collé à la fin.
//     v2 produisait une traînée de plusieurs centaines de caractères
//     invisibles d'un seul tenant : c'est ce que cherchent les expressions
//     régulières de détection.
//   - padding par paliers en option, pour que la longueur du message ne suive
//     plus la longueur du secret.
//   - plus d'en-tête de densité (v4). v3 le plaçait en premier symbole du
//     payload : c'était une constante, donc le premier caractère invisible de
//     tout message valait ZW[1] en 3 bits et ZW[0] en 2 bits — mesuré 400 fois
//     sur 400. Le marqueur avait changé de place, pas disparu. La densité se
//     déduit maintenant des symboles eux-mêmes.
//   - le message commence toujours par du texte visible (v4). En v3 la
//     dispersion pouvait poser des symboles avant le premier caractère de la
//     couverture, et le faisait dans 90 % des cas (mesuré) : un message Discord
//     ordinaire ne commence jamais par un caractère invisible.
//
// À dire clairement : rien de tout cela ne rend le canal indétectable. Un
// scanner qui COMPTE les caractères invisibles d'un message les trouvera
// toujours. Ce qui change, c'est qu'il faut le faire exprès : les heuristiques
// génériques (traînée de caractères de formatage, marqueur connu) ne suffisent
// plus.

import { pickCover } from "./covers.mjs";
import { randomInts } from "./random.mjs";

const ENC = new TextEncoder();
const DEC = new TextDecoder();

const DOMAIN = "papotage-v4";  // sépare les versions de protocole ET les contextes
const ITER = 600_000;          // PBKDF2 aligné OWASP ; coût amorti par le cache de clé
const NONCE_LEN = 12;          // = taille d'IV native de GCM, aucun remplissage
const TAG_BITS = 128;          // tag complet : pas de troncature, pas de limite d'invocations
const PAD_BLOCK = 16;          // quantum de padding par défaut
const FLAG_ZIPPED = 0x01;

// Paliers du mode « longueur masquée ». Coûteux en place, mais la taille du
// message ne dit alors plus que « quelque part entre deux paliers ».
const BUCKETS = [64, 128, 256, 512, 1024, 1536, 2048];
export const PADDING = { BLOCK: "bloc", BUCKET: "palier" };

// --- Compression (deflate-raw) ----------------------------------------------
// Chaque octet économisé = 1 à 4 caractères invisibles en moins. Format "raw"
// (sans en-tête zlib) pour ne rien gaspiller. Appliquée seulement si elle réduit
// vraiment la taille ; le drapeau voyage dans l'en-tête chiffré.
const HAS_COMPRESSION = typeof CompressionStream === "function"
    && typeof DecompressionStream === "function";

// Mesuré : deflate-raw ne devient gagnant qu'à partir d'une trentaine d'octets
// (16 octets en donnent 18, 32 en donnent 31). En dessous, c'est du calcul pur
// perdu — le résultat serait de toute façon écarté.
const MIN_DEFLATE = 32;

async function pipeThrough(stream, bytes) {
    const writer = stream.writable.getWriter();
    writer.write(bytes);
    writer.close();
    const reader = stream.readable.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        total += value.length;
    }
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { out.set(c, off); off += c.length; }
    return out;
}
const deflate = bytes => pipeThrough(new CompressionStream("deflate-raw"), bytes);
const inflate = bytes => pipeThrough(new DecompressionStream("deflate-raw"), bytes);

// --- Padding ISO/IEC 7816-4 -------------------------------------------------
// Un octet 0x80 puis des 0x00 jusqu'à la cible. Toujours au moins un octet
// ajouté, donc le dépaddage est non ambigu quelle que soit la cible.
function targetLength(n, mode) {
    if (mode === PADDING.BUCKET) {
        for (const b of BUCKETS) if (n < b) return b;
        return Math.ceil((n + 1) / 512) * 512;
    }
    return (Math.floor(n / PAD_BLOCK) + 1) * PAD_BLOCK;
}

function pad(bytes, mode) {
    const out = new Uint8Array(targetLength(bytes.length, mode));
    out.set(bytes, 0);
    out[bytes.length] = 0x80;
    return out;
}

function unpad(bytes) {
    for (let i = bytes.length - 1; i >= 0; i--) {
        if (bytes[i] === 0x00) continue;
        if (bytes[i] === 0x80) return bytes.subarray(0, i);
        break;
    }
    throw new Error("padding invalide"); // fail-closed : l'appelant renverra null
}

// --- Dérivation de clé (PBKDF2 -> AES-GCM 256) ------------------------------
// Le sel dépend du `context` (en pratique : l'identifiant du salon). Deux effets :
//   - pas de sel constant partagé par tous les utilisateurs du plugin, donc pas
//     de précalculation unique qui casserait tout le monde d'un coup ;
//   - un même mot de passe donne une clé différente par conversation, donc la
//     compromission d'un salon ne déchiffre pas les autres.
// PBKDF2 600k coûte ~300 ms : on met la clé en cache (sel déterministe pour un
// contexte donné), sinon déchiffrer un salon dériverait la clé à chaque message.
// Borné : une dérivation coûte ~104 ms de CPU (mesuré) et retient une clé en
// mémoire. Sans limite, parcourir cent salons en dérivait cent et les gardait
// toutes jusqu'au rechargement de Discord.
const KEY_CACHE_MAX = 16;
const keyCache = new Map(); // `${context}\0${passphrase}` -> Promise<CryptoKey>

async function saltFor(context) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", ENC.encode(`${DOMAIN}|${context}`)));
}

function deriveKey(passphrase, context = "") {
    const cacheKey = `${context}\u0000${passphrase}`;
    const cached = keyCache.get(cacheKey);
    if (cached) {
        keyCache.delete(cacheKey); // réinsertion = remise en tête (Map = ordre d'insertion)
        keyCache.set(cacheKey, cached);
        return cached;
    }
    const key = (async () => {
        const base = await crypto.subtle.importKey(
            "raw", ENC.encode(passphrase), "PBKDF2", false, ["deriveKey"]
        );
        return crypto.subtle.deriveKey(
            { name: "PBKDF2", salt: await saltFor(context), iterations: ITER, hash: "SHA-256" },
            base,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    })();
    key.catch(() => keyCache.delete(cacheKey)); // ne pas garder un échec en cache
    if (keyCache.size >= KEY_CACHE_MAX) keyCache.delete(keyCache.keys().next().value);
    keyCache.set(cacheKey, key);
    return key;
}

// Pré-dérive la clé pour que le 1er déchiffrement du salon soit instantané.
export function warmKey(passphrase, context = "") {
    if (passphrase) void deriveKey(passphrase, context);
}

// Oublie les clés dérivées (changement de mot de passe, verrouillage).
export function forgetKeys() {
    keyCache.clear();
}

// --- Chiffrement : texte -> octets (nonce || ciphertext+tag) ----------------
async function encryptBytes(text, passphrase, context = "", padding = PADDING.BLOCK) {
    const key = await deriveKey(passphrase, context);
    const raw = ENC.encode(text);

    let body = raw, flags = 0;
    if (HAS_COMPRESSION && raw.length >= MIN_DEFLATE) {
        const packed = await deflate(raw);
        if (packed.length < raw.length) { body = packed; flags |= FLAG_ZIPPED; }
    }

    const inner = new Uint8Array(1 + body.length);
    inner[0] = flags;                 // en-tête chiffré : aucun oracle en clair
    inner.set(body, 1);

    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
    const ct = new Uint8Array(await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, tagLength: TAG_BITS }, key, pad(inner, padding)
    ));

    const out = new Uint8Array(nonce.length + ct.length);
    out.set(nonce, 0);
    out.set(ct, nonce.length);
    return out;
}

// Lève si le tag est invalide (mauvaise clé, mauvais contexte, message étranger).
async function decryptBytes(bytes, passphrase, context = "") {
    if (bytes.length <= NONCE_LEN) throw new Error("trame trop courte");
    const key = await deriveKey(passphrase, context);
    const padded = new Uint8Array(await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: bytes.subarray(0, NONCE_LEN), tagLength: TAG_BITS },
        key,
        bytes.subarray(NONCE_LEN)
    ));
    const inner = unpad(padded);
    if (inner.length < 1) throw new Error("trame vide");
    const body = inner.subarray(1);
    if ((inner[0] & FLAG_ZIPPED) === 0) return DEC.decode(body);
    return DEC.decode(await inflate(body));
}

// Nombre d'octets envoyés pour un secret de `n` octets utiles (en-tête + padding).
export function wireSize(n, padding = PADDING.BLOCK) {
    return NONCE_LEN + TAG_BITS / 8 + targetLength(n + 1, padding);
}

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
// `allowLeading = false` interdit la position de tête, pour les symboles qui
// doivent modifier un caractère de base (sélecteurs de variation).
function scatter(cover, symbols, { allowLeading = true, fromGrapheme = 0 } = {}) {
    const all = graphemes(cover);
    const head = all.slice(0, fromGrapheme).join(""); // zone laissée intacte
    const gs = all.slice(fromGrapheme);
    const leading = allowLeading || gs.length === 0;
    const slots = Math.max(1, gs.length + (leading ? 1 : 0));

    // Composition aléatoire uniforme de symbols.length en `slots` parts.
    const cuts = randomInts(slots - 1, symbols.length + 1);
    cuts.sort((a, b) => a - b);
    const parts = [];
    let prev = 0;
    for (const c of cuts) { parts.push(symbols.slice(prev, c).join("")); prev = c; }
    parts.push(symbols.slice(prev).join(""));

    let out = head, i = 0;
    if (leading) out += parts[i++];
    for (const g of gs) {
        out += g;
        if (i < parts.length) out += parts[i++];
    }
    return out;
}

// ===========================================================================
// Mode invisible (zero-width) — le mode par défaut.
// ===========================================================================
// Alphabet zero-width extensible. Plus il y a de symboles, moins on envoie de
// caractères : 4 symboles = 2 bits/car, 8 symboles = 3 bits/car (-33 %).
// - index 0-3 : sûrs, préservés par Discord (ZWSP, ZWNJ, ZWJ, word-joiner).
// - index 4-7 : opérateurs invisibles (même famille Cf que le word-joiner), très
//   probablement préservés -> activés par la densité 3 bits.
// Le PREMIER symbole rencontré code la densité (0 => 2 bits, 1 => 3 bits) : le
// récepteur s'adapte seul, rien à régler de son côté.
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
// sélecteur de variation. Les sélecteurs de « ❤️ » ou « 🏳️‍🌈 » se retrouvent ainsi
// tous AVANT le MAGIC, donc ignorés par le décodeur — la couverture garde son
// rendu exact au lieu d'être amputée.
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

function coverFor(cover, pool) {
    return pickCover(cover, { pool });
}

// `bits` = 2 (sûr, 4 symboles) ou 3 (dense, 8 symboles). Le flux d'octets est
// ré-empaqueté en groupes de `bits` bits (pas d'alignement octet requis).
export async function encodeHidden(text, passphrase, { cover, bits = 3, context = "", padding, pool } = {}) {
    if (bits !== 2 && bits !== 3) bits = 3;
    const bytes = await encryptBytes(text, passphrase, context, padding);
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
    return scatter(stripHidden(coverFor(cover, pool)), syms, { allowLeading: false });
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
    const syms = [];
    let max = 0;
    for (const ch of message) {
        const v = ZW_VAL.get(ch);
        if (v !== undefined) {
            syms.push(v);
            if (v > max) max = v;
        }
    }
    if (syms.length < 8) return null;
    for (const bits of max >= 4 ? [3] : [2, 3]) {
        const bytes = unpackBits(syms, bits);
        if (!bytes) continue;
        try {
            return await decryptBytes(bytes, passphrase, context);
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
const MAGIC = 0xc7;        // 1er octet de la trame : repère le début du payload
const ATTEMPT_CAP = 32;    // borne le travail sur une entrée hostile

export async function encodeCompact(text, passphrase, { cover, context = "", padding, pool } = {}) {
    const body = await encryptBytes(text, passphrase, context, padding);
    const syms = [String.fromCodePoint(byteToVS(MAGIC))];
    for (const b of body) syms.push(String.fromCodePoint(byteToVS(b)));
    const base = coverFor(cover, pool) || "ok";
    return scatter(base, syms, { allowLeading: false, fromGrapheme: firstCompactSlot(base) });
}

// Renvoie le texte clair, ou null. On collecte tous les sélecteurs de variation
// dans l'ordre puis on se cale sur le MAGIC.
export async function decodeCompact(message, passphrase, { context = "" } = {}) {
    const bytes = [];
    for (const ch of message) {
        const b = vsToByte(ch.codePointAt(0));
        if (b !== null) bytes.push(b);
    }
    let tries = 0;
    for (let s = bytes.indexOf(MAGIC); s >= 0; s = bytes.indexOf(MAGIC, s + 1)) {
        if (++tries > ATTEMPT_CAP) break;
        try {
            return await decryptBytes(new Uint8Array(bytes.slice(s + 1)), passphrase, context);
        } catch { /* faux MAGIC : essayer l'occurrence suivante */ }
    }
    return null;
}

// ===========================================================================
// Mode emoji : les emojis VISIBLES portent le secret. 16 emojis = les 16
// valeurs hexa -> 1 octet = 2 emojis. Le message ressemble à un délire d'emojis
// mais c'est le secret chiffré. Beaucoup moins discret que les modes invisibles
// (une longue traînée d'emojis se voit) : réservé aux messages courts.
// ===========================================================================
export async function encodeEmoji(text, passphrase, { cover, context = "", padding } = {}) {
    const body = await encryptBytes(text, passphrase, context, padding);
    let seq = EMOJI[MAGIC >> 4] + EMOJI[MAGIC & 0x0f];
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
        for (let s = bytes.indexOf(MAGIC); s >= 0; s = bytes.indexOf(MAGIC, s + 1)) {
            if (++tries > ATTEMPT_CAP) return null;
            try {
                return await decryptBytes(new Uint8Array(bytes.slice(s + 1)), passphrase, context);
            } catch { /* MAGIC suivant / autre alignement */ }
        }
    }
    return null;
}

// ===========================================================================
// Saisie
// ===========================================================================
// Sépare une saisie "phrase visible | message secret".
// - séparateur présent -> couverture écrite par l'humain (conversation cohérente)
// - absent -> tout est secret, couverture auto
// On coupe au PREMIER séparateur seulement (le secret peut en contenir).
export function parseInput(raw, separator = " | ") {
    const at = separator ? raw.indexOf(separator) : -1;
    if (at < 0) return { cover: null, secret: raw };
    const cover = raw.slice(0, at).trim();
    const secret = raw.slice(at + separator.length);
    // Un des deux côtés vide (y compris seulement des espaces) => la saisie n'est
    // pas un vrai "couverture | secret" : on chiffre tout, plutôt que de publier
    // la moitié gauche en clair en croyant que c'est une couverture voulue.
    if (!cover || !secret.trim()) return { cover: null, secret: raw };
    return { cover, secret };
}
