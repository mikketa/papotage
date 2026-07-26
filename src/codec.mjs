// Papotage — chiffre un texte puis le cache dans un message d'apparence banale.
// Fonctionne dans Node (>=20) et dans le navigateur : utilise globalThis.crypto.
//
// ===========================================================================
// Format v2 (INCOMPATIBLE avec v1 : un message v1 se décode en null, et
// réciproquement — la séparation est assurée par le domaine de dérivation).
// ===========================================================================
//
//   clair ──▶ [flags(1)] ──▶ deflate? ──▶ padding 16 o ──▶ AES-GCM ──▶ octets
//                                                                       │
//                              ┌────────────────────────────────────────┘
//                              ▼
//   octets = nonce(12 o) || ciphertext || tag(16 o)
//
// Ce que v2 corrige par rapport à v1 :
//   - nonce 12 o aléatoires (v1 : 5 o dont 1 bit de drapeau = 39 bits). Le sel
//     PBKDF2 était constant, donc la clé était identique pour tous les
//     utilisateurs et pour toujours : l'espace de nonces était partagé
//     globalement. Une collision GCM n'expose pas seulement le XOR des clairs,
//     elle donne la clé d'authentification GHASH -> forge de messages.
//   - tag 128 bits (v1 : 32 bits tronqués -> forge à 2^-32 par essai, et les
//     tags courts accélèrent la récupération de GHASH).
//   - sel dérivé d'un contexte de conversation (v1 : constante publique, donc
//     une seule précalculation cassait tous les utilisateurs à la fois).
//   - drapeau de compression déplacé DANS le clair chiffré (v1 : en clair dans
//     le nonce -> oracle sur la compressibilité du message).
//   - padding à 16 octets : la longueur envoyée ne suit plus au caractère près
//     la longueur du secret.
//
// Coût total : 28 o d'en-tête au lieu de 9, plus 8 o de padding en moyenne.
// Sur un message de 200 caractères en mode invisible dense, ça fait +12 %.

import { pickCover } from "./covers.mjs";

const ENC = new TextEncoder();
const DEC = new TextDecoder();

const DOMAIN = "papotage-v2";  // sépare les versions de protocole ET les contextes
const ITER = 600_000;          // PBKDF2 aligné OWASP ; coût amorti par le cache de clé
const NONCE_LEN = 12;          // = taille d'IV native de GCM, aucun remplissage
const TAG_BITS = 128;          // tag complet : pas de troncature, pas de limite d'invocations
const PAD_BLOCK = 16;          // quantum de padding (masque la longueur exacte)
const FLAG_ZIPPED = 0x01;

// --- Compression (deflate-raw) ----------------------------------------------
// Chaque octet économisé = 2,7 à 4 caractères invisibles en moins. Format "raw"
// (sans en-tête zlib) pour ne rien gaspiller. Appliquée seulement si elle réduit
// vraiment la taille ; le drapeau voyage dans l'en-tête chiffré.
const HAS_COMPRESSION = typeof CompressionStream === "function"
    && typeof DecompressionStream === "function";

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
// Un octet 0x80 puis des 0x00 jusqu'au prochain multiple de PAD_BLOCK. Toujours
// au moins un octet ajouté, donc le dépaddage est non ambigu.
function pad(bytes) {
    const extra = PAD_BLOCK - (bytes.length % PAD_BLOCK);
    const out = new Uint8Array(bytes.length + extra);
    out.set(bytes, 0);
    out[bytes.length] = 0x80;
    return out;
}

function unpad(bytes) {
    for (let i = bytes.length - 1, seen = 0; i >= 0 && seen < PAD_BLOCK; i--, seen++) {
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
const keyCache = new Map(); // `${context}\0${passphrase}` -> Promise<CryptoKey>

async function saltFor(context) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", ENC.encode(`${DOMAIN}|${context}`)));
}

function deriveKey(passphrase, context = "") {
    const cacheKey = `${context}\u0000${passphrase}`;
    let key = keyCache.get(cacheKey);
    if (key) return key;
    key = (async () => {
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
async function encryptBytes(text, passphrase, context = "") {
    const key = await deriveKey(passphrase, context);
    const raw = ENC.encode(text);

    let body = raw, flags = 0;
    if (HAS_COMPRESSION) {
        const packed = await deflate(raw);
        if (packed.length < raw.length) { body = packed; flags |= FLAG_ZIPPED; }
    }

    const inner = new Uint8Array(1 + body.length);
    inner[0] = flags;                 // en-tête chiffré : aucun oracle en clair
    inner.set(body, 1);

    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
    const ct = new Uint8Array(await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, tagLength: TAG_BITS }, key, pad(inner)
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
export function wireSize(n) {
    return NONCE_LEN + TAG_BITS / 8 + (Math.floor((n + 1) / PAD_BLOCK) + 1) * PAD_BLOCK;
}

// ===========================================================================
// Mode invisible (zero-width) — le mode par défaut.
// Message envoyé = [couverture visible] + MARK + [payload invisible].
// ===========================================================================
// Alphabet zero-width extensible. Plus il y a de symboles, moins on envoie de
// caractères : 4 symboles = 2 bits/car, 8 symboles = 3 bits/car (-33 %).
// - index 0-3 : sûrs, préservés par Discord (ZWSP, ZWNJ, ZWJ, word-joiner).
// - index 4-7 : opérateurs invisibles (même famille Cf que le word-joiner), très
//   probablement préservés -> activés par la densité 3 bits.
// Le word-joiner (index 3) sert aussi de délimiteur MARK : il n'apparaît jamais
// dans une couverture, donc le PREMIER word-joiner marque le début du payload.
// Juste après le MARK, un caractère d'en-tête code la densité (0 => 2 bits,
// 1 => 3 bits) : le récepteur la détecte seul, rien à régler de son côté.
const ZW_ALL = ["​", "‌", "‍", "⁠", "⁡", "⁢", "⁣", "⁤"];
const ZW_VAL = new Map(ZW_ALL.map((c, i) => [c, i]));
export const MARK = "⁠"; // = ZW_ALL[3]

// `bits` = 2 (sûr, 4 symboles) ou 3 (dense, 8 symboles). Le flux d'octets est
// ré-empaqueté en groupes de `bits` bits (pas d'alignement octet requis).
export async function encodeHidden(text, passphrase, { cover, bits = 3, context = "" } = {}) {
    if (bits !== 2 && bits !== 3) bits = 3;
    const bytes = await encryptBytes(text, passphrase, context);
    const mask = (1 << bits) - 1;
    let zw = ZW_ALL[bits - 2]; // en-tête densité (0 => 2 bits, 1 => 3 bits)
    let acc = 0, accBits = 0;
    for (const byte of bytes) {
        acc = (acc << 8) | byte;
        accBits += 8;
        while (accBits >= bits) {
            accBits -= bits;
            zw += ZW_ALL[(acc >> accBits) & mask];
        }
    }
    if (accBits > 0) zw += ZW_ALL[(acc << (bits - accBits)) & mask]; // bits de fin (padding)
    // Retirer tout MARK déjà présent dans la couverture (ex. couverture copiée
    // depuis un ancien message Papotage) : sinon indexOf(MARK) tomberait dessus.
    return pickCover(cover).split(MARK).join("") + MARK + zw;
}

// Renvoie le texte clair, ou null si pas de payload / mauvaise clé / mauvais contexte.
// La densité est lue dans l'en-tête : le récepteur s'adapte tout seul.
export async function decodeHidden(message, passphrase, { context = "" } = {}) {
    const at = message.indexOf(MARK);
    if (at < 0) return null;
    // On ne garde que les symboles de l'alphabet : du texte ajouté après le
    // payload (message édité, signature de bot) ne casse plus le décodage.
    const syms = [];
    for (const ch of message.slice(at + 1)) {
        const v = ZW_VAL.get(ch);
        if (v !== undefined) syms.push(v);
    }
    if (syms.length < 2 || syms[0] > 1) return null; // densité inconnue
    const bits = syms[0] + 2;
    const alpha = 1 << bits;
    let acc = 0, accBits = 0;
    const bytes = [];
    for (let i = 1; i < syms.length; i++) {
        if (syms[i] >= alpha) return null; // symbole hors densité annoncée
        acc = (acc << bits) | syms[i];
        accBits += bits;
        if (accBits >= 8) {
            accBits -= 8;
            bytes.push((acc >> accBits) & 0xff);
        }
    }
    if (bytes.length === 0) return null; // les bits restants (< 8) sont du padding
    try {
        return await decryptBytes(new Uint8Array(bytes), passphrase, context);
    } catch {
        return null;
    }
}

// ===========================================================================
// Mode compact (sélecteurs de variation) : 1 octet = 1 caractère invisible,
// soit ~2,7x plus court que le mode zero-width dense. Les sélecteurs se collent
// à la dernière lettre visible de la couverture : rendu invisible garanti, pas
// de carré vide, pas de débordement à la sélection.
// Contrepartie : encodage moins universel que les zero-width, à réserver aux
// interlocuteurs qui ont la même version du plugin.
// ===========================================================================
const MAGIC = 0xc7;        // 1er octet de la trame : repère le début du payload
const ATTEMPT_CAP = 32;    // bornes le travail sur une entrée hostile

function byteToVS(b) { return b < 16 ? 0xfe00 + b : 0xe0100 + (b - 16); }
function vsToByte(cp) {
    if (cp >= 0xfe00 && cp <= 0xfe0f) return cp - 0xfe00;
    if (cp >= 0xe0100 && cp <= 0xe01ef) return cp - 0xe0100 + 16;
    return null;
}

export async function encodeCompact(text, passphrase, { cover, context = "" } = {}) {
    const body = await encryptBytes(text, passphrase, context);
    let out = pickCover(cover);
    out += String.fromCodePoint(byteToVS(MAGIC));
    for (const b of body) out += String.fromCodePoint(byteToVS(b));
    return out;
}

// Renvoie le texte clair, ou null. On collecte tous les sélecteurs de variation
// dans l'ordre puis on se cale sur le MAGIC : ça tolère un emoji de la couverture
// qui porterait un sélecteur légitime (❤️ = U+2764 U+FE0F).
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
// Tous single-codepoint, sans sélecteur de variation ni modificateur de teinte.
export const EMOJI = ["😀", "😂", "😅", "😍", "🤔", "😎", "😭", "😡", "👍", "🔥", "🎉", "💀", "👀", "🚀", "🍕", "💯"];
const EMOJI_INDEX = new Map(EMOJI.map((e, i) => [e, i]));

export async function encodeEmoji(text, passphrase, { cover, context = "" } = {}) {
    const body = await encryptBytes(text, passphrase, context);
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


