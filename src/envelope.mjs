// Enveloppe cryptographique de Papotage — la partie qu'il faut relire seule.
//
// Ce module ne sait rien d'Unicode, de caractères invisibles ni de Discord : il
// transforme un texte en octets scellés, et l'inverse. Il est séparé du codec
// pour cette raison précise — c'est le code dont une erreur est irrattrapable,
// et il s'audite sans lire le reste du projet.
//
//   clair ──▶ [flags(1)] ──▶ deflate? ──▶ padding ──▶ AES-GCM ──▶ octets
//                                                                   │
//                          ┌────────────────────────────────────────┘
//                          ▼
//   octets = nonce(12 o) || ciphertext || tag(16 o)
//
// Nonce de 12 octets aléatoires, tag GCM complet de 128 bits, sel PBKDF2 dérivé
// du salon, drapeau de compression placé DANS le clair chiffré pour ne pas
// fuiter la compressibilité, remplissage par blocs avec jitter aléatoire.
// Le raisonnement derrière chaque choix est dans SECURITY.md.

import { randomInts } from "./random.mjs";

const ENC = new TextEncoder();
const DEC = new TextDecoder();

const DOMAIN = "papotage-v4";  // sépare les versions de protocole ET les contextes
const ITER = 600_000;          // PBKDF2 aligné OWASP ; coût amorti par le cache de clé
const NONCE_LEN = 12;          // = taille d'IV native de GCM, aucun remplissage
const TAG_BITS = 128;          // tag complet : pas de troncature, pas de limite d'invocations
export const PAD_BLOCK = 16;   // quantum de padding par défaut
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

// Blocs de remplissage supplémentaires tirés au hasard. Sans eux, un secret
// donné produit toujours exactement la même taille de message : deux envois du
// même texte se reconnaissent à la longueur, et la longueur envoyée détermine
// celle du clair à 16 octets près. Le mode paliers, lui, brouille déjà bien
// plus largement — y ajouter du bruit ne ferait que casser ses paliers.
const JITTER_BLOCKS = 3;

function pad(bytes, mode) {
    const jitter = mode === PADDING.BUCKET ? 0 : randomInts(1, JITTER_BLOCKS)[0] * PAD_BLOCK;
    const out = new Uint8Array(targetLength(bytes.length, mode) + jitter);
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
// Scelle un texte : renvoie nonce || ciphertext || tag.
export async function seal(text, passphrase, context = "", padding = PADDING.BLOCK) {
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
export async function unseal(bytes, passphrase, context = "") {
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

// Taille de l'en-tête d'une trame scellée : le codec en a besoin pour calculer
// un décalage, sans rien savoir de ce qu'il y a dedans.
export const FRAME_HEAD = NONCE_LEN + TAG_BITS / 8;

// La trame fait nonce(12) + ciphertext + tag(16), et GCM ne change pas la
// taille : le ciphertext vaut exactement le clair rembourré, donc un multiple de
// PAD_BLOCK. Toute longueur qui ne respecte pas ça ne peut pas être une trame
// Papotage — on l'écarte sans lancer le moindre déchiffrement.
export function plausibleFrame(len) {
    return len >= FRAME_HEAD + PAD_BLOCK && (len - FRAME_HEAD) % PAD_BLOCK === 0;
}

// Nombre MINIMAL d'octets envoyés pour un secret de `n` octets utiles. La taille
// réelle y ajoute 0 à 2 blocs de remplissage tirés au hasard (mode blocs).
export function wireSize(n, padding = PADDING.BLOCK) {
    return FRAME_HEAD + targetLength(n + 1, padding);
}

// Nombre maximal, jitter compris.
export function wireSizeMax(n, padding = PADDING.BLOCK) {
    return wireSize(n, padding) + (padding === PADDING.BUCKET ? 0 : (JITTER_BLOCKS - 1) * PAD_BLOCK);
}
