// Enveloppe cryptographique de Papotage — la partie qu'il faut relire seule.
//
// Ce module ne sait rien d'Unicode, de caractères invisibles ni de Discord : il
// transforme un texte en octets scellés, et l'inverse. Il est séparé du codec
// pour cette raison précise — c'est le code dont une erreur est irrattrapable,
// et il s'audite sans lire le reste du projet.
//
//   clair ──▶ [flags(1)] ──▶ deflate? ──▶ padding ──▶ AES-GCM ──▶ octets
//   octets envoyés = nonce(12 o) || ciphertext || tag(16 o)
//
// Le raisonnement derrière chacune des valeurs ci-dessous est dans SECURITY.md,
// section « Choix cryptographiques » : ne pas y toucher sans l'avoir lue.

import { randomInt } from "./random.mjs";

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

// Blocs de remplissage supplémentaires tirés au hasard. Sans eux, un secret
// donné produit toujours exactement la même taille de message : deux envois du
// même texte se reconnaissent à la longueur. Le mode paliers, lui, brouille déjà
// bien plus largement — y ajouter du bruit ne ferait que casser ses paliers.
const JITTER_BLOCKS = 3;

function concat(parts, total) {
    const out = new Uint8Array(total);
    let at = 0;
    for (const p of parts) { out.set(p, at); at += p.length; }
    return out;
}

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

async function pipe(transform, bytes) {
    const writer = transform.writable.getWriter();
    writer.write(bytes);
    writer.close();
    const reader = transform.readable.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) return concat(chunks, total);
        chunks.push(value);
        total += value.length;
    }
}
const deflate = bytes => pipe(new CompressionStream("deflate-raw"), bytes);
const inflate = bytes => pipe(new DecompressionStream("deflate-raw"), bytes);

// --- Trame à chiffrer -------------------------------------------------------
// [flags(1)] || corps || padding ISO/IEC 7816-4 (un octet 0x80 puis des 0x00).
// Toujours au moins un octet ajouté, donc le dépaddage est non ambigu quelle que
// soit la cible. Construite d'un seul jet : une seule allocation, une seule
// copie du corps.
function targetLength(n, mode) {
    if (mode !== PADDING.BUCKET) return (Math.floor(n / PAD_BLOCK) + 1) * PAD_BLOCK;
    return BUCKETS.find(b => n < b) ?? Math.ceil((n + 1) / 512) * 512;
}

function frame(flags, body, mode) {
    const used = 1 + body.length;
    const jitter = mode === PADDING.BUCKET ? 0 : randomInt(JITTER_BLOCKS) * PAD_BLOCK;
    const out = new Uint8Array(targetLength(used, mode) + jitter);
    out[0] = flags; // en-tête DANS le clair chiffré : aucun oracle en clair
    out.set(body, 1);
    out[used] = 0x80;
    return out;
}

function unframe(padded) {
    for (let i = padded.length - 1; i >= 0; i--) {
        if (padded[i] === 0x00) continue;
        if (padded[i] === 0x80 && i >= 1) return padded.subarray(0, i);
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
//
// Une dérivation coûte ~104 ms de CPU (mesuré) : sans cache, déchiffrer un salon
// la refait à chaque message. Le cache est borné et évince le moins récemment
// utilisé — sans borne, parcourir cent salons retenait cent clés en mémoire
// jusqu'au rechargement de Discord.
const KEY_CACHE_MAX = 16;
const keyCache = new Map(); // `${context}\0${passphrase}` -> Promise<CryptoKey>

function deriveKey(passphrase, context = "") {
    const id = `${context}\u0000${passphrase}`; // séparateur impossible dans un mot de passe
    const cached = keyCache.get(id);
    if (cached) {
        keyCache.delete(id); // réinsertion = remise en tête (Map = ordre d'insertion)
        keyCache.set(id, cached);
        return cached;
    }
    const key = (async () => {
        const salt = await crypto.subtle.digest("SHA-256", ENC.encode(`${DOMAIN}|${context}`));
        const base = await crypto.subtle.importKey("raw", ENC.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
        return crypto.subtle.deriveKey(
            { name: "PBKDF2", salt: new Uint8Array(salt), iterations: ITER, hash: "SHA-256" },
            base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    })();
    key.catch(() => keyCache.delete(id)); // ne pas garder un échec en cache
    if (keyCache.size >= KEY_CACHE_MAX) keyCache.delete(keyCache.keys().next().value);
    keyCache.set(id, key);
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

// --- Sceller / ouvrir -------------------------------------------------------
// Renvoie nonce || ciphertext || tag.
export async function seal(text, passphrase, context = "", padding = PADDING.BLOCK) {
    const key = await deriveKey(passphrase, context);
    const raw = ENC.encode(text);

    let body = raw, flags = 0;
    if (HAS_COMPRESSION && raw.length >= MIN_DEFLATE) {
        const packed = await deflate(raw);
        if (packed.length < raw.length) { body = packed; flags |= FLAG_ZIPPED; }
    }

    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
    const ct = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, tagLength: TAG_BITS }, key, frame(flags, body, padding));
    return concat([nonce, new Uint8Array(ct)], NONCE_LEN + ct.byteLength);
}

// Lève si le tag est invalide (mauvaise clé, mauvais contexte, message étranger).
export async function unseal(bytes, passphrase, context = "") {
    if (bytes.length <= NONCE_LEN) throw new Error("trame trop courte");
    const key = await deriveKey(passphrase, context);
    const padded = new Uint8Array(await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: bytes.subarray(0, NONCE_LEN), tagLength: TAG_BITS },
        key, bytes.subarray(NONCE_LEN)));
    const inner = unframe(padded);
    const body = inner.subarray(1);
    return (inner[0] & FLAG_ZIPPED) === 0 ? DEC.decode(body) : DEC.decode(await inflate(body));
}

// --- Ce que le codec doit savoir d'une trame, sans en connaître le contenu ---
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
