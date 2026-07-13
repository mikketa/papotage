// Papotage — chiffre un texte puis l'encode en phrases banales (stéganographie).
// Fonctionne dans Node (>=20) et dans le navigateur : utilise globalThis.crypto.
import { LISTS, GLUE } from "./wordlist.mjs";

const ENC = new TextEncoder();
const DEC = new TextDecoder();
const SALT = ENC.encode("papotage-v1-salt");
const ITER = 600_000;     // PBKDF2 (aligné OWASP) ; coût amorti par le cache de clé
const NONCE_LEN = 5;      // octets transmis ; complétés à 12 pour l'IV GCM
const TAG_BITS = 32;      // tag GCM tronqué (32 bits = suffisant en casual, valeur valide WebCrypto)
// Budget d'en-tête : nonce 5 o + tag 4 o = 9 o (au lieu de 12), et le nonce passe
// de 31 à 39 bits effectifs -> seuil de collision ~6 570 -> ~105 000 messages.

function ivFromNonce(nonce) {
    const iv = new Uint8Array(12);
    iv.set(nonce, 0);     // octets restants à zéro (fixes)
    return iv;
}
const BITS_PER_WORD = 5;  // chaque liste = 32 mots = 5 bits

// --- Compression (deflate-raw) ----------------------------------------------
// Réduit la taille du payload : chaque octet économisé = 4 caractères invisibles
// en moins dans Discord. Format "raw" (sans en-tête zlib) pour ne rien gaspiller.
// La compression n'est appliquée que si elle réduit vraiment la taille ; le
// drapeau voyage dans le bit de poids fort du nonce -> aucun octet d'overhead.
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

// --- Dérivation de clé (PBKDF2 -> AES-GCM 256) ------------------------------
// PBKDF2 200k itérations coûte ~50-100 ms : on met la clé en cache par mot de
// passe (le sel est fixe, donc la clé est déterministe). Déchiffrer un salon
// entier ne dérive alors la clé qu'une seule fois au lieu d'une fois par message.
const keyCache = new Map(); // passphrase -> Promise<CryptoKey>

function deriveKey(passphrase) {
    let key = keyCache.get(passphrase);
    if (key) return key;
    key = (async () => {
        const base = await crypto.subtle.importKey(
            "raw", ENC.encode(passphrase), "PBKDF2", false, ["deriveKey"]
        );
        return crypto.subtle.deriveKey(
            { name: "PBKDF2", salt: SALT, iterations: ITER, hash: "SHA-256" },
            base,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    })();
    key.catch(() => keyCache.delete(passphrase)); // ne pas garder un échec en cache
    keyCache.set(passphrase, key);
    return key;
}

// Pré-dérive la clé (PBKDF2 ~50-100 ms) pour que le 1er déchiffrement soit instantané.
export function warmKey(passphrase) {
    if (passphrase) void deriveKey(passphrase);
}

// --- Chiffrement : texte -> octets (iv || ciphertext+tag) -------------------
async function encryptBytes(text, passphrase) {
    const key = await deriveKey(passphrase);
    const raw = ENC.encode(text);
    const packed = await deflate(raw);
    const zipped = packed.length < raw.length; // ne compresse que si ça aide vraiment
    const plain = zipped ? packed : raw;

    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
    nonce[0] = (nonce[0] & 0x7f) | (zipped ? 0x80 : 0); // bit de poids fort = drapeau compression
    const ct = new Uint8Array(await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: ivFromNonce(nonce), tagLength: TAG_BITS },
        key,
        plain
    ));
    const out = new Uint8Array(nonce.length + ct.length);
    out.set(nonce, 0);
    out.set(ct, nonce.length);
    return out;
}

async function decryptBytes(bytes, passphrase) {
    const key = await deriveKey(passphrase);
    const nonce = bytes.slice(0, NONCE_LEN);
    const ct = bytes.slice(NONCE_LEN);
    const zipped = (nonce[0] & 0x80) !== 0; // drapeau lu dans le nonce (déjà authentifié par le tag)
    const pt = new Uint8Array(await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ivFromNonce(nonce), tagLength: TAG_BITS }, key, ct
    ));
    if (!zipped) return DEC.decode(pt);
    return DEC.decode(await inflate(pt)); // si inflate lève, l'appelant renvoie null (fail-closed)
}

// --- Octets <-> phrases -----------------------------------------------------
function bytesToWords(payload) {
    // en-tête 2 octets = longueur, puis le payload
    const all = new Uint8Array(payload.length + 2);
    all[0] = (payload.length >> 8) & 0xff;
    all[1] = payload.length & 0xff;
    all.set(payload, 2);

    const bits = [];
    for (const byte of all)
        for (let b = 7; b >= 0; b--) bits.push((byte >> b) & 1);
    while (bits.length % BITS_PER_WORD !== 0) bits.push(0); // padding

    const words = [];
    for (let i = 0; i < bits.length; i += BITS_PER_WORD) {
        let val = 0;
        for (let k = 0; k < BITS_PER_WORD; k++) val = (val << 1) | bits[i + k];
        const slot = words.length % LISTS.length;
        words.push(LISTS[slot][val]);
    }
    return words;
}

function wordsToSentences(words) {
    const tokens = [];
    words.forEach((w, idx) => {
        const slot = idx % 4;
        if (slot === 0) tokens.push("Le");
        tokens.push(w);
        if (slot === 1) tokens.push("son");
        if (slot === 3) tokens.push(".");
    });
    if (words.length % 4 !== 0) tokens.push(".");
    return tokens.join(" ").replace(/ \./g, ".");
}

function sentencesToWords(text) {
    const raw = text.toLowerCase().replace(/\./g, " ").split(/\s+/).filter(Boolean);
    const words = raw.filter(t => !GLUE.has(t));
    const bits = [];
    for (let i = 0; i < words.length; i++) {
        const slot = i % LISTS.length;
        const val = LISTS[slot].indexOf(words[i]);
        if (val < 0) return null; // un mot hors-liste => ce n'est pas du Papotage
        for (let k = BITS_PER_WORD - 1; k >= 0; k--) bits.push((val >> k) & 1);
    }
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        let v = 0;
        for (let k = 0; k < 8; k++) v = (v << 1) | bits[i + k];
        bytes.push(v);
    }
    if (bytes.length < 2) return null;
    const len = (bytes[0] << 8) | bytes[1];
    if (bytes.length < 2 + len) return null;
    return new Uint8Array(bytes.slice(2, 2 + len));
}

// --- API publique -----------------------------------------------------------
export async function encode(text, passphrase) {
    return wordsToSentences(bytesToWords(await encryptBytes(text, passphrase)));
}

// Renvoie le texte clair, ou null si ce n'est pas un message Papotage / mauvaise clé.
export async function decode(sentences, passphrase) {
    const payload = sentencesToWords(sentences);
    if (!payload) return null;
    try {
        return await decryptBytes(payload, passphrase);
    } catch {
        return null; // tag GCM invalide = pas notre message ou clé fausse
    }
}

// ===========================================================================
// Mode caché (zero-width) : court + invisible, recommandé pour Discord.
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
const MARK = "⁠"; // = ZW_ALL[3]

const COVERS = ["ok", "mdr", "👍", "ah ouais", "mouais", "jsp", "wsh", "nan mais", "🤙", "hmm"];

// Phrases naturelles pour le mode dense. Volontairement "réactives" (réponses
// / backchannel) : ça passe crédiblement après n'importe quel message, donc un
// fil de conversation en couvertures auto reste plausible. Avec quelques emojis.
const NATURAL_COVERS = [
    "ok ça marche 👍",
    "ah ouais carrément 😂",
    "mdr t'es sérieux",
    "ouais je te suis là-dessus",
    "franchement pas faux 🤔",
    "haha ok je note",
    "nickel on fait comme ça 🙌",
    "attends je check et je reviens",
    "ptdr ouais grave",
    "hmm ok pourquoi pas",
    "genre ouais je vois 😅",
    "bah écoute ça me va",
    "ah d'accord je comprends mieux",
    "oui oui t'inquiète",
    "mouais à voir 🤷"
];

function randIndex(n) {
    return Math.floor(crypto.getRandomValues(new Uint32Array(1))[0] / 2 ** 32 * n);
}

function pickCover(seed) {
    // seed déterministe optionnel (tests) ; sinon aléatoire
    const i = seed != null ? seed % COVERS.length : randIndex(COVERS.length);
    return COVERS[i];
}

// Couverture pour le mode dense : phrase perso fournie par l'appelant, sinon
// une phrase naturelle tirée au hasard.
function pickNaturalCover(custom) {
    if (custom && custom.trim()) return custom.trim();
    return NATURAL_COVERS[randIndex(NATURAL_COVERS.length)];
}

// `bits` = 2 (sûr, 4 symboles) ou 3 (dense, 8 symboles). Le flux d'octets est
// ré-empaqueté en groupes de `bits` bits (pas d'alignement octet requis).
export async function encodeHidden(text, passphrase, cover, bits = 2) {
    if (bits !== 2 && bits !== 3) bits = 2;
    const bytes = await encryptBytes(text, passphrase);
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
    return pickNaturalCover(cover).split(MARK).join("") + MARK + zw;
}

// Renvoie le texte clair, ou null si pas de payload caché / mauvaise clé.
// La densité est lue dans l'en-tête : le récepteur s'adapte tout seul.
export async function decodeHidden(message, passphrase) {
    const at = message.indexOf(MARK);
    if (at < 0) return null;
    const syms = [...message.slice(at + 1)];
    const header = syms.length ? ZW_VAL.get(syms[0]) : undefined;
    if (header === undefined || header > 1) return null; // densité inconnue
    const bits = header + 2;
    const alpha = 1 << bits;
    let acc = 0, accBits = 0;
    const bytes = [];
    for (let i = 1; i < syms.length; i++) {
        const v = ZW_VAL.get(syms[i]);
        if (v === undefined || v >= alpha) return null; // parasite / mauvaise densité
        acc = (acc << bits) | v;
        accBits += bits;
        if (accBits >= 8) {
            accBits -= 8;
            bytes.push((acc >> accBits) & 0xff);
        }
    }
    if (bytes.length === 0) return null; // les bits restants (< 8) sont du padding
    try {
        return await decryptBytes(new Uint8Array(bytes), passphrase);
    } catch {
        return null;
    }
}

// ===========================================================================
// Mode dense (sélecteurs de variation) : 1 octet = 1 caractère invisible.
// ~8x plus court que le mode zero-width. Découpe en plusieurs messages si
// ça dépasse la limite Discord, le destinataire les recolle.
// ===========================================================================
const MAGIC = 0xc7;             // 1er octet de chaque trame : reconnaît un morceau Papotage
const HEADER = 5;               // MAGIC(1) + id(2) + index(1) + total(1)
const MAX_CHARS = 1900;         // marge sous la limite Discord de 2000
const MAX_PARTS = 255;

// octet <-> sélecteur de variation invisible (256 valeurs disponibles)
function byteToVS(b) { return b < 16 ? 0xfe00 + b : 0xe0100 + (b - 16); }
function vsToByte(cp) {
    if (cp >= 0xfe00 && cp <= 0xfe0f) return cp - 0xfe00;
    if (cp >= 0xe0100 && cp <= 0xe01ef) return cp - 0xe0100 + 16;
    return null;
}

// Accroche les octets (sélecteurs de variation) directement APRÈS la dernière
// lettre visible de la couverture : ils "modifient" cette lettre -> rendu
// invisible garanti, pas de carré vide, pas de débordement à la sélection.
function frameToString(cover, frame) {
    let s = cover;
    for (const b of frame) s += String.fromCodePoint(byteToVS(b));
    return s;
}

// Extrait la trame d'octets cachée dans un message, ou null.
// On collecte tous les sélecteurs de variation dans l'ordre puis on se cale sur
// le MAGIC : ça tolère un emoji de la couverture qui porterait un VS légitime.
function stringToFrame(message) {
    const bytes = [];
    for (const ch of message) {
        const b = vsToByte(ch.codePointAt(0));
        if (b !== null) bytes.push(b);
    }
    const start = bytes.indexOf(MAGIC);
    if (start < 0) return null;
    const frame = bytes.slice(start);
    return frame.length >= HEADER ? new Uint8Array(frame) : null;
}

// Chiffre puis renvoie 1..N messages prêts à envoyer (chacun sous MAX_CHARS).
// `cover` (optionnel) : phrase de couverture perso ; sinon phrase naturelle auto.
export async function encodeMulti(text, passphrase, maxChars = MAX_CHARS, cover) {
    const full = await encryptBytes(text, passphrase);
    const id = crypto.getRandomValues(new Uint16Array(1))[0];
    // chaque octet coûte jusqu'à 2 unités UTF-16 ; on réserve la place de la couverture
    const perPart = Math.floor((maxChars - 80) / 2) - HEADER;
    const total = Math.max(1, Math.ceil(full.length / perPart));
    if (total > MAX_PARTS) throw new Error("message trop long même découpé");

    const parts = [];
    for (let i = 0; i < total; i++) {
        const chunk = full.slice(i * perPart, (i + 1) * perPart);
        const frame = new Uint8Array(HEADER + chunk.length);
        frame[0] = MAGIC;
        frame[1] = (id >> 8) & 0xff;
        frame[2] = id & 0xff;
        frame[3] = i;
        frame[4] = total;
        frame.set(chunk, HEADER);
        // couverture différente par morceau -> ça ressemble à plusieurs vrais messages
        parts.push(frameToString(pickNaturalCover(cover), frame));
    }
    return parts;
}

// Lit un morceau reçu : { id, index, total, chunk } ou null si pas Papotage.
export function decodePart(message) {
    const frame = stringToFrame(message);
    if (!frame || frame[0] !== MAGIC) return null;
    const total = frame[4];
    if (total === 0 || frame[3] >= total) return null;
    return {
        id: (frame[1] << 8) | frame[2],
        index: frame[3],
        total,
        chunk: frame.slice(HEADER)
    };
}

// Sépare une saisie "phrase visible | message secret".
// - séparateur présent -> couverture écrite par l'humain (conversation cohérente)
// - absent -> tout est secret, couverture auto
// On coupe au PREMIER séparateur seulement (le secret peut en contenir).
export function parseInput(raw, separator = " | ") {
    const at = raw.indexOf(separator);
    if (at < 0) return { cover: null, secret: raw };
    const cover = raw.slice(0, at).trim();
    const secret = raw.slice(at + separator.length);
    if (!cover || !secret) return { cover: null, secret: raw };
    return { cover, secret };
}

// Recolle des morceaux complets et déchiffre. `chunks` = tableau indexé par index.
export async function reassemble(chunks, passphrase) {
    const totalLen = chunks.reduce((n, c) => n + c.length, 0);
    const full = new Uint8Array(totalLen);
    let off = 0;
    for (const c of chunks) { full.set(c, off); off += c.length; }
    try {
        return await decryptBytes(full, passphrase);
    } catch {
        return null;
    }
}

// ===========================================================================
// Mode emoji-opcodes : les emojis VISIBLES portent le secret.
// 16 emojis = les 16 valeurs hexa -> 1 octet = 2 emojis. Le message ressemble
// à un délire d'emojis mais c'est le secret chiffré. Moins discret que le mode
// invisible (une longue traînée d'emojis se voit) : réservé aux messages courts.
// ===========================================================================
// Tous single-codepoint, sans sélecteur de variation ni modificateur de teinte.
const EMOJI = ["😀", "😂", "😅", "😍", "🤔", "😎", "😭", "😡", "👍", "🔥", "🎉", "💀", "👀", "🚀", "🍕", "💯"];
const EMOJI_INDEX = new Map(EMOJI.map((e, i) => [e, i]));

// Chiffre `text` et l'encode en une séquence d'emojis (préfixée d'une couverture
// texte optionnelle, qui ne doit pas contenir d'emoji du dictionnaire).
export async function encodeEmoji(text, passphrase, cover) {
    const body = await encryptBytes(text, passphrase);
    const frame = new Uint8Array(1 + body.length);
    frame[0] = MAGIC;
    frame.set(body, 1);
    let seq = "";
    for (const b of frame) seq += EMOJI[b >> 4] + EMOJI[b & 0x0f];
    const prefix = cover && cover.trim() ? cover.trim() + " " : "";
    return prefix + seq;
}

// Renvoie le texte clair, ou null si pas de séquence Papotage / mauvaise clé.
export async function decodeEmoji(message, passphrase) {
    const nibbles = [];
    for (const ch of message) {
        const i = EMOJI_INDEX.get(ch);
        if (i !== undefined) nibbles.push(i);
    }
    // deux alignements possibles si un emoji parasite précède la séquence
    for (const off of [0, 1]) {
        const bytes = [];
        for (let i = off; i + 1 < nibbles.length; i += 2) bytes.push((nibbles[i] << 4) | nibbles[i + 1]);
        // Essayer CHAQUE occurrence de MAGIC : une couverture peut contenir un faux
        // MAGIC (0xC7 se rend 👀😡), il faut pouvoir sauter jusqu'au vrai.
        for (let start = bytes.indexOf(MAGIC); start >= 0; start = bytes.indexOf(MAGIC, start + 1)) {
            try {
                return await decryptBytes(new Uint8Array(bytes.slice(start + 1)), passphrase);
            } catch { /* MAGIC suivant / autre alignement */ }
        }
    }
    return null;
}
