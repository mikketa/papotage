// Logique du plugin, isolée de Vencord.
//
// Tout ce qui décide *quoi* envoyer et *quoi* déchiffrer vit ici : aucune
// dépendance à Discord, donc testable en Node. `index.tsx` ne garde que le
// câblage (boutons, événements Flux, toasts).

import {
    EMOJI, MARK,
    decodeCompact, decodeEmoji, decodeHidden,
    encodeCompact, encodeEmoji, encodeHidden,
    parseInput
} from "./codec.mjs";

export const MODE = {
    HIDDEN: "hidden",     // zero-width 3 bits/car (défaut)
    HIDDEN_SAFE: "safe",  // zero-width 2 bits/car : 4 symboles seulement, le jeu
    //                       le plus universellement préservé. Plus long.
    COMPACT: "compact",   // sélecteurs de variation : 1 octet = 1 car, le plus court
    EMOJI: "emoji"        // emojis visibles : lisiblement bizarre, messages courts
};

export const DEFAULT_SEPARATOR = " | ";
export const LOCK_PREFIX = "🔓 ";
export const MAX_MESSAGE_CHARS = 2000; // limite Discord

// Un séparateur vide ou fait uniquement d'espaces découperait tous les messages
// normaux : on retombe sur la valeur par défaut dans ce cas.
export function resolveSeparator(sep) {
    return sep && sep.trim() ? sep : DEFAULT_SEPARATOR;
}

export class PapotageError extends Error {
    constructor(code, message) {
        super(message);
        this.name = "PapotageError";
        this.code = code;
    }
}

// ===========================================================================
// Envoi
// ===========================================================================
// Renvoie le message prêt à envoyer. Lève une PapotageError sur TOUT problème :
// l'appelant doit annuler l'envoi. C'est le point le plus important du plugin —
// un échec silencieux ici publie le message en clair.
export async function encodeOutgoing({
    raw,
    passphrase,
    mode = MODE.HIDDEN,
    defaultCover = "",
    separator = DEFAULT_SEPARATOR,
    context = "",
    maxChars = MAX_MESSAGE_CHARS
}) {
    if (!passphrase) {
        throw new PapotageError("no-passphrase",
            "Papotage : aucun mot de passe défini. Message NON envoyé (il serait parti en clair).");
    }
    if (!raw || !raw.trim()) {
        throw new PapotageError("empty", "Papotage : message vide.");
    }

    const { cover, secret } = parseInput(raw, resolveSeparator(separator));
    if (!secret.trim()) {
        throw new PapotageError("empty-secret",
            "Papotage : rien à chiffrer après le séparateur. Message NON envoyé.");
    }
    const chosenCover = cover ?? (defaultCover.trim() || undefined);

    let content;
    try {
        switch (mode) {
            case MODE.EMOJI:
                content = await encodeEmoji(secret, passphrase, { cover: chosenCover, context });
                break;
            case MODE.COMPACT:
                content = await encodeCompact(secret, passphrase, { cover: chosenCover, context });
                break;
            case MODE.HIDDEN_SAFE:
                content = await encodeHidden(secret, passphrase, { cover: chosenCover, bits: 2, context });
                break;
            default:
                content = await encodeHidden(secret, passphrase, { cover: chosenCover, bits: 3, context });
        }
    } catch (e) {
        throw new PapotageError("encode-failed",
            `Papotage : échec du chiffrement (${e?.message ?? e}). Message NON envoyé.`);
    }

    // Discord rejette silencieusement au-delà de 2000 : mieux vaut annuler avec
    // une explication que laisser le message disparaître sans rien dire.
    if (content.length > maxChars) {
        const over = content.length - maxChars;
        throw new PapotageError("too-long",
            `Papotage : message trop long de ${over} caractères une fois chiffré `
            + `(${content.length} / ${maxChars}). Coupe-le en deux`
            + (mode === MODE.HIDDEN ? " ou passe en mode compact." : "."));
    }
    return content;
}

// ===========================================================================
// Réception
// ===========================================================================
// Pré-filtre : quel décodeur tenter, ou null si le message n'a clairement rien
// à voir avec Papotage. Évite de lancer un déchiffrement sur chaque message du
// salon (le scan d'un historique en traite des centaines).

// Chaque filtre exige une *série* de symboles, jamais un symbole isolé. C'est
// ce qui distingue un payload d'un caractère exotique qui traîne dans un message
// ordinaire — et ça compte deux fois :
//   - à la réception, ça évite de lancer un déchiffrement sur chaque message ;
//   - à l'envoi, `isPapotageMessage` sert à ne pas re-chiffrer un message déjà
//     chiffré. Un faux positif là-dessus enverrait le message EN CLAIR.
// La plus petite trame possible fait 44 octets, soit 118 caractères invisibles
// en densité 3 bits : les seuils ci-dessous gardent une marge confortable.

// MARK suivi d'une vraie traînée de zero-width (et pas d'un U+2060 collé depuis
// une page web au milieu d'une phrase). Écrit en échappements : un caractère
// invisible littéral dans une expression régulière est illisible et se perd au
// premier copier-coller.
const HIDDEN_RUN = new RegExp(`${MARK}[\\u200B-\\u200D\\u2060-\\u2064]{32,}`, "u");

// Un ❤️ isolé contient un sélecteur de variation parfaitement légitime ; une
// trame Papotage en aligne au moins 45.
const VS_RUN = /(?:[\u{FE00}-\u{FE0F}]|[\u{E0100}-\u{E01EF}]){24,}/u;

// Un vrai payload emoji fait au moins 90 emojis : exiger une série évite de
// réagir à un simple 👍 dans une phrase.
const EMOJI_RUN = new RegExp(`[${EMOJI.join("")}]{16,}`, "u");

export function detectMode(content) {
    if (!content) return null;
    if (HIDDEN_RUN.test(content)) return MODE.HIDDEN; // couvre aussi HIDDEN_SAFE
    if (VS_RUN.test(content)) return MODE.COMPACT;
    if (EMOJI_RUN.test(content)) return MODE.EMOJI;
    return null;
}

// true si le message porte déjà un payload Papotage (ne pas le re-chiffrer).
export function isPapotageMessage(content) {
    return detectMode(content) !== null;
}

// Renvoie le texte clair, ou null si ce n'est pas pour nous / mauvaise clé.
// Ne lève jamais : un message hostile ne doit pas casser le rendu du salon.
export async function decodeIncoming({ content, passphrase, context = "" }) {
    if (!passphrase || !content) return null;
    const mode = detectMode(content);
    if (!mode) return null;
    try {
        switch (mode) {
            case MODE.COMPACT: return await decodeCompact(content, passphrase, { context });
            case MODE.EMOJI: return await decodeEmoji(content, passphrase, { context });
            default: return await decodeHidden(content, passphrase, { context });
        }
    } catch {
        return null;
    }
}

// Retire le préfixe ajouté à l'affichage, pour récupérer le clair d'origine
// (nécessaire avant de re-chiffrer un message qu'on édite).
export function stripLockPrefix(content) {
    return content.startsWith(LOCK_PREFIX) ? content.slice(LOCK_PREFIX.length) : content;
}

// ===========================================================================
// Anti-rejeu d'affichage
// ===========================================================================
// Discord re-dispatche les mêmes messages en boucle (scroll, focus, édition).
// On mémorise ce qui a déjà été traité — succès comme échec — pour ne pas
// relancer un déchiffrement par re-render.
export class SeenCache {
    constructor(max = 5000, evict = 1000) {
        this.max = max;
        this.evict = evict;
        this.map = new Map(); // Map = ordre d'insertion : les plus anciens d'abord
    }

    has(id, content) {
        return this.map.get(id) === content;
    }

    set(id, content) {
        if (this.map.size >= this.max) {
            let n = this.evict;
            for (const k of this.map.keys()) { this.map.delete(k); if (--n === 0) break; }
        }
        this.map.set(id, content);
    }

    clear() {
        this.map.clear();
    }

    get size() {
        return this.map.size;
    }
}
