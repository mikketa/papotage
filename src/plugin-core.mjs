// Logique du plugin, isolée de Vencord.
//
// Tout ce qui décide *quoi* envoyer et *quoi* déchiffrer vit ici : aucune
// dépendance à Discord, donc testable en Node. `index.tsx` ne garde que le
// câblage (boutons, événements Flux, toasts).

import {
    decodeCompact, decodeEmoji, decodeHidden,
    encodeCompact, encodeEmoji, encodeHidden,
    scanSymbols,
    visibleText
} from "./codec.mjs";
import { MIN_COVER_GRAPHEMES, parseCoverPool, pickCover } from "./covers.mjs";
import { PADDING, forgetKeys, warmKey } from "./envelope.mjs";

// Réexporté pour que le câblage Vencord n'ait qu'une seule couche en face de
// lui : c'est la couche application qui expose ce dont l'interface a besoin.
export { MIN_COVER_GRAPHEMES, PADDING, forgetKeys, parseCoverPool, warmKey };

export const MODE = {
    HIDDEN: "hidden",     // zero-width 3 bits/car (défaut)
    HIDDEN_SAFE: "safe",  // zero-width 2 bits/car : 4 symboles seulement, le jeu
    //                       le plus universellement préservé. Plus long.
    COMPACT: "compact",   // sélecteurs de variation : 1 octet = 1 car, le plus court
    EMOJI: "emoji"        // emojis visibles : lisiblement bizarre, messages courts
};

// Un mode = un encodeur et un décodeur, déclarés côte à côte. `detectMode` ne
// distingue pas les deux densités zero-width (elle se déduit des symboles), donc
// HIDDEN décode aussi HIDDEN_SAFE.
const CODECS = {
    [MODE.HIDDEN]: [(txt, pass, o) => encodeHidden(txt, pass, { ...o, bits: 3 }), decodeHidden],
    [MODE.HIDDEN_SAFE]: [(txt, pass, o) => encodeHidden(txt, pass, { ...o, bits: 2 }), decodeHidden],
    [MODE.COMPACT]: [encodeCompact, decodeCompact],
    [MODE.EMOJI]: [encodeEmoji, decodeEmoji]
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

// Sépare une saisie « phrase visible | message secret ».
//   - séparateur présent -> couverture écrite par l'humain, pour garder une
//     conversation cohérente ;
//   - absent -> tout est secret, la couverture est tirée au sort.
// On coupe au PREMIER séparateur seulement : le secret peut en contenir.
//
// C'est de l'interprétation de saisie utilisateur, pas de l'encodage — d'où sa
// place ici et non dans le codec.
function parseInput(raw, separator) {
    const at = raw.indexOf(separator);
    const cover = at < 0 ? "" : raw.slice(0, at).trim();
    const secret = at < 0 ? raw : raw.slice(at + separator.length);
    // Un des deux côtés vide (espaces compris) => la saisie n'est pas un vrai
    // couple couverture/secret : on chiffre tout, plutôt que de publier la
    // moitié gauche en clair en croyant que c'est une couverture voulue.
    return cover && secret.trim() ? { cover, secret } : { cover: null, secret: raw };
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
    maxChars = MAX_MESSAGE_CHARS,
    padding = PADDING.BLOCK,
    pool = []
}) {
    if (!passphrase) {
        throw new PapotageError("no-passphrase",
            "Papotage : aucun mot de passe défini. Message NON envoyé (il serait parti en clair).");
    }
    if (!raw || !raw.trim()) {
        throw new PapotageError("empty", "Papotage : message vide.");
    }

    const { cover, secret } = parseInput(raw, resolveSeparator(separator));
    // Le choix de la phrase affichée se fait ICI : c'est une décision de produit.
    // Le codec la reçoit toute faite et n'a pas à connaître le pool.
    const encode = (CODECS[mode] ?? CODECS[MODE.HIDDEN])[0];
    let content;
    try {
        content = await encode(secret, passphrase,
            { cover: pickCover(cover ?? defaultCover, { pool }), context, padding });
    } catch (e) {
        // Une couverture trop courte n'est pas une panne de chiffrement : c'est
        // un réglage à corriger, et le message doit le dire.
        if (e instanceof RangeError || e instanceof TypeError) {
            throw new PapotageError("cover-too-short", `${e.message} Message NON envoyé.`);
        }
        throw new PapotageError("encode-failed",
            `Papotage : échec du chiffrement (${e?.message ?? e}). Message NON envoyé.`);
    }

    // Discord rejette silencieusement au-delà de 2000 : mieux vaut annuler avec
    // une explication que laisser le message disparaître sans rien dire.
    if (content.length > maxChars) {
        throw new PapotageError("too-long",
            `Papotage : message trop long de ${content.length - maxChars} caractères une fois chiffré `
            + `(${content.length} / ${maxChars}). Coupe-le en deux`
            + (mode === MODE.HIDDEN ? " ou passe en mode compact." : "."));
    }
    return content;
}

// ===========================================================================
// Réception
// ===========================================================================
// Pré-filtre : quel décodeur tenter, ou null si le message n'a clairement rien
// à voir avec Papotage. Le payload étant dispersé dans la couverture, il n'y a
// ni marqueur de début ni traînée à chercher : on compte les symboles présents.
//
// Ces seuils comptent deux fois :
//   - à la réception, ils évitent de lancer un déchiffrement sur chaque message
//     du salon (le scan d'un historique en traite des centaines) ;
//   - à l'envoi, `isPapotageMessage` sert à ne pas re-chiffrer un message déjà
//     chiffré. Un faux positif là-dessus enverrait le message EN CLAIR.
// La plus petite trame possible fait 44 octets, soit 119 symboles invisibles en
// densité 3 bits, 45 en mode compact, 90 emojis en mode emoji. Les seuils gardent
// une marge sous ces minimums, tout en restant très au-dessus de ce qu'un humain
// peut taper ou coller par accident. Le mode emoji, lui, produit une série
// contiguë : c'est un run qu'on cherche, pour ne pas réagir à un simple 👍.
const MIN_HIDDEN = 64;
const MIN_COMPACT = 40;
const MIN_EMOJI_RUN = 32;
const STOP = Object.freeze({ hidden: MIN_HIDDEN, compact: MIN_COMPACT, emoji: MIN_EMOJI_RUN });

export function detectMode(content) {
    if (!content) return null;
    // Un seul passage sur le message, avec sortie dès qu'un seuil est franchi.
    const { hidden, compact, emojiRun } = scanSymbols(content, STOP);
    if (hidden >= MIN_HIDDEN) return MODE.HIDDEN; // couvre aussi HIDDEN_SAFE
    if (compact >= MIN_COMPACT) return MODE.COMPACT;
    if (emojiRun >= MIN_EMOJI_RUN) return MODE.EMOJI;
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
        return await CODECS[mode][1](content, passphrase, { context });
    } catch {
        return null;
    }
}

// Retire le marqueur ajouté à l'affichage, pour récupérer le clair d'origine
// (nécessaire avant de re-chiffrer un message qu'on édite).
//
// Un message chiffré qu'on ne sait PAS lire n'est, lui, marqué par rien : un
// signe à l'écran trahirait l'utilisateur devant un témoin ou un partage
// d'écran. L'échec silencieux est un choix, pas un oubli.
export function stripMarkers(content) {
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

// ===========================================================================
// Vérification de bout en bout
// ===========================================================================
// Le codec suppose que Discord conserve intégralement les caractères invisibles
// d'un message, y compris insérés au milieu d'un texte. Cette hypothèse ne se
// vérifie pas en local : seul un aller-retour par les serveurs de Discord peut
// trancher. Plutôt que de la documenter comme une inconnue, on la mesure. Chaque
// message chiffré envoyé est retenu ; quand Discord nous le renvoie
// (MESSAGE_CREATE), on compare. S'il diffère, le destinataire ne pourra pas le
// lire, et l'expéditeur doit le savoir tout de suite.
export class SendLedger {
    constructor(max = 32) {
        this.max = max;
        this.pending = [];
    }

    remember(content) {
        if (this.pending.length >= this.max) this.pending.shift();
        this.pending.push({ content, key: visibleText(content), settled: false });
    }

    // "ok"      : Discord a rendu le message à l'identique ;
    // "altered" : un de nos envois est revenu différent ;
    // null      : rien à signaler.
    //
    // `isOwn` est indispensable et ne peut pas être deviné ici : un message
    // dépouillé de tous ses caractères invisibles est indiscernable d'un message
    // où quelqu'un d'autre a tapé la même phrase que notre couverture. Sans
    // l'identité de l'auteur, on alerterait à tort.
    check(received, { isOwn = false } = {}) {
        const exact = this.pending.find(e => e.content === received);
        if (exact) { exact.settled = true; return "ok"; }
        if (!isOwn) return null;
        // Même couverture, contenu différent : Discord a touché au message.
        // On ne prévient qu'une fois par envoi.
        const key = visibleText(received); // invariant de boucle : une seule fois
        const near = this.pending.find(e => !e.settled && e.key === key);
        if (!near) return null;
        near.settled = true;
        return "altered";
    }

    get size() {
        return this.pending.length;
    }
}
