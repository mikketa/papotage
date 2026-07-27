/*
 * Papotage — plugin Vencord.
 * Chiffre les messages et cache le résultat : l'outsider voit une phrase banale
 * (ou des emojis), toi (avec le plugin + la clé) tu vois le vrai texte à la place.
 *
 * Ce fichier ne fait que du câblage Vencord, et c'est le SEUL qui connaisse
 * Discord. Toute la logique vit derrière `plugin-core.mjs`, qui expose ce dont
 * l'interface a besoin — d'où l'unique import local ci-dessous.
 * `test/architecture.test.mjs` vérifie cette règle à chaque exécution.
 */

import { addChatBarButton, ChatBarButton, ChatBarButtonFactory, removeChatBarButton } from "@api/ChatButtons";
import {
    addMessagePreEditListener,
    addMessagePreSendListener,
    removeMessagePreEditListener,
    removeMessagePreSendListener
} from "@api/MessageEvents";
import { updateMessage } from "@api/MessageUpdater";
import { definePluginSettings } from "@api/Settings";
import definePlugin, { OptionType } from "@utils/types";
import { FluxDispatcher, MessageStore, SelectedChannelStore, Toasts, UserStore, useState } from "@webpack/common";

import {
    decodeIncoming,
    encodeOutgoing,
    isPapotageMessage,
    LOCK_PREFIX,
    MIN_COVER_GRAPHEMES,
    MODE,
    PADDING,
    PapotageError,
    SeenCache,
    SendLedger,
    forgetKeys,
    parseCoverPool,
    stripMarkers,
    warmKey
} from "./plugin-core.mjs";

const settings = definePluginSettings({
    passphrase: {
        type: OptionType.STRING,
        description: "Mot de passe partagé (identique chez tous les participants)",
        default: "",
        // 600 000 itérations PBKDF2 ne rachètent pas un mot de passe de six
        // caractères : c'est la façon la plus réaliste de casser Papotage.
        isValid: (v: string) => !v || v.length >= 12
            || "Trop court : sous 12 caractères, le mot de passe se devine plus vite que le chiffrement ne se casse."
    },
    mode: {
        type: OptionType.SELECT,
        description: "Encodage du secret",
        options: [
            {
                label: "Invisible dense — recommandé (caractères zero-width, 3 bits/car)",
                value: MODE.HIDDEN,
                default: true
            },
            { label: "Invisible sûr — jeu de caractères minimal, messages plus longs", value: MODE.HIDDEN_SAFE },
            { label: "Compact — le plus court (sélecteurs de variation)", value: MODE.COMPACT },
            { label: "Emoji — visible et bizarre, pour messages courts", value: MODE.EMOJI }
        ]
    },
    autoDecrypt: {
        type: OptionType.BOOLEAN,
        description: "Déchiffrer automatiquement les messages reçus",
        default: true
    },
    showLock: {
        type: OptionType.BOOLEAN,
        description: "Afficher un 🔓 devant les messages déchiffrés (pour les distinguer)",
        default: true
    },
    customCover: {
        type: OptionType.STRING,
        description: "Phrase de couverture perso par défaut (vide = phrase naturelle aléatoire)",
        default: "",
        // Une couverture courte n'offre pas assez d'intervalles pour répartir la
        // partie invisible : le message part en un bloc, ce qui se repère. Mieux
        // vaut le dire ici qu'au moment de l'envoi.
        isValid: (v: string) => !v || v.trim().length >= MIN_COVER_GRAPHEMES
            || `Trop courte : sous ${MIN_COVER_GRAPHEMES} caractères, la partie invisible ne peut pas se répartir et forme un bloc repérable.`
    },
    coverPool: {
        type: OptionType.STRING,
        multiline: true,
        description: "Tes propres phrases de couverture, une par ligne "
            + "(le pool intégré est public, donc connu de qui lit le code)",
        default: ""
    },
    lengthHiding: {
        type: OptionType.BOOLEAN,
        description: "Masquer la longueur : rembourre par paliers au lieu de blocs de 16 octets. "
            + "Plus discret, mais les messages courts deviennent nettement plus longs",
        default: false
    },
    separator: {
        type: OptionType.STRING,
        description: "Séparateur 'couverture | secret' pour écrire soi-même la phrase visible",
        default: " | "
    }
});

// Salons où le chiffrement est activé (réinitialisé au rechargement de Discord :
// on préfère un cadenas qui retombe sur « off » à un cadenas qu'on croit à tort actif).
const enabledChannels = new Set<string>();

function toast(type: any, message: string) {
    Toasts.show({ id: Toasts.genId(), type, message });
}

// Réglages d'encodage, résolus au moment de l'envoi (l'utilisateur peut les
// changer en cours de session).
function encodeSettings() {
    return {
        passphrase: settings.store.passphrase,
        mode: settings.store.mode,
        defaultCover: settings.store.customCover ?? "",
        separator: settings.store.separator,
        pool: parseCoverPool(settings.store.coverPool),
        padding: settings.store.lengthHiding ? PADDING.BUCKET : PADDING.BLOCK
    };
}

// --- Icône cadenas ----------------------------------------------------------
// Vencord exige un IconComponent en 3e argument de addChatBarButton : il sert à
// représenter le bouton dans l'écran de réglages, où il est dimensionné par
// l'appelant. D'où les props height/width/className, à ne pas ignorer.
function LockIcon({ on, height = 24, width = 24, className }: {
    on: boolean; height?: number | string; width?: number | string; className?: string;
}) {
    return (
        <svg width={width} height={height} className={className} viewBox="0 0 24 24" fill="none">
            <rect x="5" y="11" width="14" height="9" rx="2"
                fill={on ? "currentColor" : "none"} stroke="currentColor" strokeWidth="2" />
            <path d={on ? "M8 11V8a4 4 0 0 1 8 0v3" : "M8 11V8a4 4 0 0 1 8 0"}
                stroke="currentColor" strokeWidth="2" fill="none" />
        </svg>
    );
}

// --- Bouton dans la barre de message ----------------------------------------
const PapotageButton: ChatBarButtonFactory = ({ channel, isMainChat }) => {
    const [on, setOn] = useState(enabledChannels.has(channel.id));
    if (!isMainChat) return null;

    // Cadenas vert mais pas de mot de passe = rien ne peut être chiffré. On le
    // signale (orange + tooltip) au lieu de laisser croire que c'est protégé.
    const armed = on && !!settings.store.passphrase;
    const color = !on ? "var(--interactive-normal)"
        : armed ? "var(--green-360)" : "var(--yellow-300)";

    const toggle = () => {
        if (enabledChannels.has(channel.id)) enabledChannels.delete(channel.id);
        else {
            enabledChannels.add(channel.id);
            if (!settings.store.passphrase) {
                toast(Toasts.Type.MESSAGE, "Papotage : définis un mot de passe dans les réglages du plugin.");
            }
        }
        setOn(enabledChannels.has(channel.id));
    };

    const tooltip = !on ? "Papotage désactivé"
        : armed ? "Papotage activé (messages chiffrés)"
            : "Papotage armé mais SANS mot de passe — les envois seront bloqués";

    return (
        <ChatBarButton tooltip={tooltip} onClick={toggle}>
            <div style={{ color, display: "flex" }}>
                <LockIcon on={on} />
            </div>
        </ChatBarButton>
    );
};

// --- Déchiffrement ----------------------------------------------------------
const inFlight = new Set<string>();  // déchiffrements simultanés (anti-doublon)
const seen = new SeenCache();        // messageId -> contenu déjà traité (borné, évincé)
let lastPass = "";                   // si le mot de passe change, on réessaie tout

// Messages dont on a remplacé le contenu affiché par le clair. Volontairement
// SANS limite de taille et jamais vidé en cours de session : oublier une entrée
// ici, c'est perdre la protection à l'édition sur un message dont le store
// contient le secret en clair. Ce ne sont que des identifiants.
const decrypted = new Set<string>();

// Messages chiffrés qu'on vient d'envoyer, en attente de retour par Discord.
// C'est la seule façon de savoir si Discord préserve vraiment nos caractères
// invisibles : on le mesure au lieu de le supposer.
const ledger = new SendLedger();

function passphraseChanged(pass: string) {
    if (pass === lastPass) return;
    lastPass = pass;
    seen.clear();   // retenter le déchiffrement de tout le salon avec la nouvelle clé
    forgetKeys();
    // `decrypted` n'est PAS vidé : les messages déjà affichés en clair le restent,
    // et leur édition doit continuer d'être interceptée.
}

async function tryDecrypt(channelId: string, messageId: string, content: string) {
    if (!settings.store.autoDecrypt) return;
    const pass = settings.store.passphrase;
    passphraseChanged(pass);
    if (!pass || !content) return;
    // Dédoublonnage AVANT le pré-filtre : un message déjà traité (échec compris,
    // ou contenu déjà remplacé) ne relance ni la détection ni le déchiffrement.
    if (inFlight.has(messageId) || seen.has(messageId, content)) return;

    inFlight.add(messageId);
    try {
        // Le contexte = le salon : la clé diffère d'une conversation à l'autre.
        const txt = await decodeIncoming({ content, passphrase: pass, context: channelId });
        seen.set(messageId, content);
        // Un message chiffré qu'on ne sait pas lire n'est signalé par RIEN :
        // le marquer à l'écran trahirait l'utilisateur devant un témoin ou un
        // partage d'écran. Le silence fait partie de la couverture.
        if (txt == null) return;
        const shown = settings.store.showLock ? LOCK_PREFIX + txt : txt;
        seen.set(messageId, shown); // le contenu remplacé ne repassera pas le filtre
        decrypted.add(messageId);
        updateMessage(channelId, messageId, { content: shown });
    } finally {
        inFlight.delete(messageId);
    }
}

// Les événements Flux appellent tryDecrypt sans l'attendre : une exception
// inattendue ne doit pas remonter en unhandled rejection.
const decryptLater = (channelId: string, messageId: string, content: string) =>
    void tryDecrypt(channelId, messageId, content).catch(() => { });

function scanChannel(channelId?: string) {
    if (!channelId) return;
    try {
        const store: any = MessageStore.getMessages(channelId);
        const arr: any[] = store?.toArray?.() ?? store?._array ?? (Array.isArray(store) ? store : []);
        for (const m of arr) if (m?.content) decryptLater(channelId, m.id, m.content);
    } catch { /* ignore */ }
}

function scanCurrent() {
    try { scanChannel(SelectedChannelStore.getChannelId()); } catch { /* ignore */ }
}

const onCreate = (e: any) => {
    const m = e?.message;
    if (!m?.content) return;
    // Discord nous renvoie nos propres messages : c'est le moment de vérifier
    // qu'il ne les a pas modifiés en route. L'identité de l'auteur est
    // indispensable — voir SendLedger.check.
    let isOwn = false;
    try { isOwn = !!m.author?.id && m.author.id === UserStore.getCurrentUser()?.id; } catch { /* ignore */ }
    if (ledger.check(m.content, { isOwn }) === "altered") {
        toast(Toasts.Type.FAILURE,
            "Papotage : Discord a modifié ton message en le publiant. "
            + "Le destinataire ne pourra pas le lire — essaie le mode « Invisible sûr ».");
    }
    decryptLater(m.channel_id, m.id, m.content);
};
const onUpdate = (e: any) => { const m = e?.message; if (m?.content) decryptLater(m.channel_id, m.id, m.content); };
const onSelect = (e: any) => {
    // Pré-dérive la clé, mais SEULEMENT là où le chiffrement est armé : chaque
    // dérivation coûte ~104 ms de CPU (mesuré) et occupe une place dans un cache
    // borné à 16 entrées. Pré-chauffer chaque salon parcouru gaspillait les deux.
    // Ailleurs, la clé est dérivée à la demande au premier message reconnu.
    if (e?.channelId && enabledChannels.has(e.channelId)) {
        warmKey(settings.store.passphrase, e.channelId);
    }
    scanChannel(e?.channelId);
};
// LOAD_MESSAGES_SUCCESS est émis par page d'historique : ne traiter que la page
// chargée (et pas tout le salon à chaque fois), sinon le scroll d'historique est
// quadratique. Repli sur un scan complet si le payload ne porte pas les messages.
const onLoad = (e: any) => {
    if (!e?.channelId) return;
    const msgs = e?.messages;
    if (Array.isArray(msgs) && msgs.length) {
        for (const m of msgs) if (m?.content) decryptLater(e.channelId, m.id, m.content);
    } else {
        scanChannel(e.channelId);
    }
};

let preSend: any;
let preEdit: any;
let scanTimers: any[] = []; // timers de scan différés, à annuler au stop()

export default definePlugin({
    name: "Papotage",
    description: "Chiffre tes messages et les cache dans du texte invisible ou des emojis : personne ne voit qu'ils sont chiffrés, toi tu les lis en clair.",
    authors: [{ name: "zefarie", id: 0n }],
    dependencies: ["ChatInputButtonAPI", "MessageEventsAPI", "MessageUpdaterAPI"],
    settings,

    start() {
        // --- Envoi : fail-closed -------------------------------------------
        // Toute erreur annule l'envoi. Le mode dégradé « on envoie quand même »
        // publierait le secret en clair, ce qui est pire que ne rien envoyer.
        preSend = addMessagePreSendListener(async (channelId, msg) => {
            // Le try couvre TOUT le corps, pré-filtre compris. Vencord attend bien
            // les listeners asynchrones, mais son gestionnaire journalise les
            // exceptions et renvoie `false` — c'est-à-dire « ne pas annuler ».
            // Une exception qui s'échappe d'ici publierait donc le message EN CLAIR.
            try {
                if (!enabledChannels.has(channelId)) return;
                if (!msg.content) return;
                if (isPapotageMessage(msg.content)) return; // déjà chiffré : ne pas ré-encoder

                msg.content = await encodeOutgoing({ ...encodeSettings(), raw: msg.content, context: channelId });
                ledger.remember(msg.content);
            } catch (e) {
                const m = e instanceof PapotageError ? e.message
                    : `Papotage : échec inattendu (${(e as any)?.message ?? e}). Message NON envoyé.`;
                toast(Toasts.Type.FAILURE, m);
                return { cancel: true };
            }
        });

        // --- Édition : ne jamais republier le clair -------------------------
        // On a remplacé le contenu affiché par le texte déchiffré : la boîte
        // d'édition est donc pré-remplie avec le SECRET. Sans ce garde-fou,
        // éditer un message revient à le publier en clair dans le salon.
        preEdit = addMessagePreEditListener(async (channelId, messageId, msg) => {
            // Même raison qu'à l'envoi : une exception qui s'échappe republierait
            // le clair dans le salon.
            try {
                if (!decrypted.has(messageId)) return;
                msg.content = await encodeOutgoing({
                    ...encodeSettings(), raw: stripMarkers(msg.content), context: channelId
                });
            } catch (e) {
                const why = e instanceof PapotageError ? e.message : String((e as any)?.message ?? e);
                toast(Toasts.Type.FAILURE, `Papotage : édition annulée, le texte serait parti en clair. ${why}`);
                return { cancel: true };
            }
        });

        addChatBarButton("papotage", PapotageButton, props => <LockIcon on={false} {...props} />);

        FluxDispatcher.subscribe("MESSAGE_CREATE", onCreate);
        FluxDispatcher.subscribe("MESSAGE_UPDATE", onUpdate);
        FluxDispatcher.subscribe("CHANNEL_SELECT", onSelect);
        FluxDispatcher.subscribe("LOAD_MESSAGES_SUCCESS", onLoad);

        // déchiffrer l'historique déjà affiché (ex. après un Ctrl+R, salon déjà ouvert)
        scanCurrent();
        scanTimers.push(setTimeout(scanCurrent, 1500), setTimeout(scanCurrent, 4000));
    },

    stop() {
        removeMessagePreSendListener(preSend);
        removeMessagePreEditListener(preEdit);
        removeChatBarButton("papotage");
        scanTimers.forEach(clearTimeout);
        scanTimers = [];
        FluxDispatcher.unsubscribe("MESSAGE_CREATE", onCreate);
        FluxDispatcher.unsubscribe("MESSAGE_UPDATE", onUpdate);
        FluxDispatcher.unsubscribe("CHANNEL_SELECT", onSelect);
        FluxDispatcher.unsubscribe("LOAD_MESSAGES_SUCCESS", onLoad);
        seen.clear();
        decrypted.clear();
        forgetKeys(); // ne pas laisser traîner les clés dérivées après un stop
    }
});
