/*
 * Papotage — plugin Vencord.
 * Chiffre les messages et cache le résultat : l'outsider voit une phrase banale
 * (ou des emojis), toi (avec le plugin + la clé) tu vois le vrai texte à la place.
 */

import { addChatBarButton, ChatBarButton, ChatBarButtonFactory, removeChatBarButton } from "@api/ChatButtons";
import { addMessagePreSendListener, removeMessagePreSendListener } from "@api/MessageEvents";
import { updateMessage } from "@api/MessageUpdater";
import { definePluginSettings } from "@api/Settings";
import definePlugin, { OptionType } from "@utils/types";
import { FluxDispatcher, MessageStore, SelectedChannelStore, useState } from "@webpack/common";

import { decodeEmoji, decodeHidden, encodeEmoji, encodeHidden, parseInput } from "./codec.mjs";

const MARK = "⁠"; // marqueur zero-width : signale un message déjà chiffré

const settings = definePluginSettings({
    passphrase: {
        type: OptionType.STRING,
        description: "Mot de passe partagé (identique chez tous les participants)",
        default: ""
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
        default: ""
    },
    separator: {
        type: OptionType.STRING,
        description: "Séparateur 'couverture | secret' pour écrire soi-même la phrase visible",
        default: " | "
    },
    emojiMode: {
        type: OptionType.BOOLEAN,
        description: "Mode emoji : les emojis visibles portent le secret (visible mais codé, pour messages courts)",
        default: false
    }
});

// Salons où le chiffrement est activé (réinitialisé au rechargement de Discord).
const enabledChannels = new Set<string>();

// --- Icône cadenas ----------------------------------------------------------
function LockIcon({ on }: { on: boolean; }) {
    return (
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
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

    const toggle = () => {
        if (enabledChannels.has(channel.id)) enabledChannels.delete(channel.id);
        else enabledChannels.add(channel.id);
        setOn(enabledChannels.has(channel.id));
    };

    return (
        <ChatBarButton
            tooltip={on ? "Papotage activé (messages chiffrés)" : "Papotage désactivé"}
            onClick={toggle}
        >
            <div style={{ color: on ? "var(--green-360)" : "var(--interactive-normal)", display: "flex" }}>
                <LockIcon on={on} />
            </div>
        </ChatBarButton>
    );
};

// Filtre rapide du mode emoji. Un vrai payload emoji est une longue suite
// d'emojis du dico (2 par octet, donc des dizaines) ; on exige un run pour ne PAS
// lancer le décodage sur un message normal qui contient juste un 😂 ou un 👍.
const EMOJI_RUN_RE = /[😀😂😅😍🤔😎😭😡👍🔥🎉💀👀🚀🍕💯]{16,}/u;
const inFlight = new Set<string>(); // messages en cours de déchiffrement (anti-doublon)

// --- Déchiffrement : remplace le contenu affiché par le vrai message ---------
async function tryDecrypt(channelId: string, messageId: string, content: string) {
    if (!settings.store.autoDecrypt) return;
    const pass = settings.store.passphrase;
    if (!pass || !content) return;

    const hasMark = content.includes(MARK);
    if (!hasMark && !EMOJI_RUN_RE.test(content)) return; // clairement pas chiffré
    if (inFlight.has(messageId)) return;

    inFlight.add(messageId);
    try {
        const txt = hasMark ? await decodeHidden(content, pass) : await decodeEmoji(content, pass);
        if (txt != null) updateMessage(channelId, messageId, { content: settings.store.showLock ? `🔓 ${txt}` : txt });
    } finally {
        inFlight.delete(messageId);
    }
}

function scanChannel(channelId?: string) {
    if (!channelId) return;
    try {
        const store: any = MessageStore.getMessages(channelId);
        const arr: any[] = store?.toArray?.() ?? store?._array ?? (Array.isArray(store) ? store : []);
        for (const m of arr) if (m?.content) tryDecrypt(channelId, m.id, m.content);
    } catch { /* ignore */ }
}

function scanCurrent() {
    try { scanChannel(SelectedChannelStore.getChannelId()); } catch { /* ignore */ }
}

const onCreate = (e: any) => { const m = e?.message; if (m?.content) tryDecrypt(m.channel_id, m.id, m.content); };
const onUpdate = (e: any) => { const m = e?.message; if (m?.content) tryDecrypt(m.channel_id, m.id, m.content); };
const onSelect = (e: any) => scanChannel(e?.channelId);
const onLoad = (e: any) => scanChannel(e?.channelId);

let preSend: any;

export default definePlugin({
    name: "Papotage",
    description: "Chiffre tes messages et les cache dans du texte invisible ou des emojis : personne ne voit qu'ils sont chiffrés, toi tu les lis en clair.",
    authors: [{ name: "zefarie", id: 0n }],
    dependencies: ["ChatInputButtonAPI", "MessageEventsAPI", "MessageUpdaterAPI"],
    settings,

    start() {
        preSend = addMessagePreSendListener(async (channelId, msg) => {
            if (!enabledChannels.has(channelId)) return;
            const pass = settings.store.passphrase;
            if (!pass || !msg.content) return;
            if (msg.content.includes(MARK)) return; // déjà chiffré : ne pas ré-encoder

            const { cover, secret } = parseInput(msg.content, settings.store.separator || " | ");
            if (!secret) return;
            const chosenCover = cover ?? (settings.store.customCover || undefined);

            msg.content = settings.store.emojiMode
                ? await encodeEmoji(secret, pass, chosenCover)
                : await encodeHidden(secret, pass, chosenCover);
        });

        addChatBarButton("papotage", PapotageButton, ({ ...props }) => <LockIcon on={false} {...props} />);

        FluxDispatcher.subscribe("MESSAGE_CREATE", onCreate);
        FluxDispatcher.subscribe("MESSAGE_UPDATE", onUpdate);
        FluxDispatcher.subscribe("CHANNEL_SELECT", onSelect);
        FluxDispatcher.subscribe("LOAD_MESSAGES_SUCCESS", onLoad);

        // déchiffrer l'historique déjà affiché (ex. après un Ctrl+R, salon déjà ouvert)
        scanCurrent();
        setTimeout(scanCurrent, 1500);
        setTimeout(scanCurrent, 4000);
    },

    stop() {
        removeMessagePreSendListener(preSend);
        removeChatBarButton("papotage");
        FluxDispatcher.unsubscribe("MESSAGE_CREATE", onCreate);
        FluxDispatcher.unsubscribe("MESSAGE_UPDATE", onUpdate);
        FluxDispatcher.unsubscribe("CHANNEL_SELECT", onSelect);
        FluxDispatcher.unsubscribe("LOAD_MESSAGES_SUCCESS", onLoad);
    }
});
