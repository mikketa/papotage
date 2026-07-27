// Logique du plugin. C'était le trou de couverture : tout ce qui décide
// d'envoyer ou non vivait dans index.tsx, donc n'était testé par rien.

import assert from "node:assert/strict";
import test from "node:test";

import {
    DEFAULT_SEPARATOR,
    LOCK_PREFIX,
    MODE,
    PapotageError,
    SeenCache,
    SendLedger,
    decodeIncoming,
    detectMode,
    encodeOutgoing,
    isPapotageMessage,
    resolveSeparator,
    stripMarkers
} from "../src/plugin-core.mjs";
import { EMOJI, scanSymbols, visibleText } from "../src/codec.mjs";
import { CTX, OTHER_CTX, PASS, incompressible, visible } from "./helpers.mjs";

const base = { passphrase: PASS, context: CTX };

async function expectError(code, fn) {
    await assert.rejects(fn, e => {
        assert.ok(e instanceof PapotageError, `type inattendu : ${e?.name}`);
        assert.equal(e.code, code);
        return true;
    });
}

// --- Fail-closed : le cœur du sujet ----------------------------------------

test("sans mot de passe, l'envoi échoue au lieu de partir en clair", async () => {
    await expectError("no-passphrase", () =>
        encodeOutgoing({ raw: "le colis est sous l'escalier", passphrase: "", context: CTX }));
});

test("un secret vide après le séparateur ne publie pas la moitié gauche en clair", async () => {
    // "juste une couverture |   " n'est pas un vrai couple couverture/secret :
    // on chiffre toute la saisie plutôt que d'exposer le début du message.
    const raw = "juste une couverture |   ";
    const content = await encodeOutgoing({ ...base, raw });
    assert.ok(!visible(content).includes("juste une couverture"));
    assert.equal(await decodeIncoming({ content, ...base }), raw);
});

test("un message vide échoue", async () => {
    await expectError("empty", () => encodeOutgoing({ ...base, raw: "   " }));
});

test("un message trop long une fois chiffré échoue au lieu d'être avalé par Discord", async () => {
    // Discord rejette silencieusement au-delà de 2000 : sans cette erreur, le
    // message disparaissait sans que personne ne le sache.
    // Couverture fixée : sa longueur varie de 2 à 59 caractères selon le
    // gabarit tiré, ce qui rendrait le test proche du seuil non déterministe.
    await expectError("too-long", () =>
        encodeOutgoing({ ...base, raw: incompressible(1200), mode: MODE.HIDDEN, defaultCover: "ok" }));
});

test("l'erreur de dépassement dit de combien on dépasse", async () => {
    await assert.rejects(
        () => encodeOutgoing({ ...base, raw: incompressible(1200), defaultCover: "ok" }),
        /trop long de \d+ caractères/
    );
});

// --- Aller-retour par mode --------------------------------------------------

for (const mode of Object.values(MODE)) {
    test(`aller-retour complet en mode ${mode}`, async () => {
        const clair = "on se retrouve à 21h devant chez toi 🙂";
        const content = await encodeOutgoing({ ...base, raw: clair, mode });
        assert.ok(content.length <= 2000);
        assert.equal(await decodeIncoming({ content, ...base }), clair);
    });

    test(`le mode ${mode} est reconnu par le pré-filtre`, async () => {
        const content = await encodeOutgoing({ ...base, raw: "secret un peu long pour remplir", mode });
        assert.ok(isPapotageMessage(content), `non détecté : ${JSON.stringify(content.slice(0, 40))}`);
    });
}

// --- Couverture et séparateur ----------------------------------------------

test("'couverture | secret' : seule la couverture est visible", async () => {
    const content = await encodeOutgoing({ ...base, raw: "ouais tranquille et toi ? 😄 | le colis est planqué" });
    assert.equal(visible(content), "ouais tranquille et toi ? 😄");
    assert.equal(await decodeIncoming({ content, ...base }), "le colis est planqué");
});

test("sans séparateur, tout est secret et la couverture est auto", async () => {
    const content = await encodeOutgoing({ ...base, raw: "rdv 20h" });
    assert.ok(visible(content).length > 0);
    assert.ok(!visible(content).includes("rdv"));
    assert.equal(await decodeIncoming({ content, ...base }), "rdv 20h");
});

test("la couverture par défaut des réglages sert de repli", async () => {
    const content = await encodeOutgoing({ ...base, raw: "secret", defaultCover: "ça marche pour moi" });
    assert.equal(visible(content), "ça marche pour moi");
});

test("un séparateur vide retombe sur la valeur par défaut", () => {
    // Sinon indexOf("") vaut 0 et découperait tous les messages normaux.
    assert.equal(resolveSeparator(""), DEFAULT_SEPARATOR);
    assert.equal(resolveSeparator("   "), DEFAULT_SEPARATOR);
    assert.equal(resolveSeparator(" >> "), " >> ");
});

test("un séparateur perso est respecté", async () => {
    const content = await encodeOutgoing({ ...base, raw: "salut >> le vrai message", separator: " >> " });
    assert.equal(visible(content), "salut");
    assert.equal(await decodeIncoming({ content, ...base }), "le vrai message");
});

// --- Réception --------------------------------------------------------------

test("un message d'un autre salon ne se déchiffre pas", async () => {
    const content = await encodeOutgoing({ ...base, raw: "secret" });
    assert.equal(await decodeIncoming({ content, passphrase: PASS, context: OTHER_CTX }), null);
});

test("les messages ordinaires ne déclenchent aucun déchiffrement", async () => {
    const normaux = [
        "salut ça va ?",
        "trop drôle 😂😂🔥 j'adore",
        "regarde ❤️ c'est mignon",
        "👍",
        "```js\nconst a = 1;\n```",
        "",
        "😀😂😅😍🤔"           // quelques emojis du dictionnaire, mais pas une trame
    ];
    for (const content of normaux) {
        assert.equal(detectMode(content), null, `faux positif sur ${JSON.stringify(content)}`);
        assert.equal(await decodeIncoming({ content, ...base }), null);
    }
});

test("un caractère invisible isolé ne fait pas passer un message pour chiffré", async () => {
    // Point critique côté ENVOI : isPapotageMessage() décide de ne pas
    // re-chiffrer. Un faux positif ici enverrait le message en clair. Un
    // word-joiner ou un sélecteur de variation collé depuis une page web ne doit
    // donc jamais suffire.
    const pieges = [
        "rendez-vous⁠demain à 20h",       // word-joiner = le délimiteur lui-même
        "texte​avec‌des‍blancs", // quelques zero-width épars
        "coucou ❤️ ça va",                      // sélecteur de variation légitime
        "⁠".repeat(10),
        "a️b️c️"
    ];
    for (const content of pieges) {
        assert.equal(isPapotageMessage(content), false, `faux positif sur ${JSON.stringify(content)}`);
    }
});

test("un message réellement chiffré est bien reconnu comme tel", async () => {
    // L'autre bord du même seuil : sans ça, on re-chiffrerait un message déjà
    // chiffré à chaque édition.
    for (const mode of Object.values(MODE)) {
        const content = await encodeOutgoing({ ...base, raw: "x", mode });
        assert.equal(isPapotageMessage(content), true, `mode ${mode}`);
    }
});

test("sans mot de passe, la réception ne tente rien", async () => {
    const content = await encodeOutgoing({ ...base, raw: "secret" });
    assert.equal(await decodeIncoming({ content, passphrase: "", context: CTX }), null);
});

// --- Protection de l'édition ------------------------------------------------

test("les marqueurs d'affichage sont retirés avant de re-chiffrer", async () => {
    // 🔓 (déchiffré) comme 🔒 (illisible) sont des ajouts d'affichage : aucun
    // des deux ne doit se retrouver publié dans le salon.
    assert.equal(stripMarkers(LOCK_PREFIX + "rdv 20h"), "rdv 20h");
    assert.equal(stripMarkers("rdv 20h"), "rdv 20h");
    assert.equal(stripMarkers("🔓rdv"), "🔓rdv"); // sans l'espace, ce n'est pas le marqueur
});

test("ré-encoder un message déchiffré redonne le même clair", async () => {
    // C'est le chemin de l'édition : afficher -> éditer -> re-chiffrer.
    const clair = "le vrai contenu";
    const content = await encodeOutgoing({ ...base, raw: clair });
    const affiche = LOCK_PREFIX + await decodeIncoming({ content, ...base });
    const reencode = await encodeOutgoing({ ...base, raw: stripMarkers(affiche) });
    assert.ok(!reencode.includes(clair));
    assert.equal(await decodeIncoming({ content: reencode, ...base }), clair);
});

// --- Cache anti-rejeu -------------------------------------------------------

test("SeenCache retient un contenu déjà traité", () => {
    const c = new SeenCache();
    assert.equal(c.has("1", "abc"), false);
    c.set("1", "abc");
    assert.equal(c.has("1", "abc"), true);
    assert.equal(c.has("1", "autre chose"), false); // message édité : à retraiter
});

test("SeenCache évince les plus anciens sans tout vider", () => {
    const c = new SeenCache(10, 4);
    for (let i = 0; i < 10; i++) c.set(String(i), "x");
    c.set("10", "x");
    assert.equal(c.size, 7);            // 10 - 4 évincés + 1 nouveau
    assert.equal(c.has("0", "x"), false); // le plus ancien est parti
    assert.equal(c.has("9", "x"), true);  // le plus récent est resté
});

// --- Vérification de l'aller-retour Discord ---------------------------------
// Le codec suppose que Discord préserve les caractères invisibles. Cette
// hypothèse ne se vérifie qu'en passant par ses serveurs : le registre la
// transforme en mesure, sur chaque message envoyé.

test("un message rendu à l'identique par Discord est confirmé", async () => {
    const ledger = new SendLedger();
    const content = await encodeOutgoing({ ...base, raw: "secret", defaultCover: "ok ça marche" });
    ledger.remember(content);
    assert.equal(ledger.check(content), "ok");
});

test("un message dont Discord a retiré des caractères invisibles est signalé", async () => {
    // Le cas qu'on ne peut pas tester en local : Discord nettoie le message et
    // le destinataire ne peut plus le lire. L'expéditeur doit l'apprendre.
    const ledger = new SendLedger();
    const content = await encodeOutgoing({ ...base, raw: "secret", defaultCover: "ok ça marche" });
    ledger.remember(content);
    // Un nettoyage réaliste ne touche qu'aux invisibles, pas au texte affiché.
    const ampute = [...content].filter(c => visibleText(c) !== "").join("");
    assert.notEqual(ampute, content);
    assert.equal(ledger.check(ampute, { isOwn: true }), "altered");
});

test("le message de quelqu'un d'autre reprenant notre couverture n'alerte pas", async () => {
    // Un message dépouillé de tous ses invisibles est indiscernable d'un
    // message où quelqu'un a simplement tapé la même phrase : sans l'identité
    // de l'auteur, on alerterait à tort. D'où le drapeau isOwn.
    const ledger = new SendLedger();
    ledger.remember(await encodeOutgoing({ ...base, raw: "secret", defaultCover: "ok ça marche" }));
    for (const autre of ["salut ça va ?", "ok ça marche", ""]) {
        assert.equal(ledger.check(autre), null, `alerte à tort sur ${JSON.stringify(autre)}`);
    }
});

test("on ne prévient qu'une fois par envoi", async () => {
    // Discord peut redispatcher le même message : une seule alerte, sinon
    // l'utilisateur se prend une rafale de toasts.
    const ledger = new SendLedger();
    const content = await encodeOutgoing({ ...base, raw: "secret", defaultCover: "ok ça marche" });
    ledger.remember(content);
    const ampute = [...content].filter(c => visibleText(c) !== "").join("");
    assert.equal(ledger.check(ampute, { isOwn: true }), "altered");
    assert.equal(ledger.check(ampute, { isOwn: true }), null);
});

test("le registre reste borné", async () => {
    const ledger = new SendLedger(4);
    for (let i = 0; i < 20; i++) ledger.remember(`msg${i}`);
    assert.equal(ledger.size, 4);
});

// --- Pré-filtre : le rejet rapide ne doit jamais diverger --------------------

test("le rejet rapide donne exactement le même résultat que la boucle complète", async () => {
    // scanSymbols court-circuite les messages sans caractère candidat. Si ce
    // raccourci se désynchronisait de la boucle, des messages chiffrés
    // deviendraient invisibles au plugin — ou l'inverse. On compare les deux
    // chemins sur des entrées choisies pour tomber des deux côtés de la limite.
    const echantillons = [
        "message ordinaire en ascii",
        "français accentué : où ça, à côté ?",
        "avec un emoji 👍 dedans",
        "avec un cœur ❤️ et son sélecteur",
        "​‌‍ invisible",
        "⁠".repeat(100),
        "🏳️‍🌈👨‍👩‍👧",
        "",
        "\ud800",                       // demi-codet haut orphelin
        await encodeOutgoing({ ...base, raw: "un vrai message chiffré" }),
        await encodeOutgoing({ ...base, raw: "compact", mode: MODE.COMPACT }),
        await encodeOutgoing({ ...base, raw: "emoji", mode: MODE.EMOJI })
    ];
    for (const s of echantillons) {
        const rapide = scanSymbols(s);
        const complet = scanReference(s);
        assert.deepEqual({ ...rapide }, complet, `divergence sur ${JSON.stringify(s.slice(0, 30))}`);
    }
});

// Implémentation de référence, volontairement naïve et lente.
function scanReference(message) {
    let hidden = 0, compact = 0, run = 0, best = 0;
    for (const ch of message) {
        const cp = ch.codePointAt(0);
        let emoji = false;
        if ((cp >= 0x200b && cp <= 0x200d) || (cp >= 0x2060 && cp <= 0x2064)) hidden++;
        else if ((cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef)) compact++;
        else if (EMOJI.some(e => e.codePointAt(0) === cp)) emoji = true;
        run = emoji ? run + 1 : 0;
        if (run > best) best = run;
    }
    return { hidden, compact, emojiRun: best };
}

// --- Message chiffré mais illisible -----------------------------------------

test("un message chiffré avec une autre clé ne laisse aucune trace visible", async () => {
    // Choix délibéré : rien ne signale un message qu'on ne sait pas lire. Un
    // marqueur à l'écran trahirait l'utilisateur devant un témoin.
    for (const mode of Object.values(MODE)) {
        const content = await encodeOutgoing({ ...base, raw: "message manqué", mode });
        assert.equal(await decodeIncoming({ content, passphrase: "autre-mot-de-passe", context: CTX }), null);
        assert.ok(isPapotageMessage(content), `mode ${mode} : payload non reconnu`);
    }
});

test("un message d'un autre salon est reconnu comme chiffré mais illisible", async () => {
    const content = await encodeOutgoing({ ...base, raw: "secret" });
    assert.equal(await decodeIncoming({ content, passphrase: PASS, context: OTHER_CTX }), null);
    assert.ok(isPapotageMessage(content));
});

test("un message ordinaire n'est jamais pris pour un message chiffré", async () => {
    // Un faux positif ici ferait sauter le chiffrement à l'envoi.
    for (const content of ["salut ça va ?", "👍", "regarde ❤️ c'est mignon", "ok ça marche 👍"]) {
        assert.equal(isPapotageMessage(content), false, `faux positif sur ${JSON.stringify(content)}`);
    }
});
