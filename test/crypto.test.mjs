// Propriétés cryptographiques du format v4, indépendamment de l'encodage.
// On observe la taille de la trame via le mode compact : 1 octet = 1 caractère
// invisible, donc compter les caractères invisibles revient à compter les octets.

import assert from "node:assert/strict";
import test from "node:test";

import { decodeCompact, encodeCompact } from "../src/codec.mjs";
import { wireSize, wireSizeMax } from "../src/envelope.mjs";
import { COVER, CTX, OTHER_CTX, PASS, incompressible, invisibleCount } from "./helpers.mjs";

// Octets réellement envoyés pour un secret donné. Le mode compact code un octet
// par caractère invisible, et sa trame n'a plus d'octet de repère depuis la v4.
async function wireBytes(text, ctx = CTX) {
    const msg = await encodeCompact(text, PASS, { cover: "ok", context: ctx });
    return invisibleCount(msg);
}

test("aller-retour simple", async () => {
    const clair = "rdv 20h au parc, dis rien à personne";
    const msg = await encodeCompact(clair, PASS, { cover: COVER, context: CTX });
    assert.equal(await decodeCompact(msg, PASS, { context: CTX }), clair);
});

test("mauvaise clé => null", async () => {
    const msg = await encodeCompact("secret", PASS, { cover: COVER, context: CTX });
    assert.equal(await decodeCompact(msg, "faux", { context: CTX }), null);
});

test("un salon ne déchiffre pas les messages d'un autre salon", async () => {
    // Le sel PBKDF2 dépend du contexte : même mot de passe, clé différente.
    const msg = await encodeCompact("le colis est sous l'escalier", PASS, { cover: COVER, context: CTX });
    assert.equal(await decodeCompact(msg, PASS, { context: OTHER_CTX }), null);
    assert.equal(await decodeCompact(msg, PASS, { context: "" }), null);
});

test("le nonce est aléatoire : deux chiffrements du même texte diffèrent", async () => {
    // Sur 20 envois du même texte, aucun message identique. La TAILLE varie
    // aussi désormais (jitter de padding) : c'est voulu, elle ne doit plus
    // permettre de reconnaître un message répété.
    const vus = new Set();
    for (let i = 0; i < 20; i++) {
        vus.add(await encodeCompact("toujours le même message", PASS, { cover: "ok", context: CTX }));
    }
    assert.equal(vus.size, 20);
});

test("en-tête de 28 octets : nonce 12 + tag 16", async () => {
    // 1 octet de secret => en-tête + 1 bloc de padding, plus 0 à 2 blocs de
    // jitter. La borne basse est donc 12 + 16 + 16.
    const n = await wireBytes("x");
    assert.ok(n >= 12 + 16 + 16 && n <= 12 + 16 + 16 * 3, `${n} octets`);
});

test("le padding quantifie la longueur envoyée par blocs de 16", async () => {
    // La longueur exacte du secret ne fuite plus : elle est arrondie au bloc.
    // Toutes les tailles observées sont des multiples de 16 au-dessus de
    // l'en-tête, quel que soit le jitter tiré.
    for (let n = 1; n <= 14; n++) {
        const taille = await wireBytes(incompressible(n));
        assert.equal((taille - 28) % 16, 0, `n=${n} donne ${taille} octets`);
    }
});

test("wireSize() encadre la taille réelle", async () => {
    // Le jitter rend la taille non déterministe — c'est le but : deux envois du
    // même secret ne se reconnaissent plus à leur longueur. wireSize donne le
    // plancher, wireSizeMax le plafond.
    for (const n of [1, 15, 16, 31, 100]) {
        for (let essai = 0; essai < 8; essai++) {
            const taille = await wireBytes(incompressible(n));
            assert.ok(taille >= wireSize(n) && taille <= wireSizeMax(n),
                `n=${n} : ${taille} hors de [${wireSize(n)}, ${wireSizeMax(n)}]`);
        }
    }
});

test("un même secret ne produit pas toujours la même taille", async () => {
    // Sans jitter, deux envois du même texte avaient exactement la même
    // longueur : un observateur pouvait confirmer une répétition sans rien lire.
    const tailles = new Set();
    for (let i = 0; i < 40; i++) tailles.add(await wireBytes("rendez-vous à 20h"));
    assert.ok(tailles.size > 1, `taille toujours identique : ${[...tailles]}`);
});

test("un octet modifié invalide la trame (tag 128 bits)", async () => {
    const clair = "message authentifié";
    const msg = await encodeCompact(clair, PASS, { cover: "ok", context: CTX });
    const chars = [...msg];
    // Le dernier caractère invisible fait partie du tag : le tordre doit tout casser.
    chars[chars.length - 1] = chars[chars.length - 2];
    assert.equal(await decodeCompact(chars.join(""), PASS, { context: CTX }), null);
});

test("trame tronquée => null, sans exception", async () => {
    const msg = await encodeCompact("secret", PASS, { cover: "ok", context: CTX });
    const chars = [...msg];
    for (const keep of [1, 5, 20, chars.length - 5]) {
        const cut = chars.slice(0, keep).join("");
        assert.equal(await decodeCompact(cut, PASS, { context: CTX }), null);
    }
});

test("le clair n'apparaît jamais dans le message envoyé", async () => {
    const clair = "rendez-vous jeudi 21h";
    const msg = await encodeCompact(clair, PASS, { cover: "ok ça marche", context: CTX });
    assert.ok(!msg.includes(clair));
    assert.ok(!msg.includes("jeudi"));
});
