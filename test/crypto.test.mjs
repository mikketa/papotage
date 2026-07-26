// Propriétés cryptographiques du format v2, indépendamment de l'encodage.
// On observe la taille de la trame via le mode compact : 1 octet = 1 caractère
// invisible, donc compter les caractères invisibles revient à compter les octets.

import assert from "node:assert/strict";
import test from "node:test";

import { encodeCompact, decodeCompact, wireSize } from "../src/codec.mjs";
import { CTX, OTHER_CTX, PASS, incompressible, invisibleCount } from "./helpers.mjs";

// Octets réellement envoyés (hors MAGIC) pour un secret donné.
async function wireBytes(text, ctx = CTX) {
    const msg = await encodeCompact(text, PASS, { cover: "ok", context: ctx });
    return invisibleCount(msg) - 1; // -1 : l'octet MAGIC
}

test("aller-retour simple", async () => {
    const clair = "rdv 20h au parc, dis rien à personne";
    const msg = await encodeCompact(clair, PASS, { context: CTX });
    assert.equal(await decodeCompact(msg, PASS, { context: CTX }), clair);
});

test("mauvaise clé => null", async () => {
    const msg = await encodeCompact("secret", PASS, { context: CTX });
    assert.equal(await decodeCompact(msg, "faux", { context: CTX }), null);
});

test("un salon ne déchiffre pas les messages d'un autre salon", async () => {
    // Le sel PBKDF2 dépend du contexte : même mot de passe, clé différente.
    const msg = await encodeCompact("le colis est sous l'escalier", PASS, { context: CTX });
    assert.equal(await decodeCompact(msg, PASS, { context: OTHER_CTX }), null);
    assert.equal(await decodeCompact(msg, PASS, { context: "" }), null);
});

test("le nonce est aléatoire : deux chiffrements du même texte diffèrent", async () => {
    const a = await encodeCompact("toujours le même message", PASS, { cover: "ok", context: CTX });
    const b = await encodeCompact("toujours le même message", PASS, { cover: "ok", context: CTX });
    assert.notEqual(a, b);
    assert.equal(invisibleCount(a), invisibleCount(b)); // même taille, contenu différent
});

test("en-tête de 28 octets : nonce 12 + tag 16", async () => {
    // 1 octet de secret => en-tête + 1 bloc de padding.
    assert.equal(await wireBytes("x"), 12 + 16 + 16);
    assert.equal(await wireBytes("x"), wireSize(1));
});

test("le padding quantifie la longueur envoyée par blocs de 16", async () => {
    // Des secrets de 1 à 14 octets partent tous à la même taille : la longueur
    // exacte du message ne fuite plus au caractère près.
    const sizes = new Set();
    for (let n = 1; n <= 14; n++) sizes.add(await wireBytes(incompressible(n)));
    assert.equal(sizes.size, 1, `tailles observées : ${[...sizes].join(", ")}`);

    // Et le bloc suivant s'ouvre bien 16 octets plus loin.
    assert.equal(await wireBytes(incompressible(20)) - await wireBytes(incompressible(4)), 16);
});

test("wireSize() prédit la taille réelle", async () => {
    for (const n of [1, 15, 16, 31, 100]) {
        assert.equal(await wireBytes(incompressible(n)), wireSize(n),
            `désaccord pour n=${n}`);
    }
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
