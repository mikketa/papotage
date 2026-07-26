// Mode emoji : les emojis visibles portent le secret.

import assert from "node:assert/strict";
import test from "node:test";

import { decodeEmoji, encodeEmoji } from "../src/codec.mjs";
import { CTX, PASS } from "./helpers.mjs";

test("aller-retour simple", async () => {
    const clair = "rdv 20h";
    const msg = await encodeEmoji(clair, PASS, { context: CTX });
    assert.equal(await decodeEmoji(msg, PASS, { context: CTX }), clair);
});

test("accents et emojis dans le secret", async () => {
    const clair = "ramène la clé 🔑 à 14h précises";
    const msg = await encodeEmoji(clair, PASS, { context: CTX });
    assert.equal(await decodeEmoji(msg, PASS, { context: CTX }), clair);
});

test("couverture texte en préfixe", async () => {
    const msg = await encodeEmoji("le code c'est 4271", PASS, { cover: "ptdr regarde ça", context: CTX });
    assert.ok(msg.startsWith("ptdr regarde ça "));
    assert.equal(await decodeEmoji(msg, PASS, { context: CTX }), "le code c'est 4271");
});

test("une couverture contenant un faux MAGIC (👀😡) décode quand même", async () => {
    // Régression : 0xC7 se rend 👀😡. Une couverture avec ces emojis insérait un
    // faux point de départ ; le décodeur doit itérer jusqu'au vrai.
    for (const cover of ["👀😡 lol", "regarde 🔥💀 ça", "😀 test 💯"]) {
        const msg = await encodeEmoji("code", PASS, { cover, context: CTX });
        assert.equal(await decodeEmoji(msg, PASS, { context: CTX }), "code", `couverture "${cover}"`);
    }
});

test("mauvaise clé => null", async () => {
    const msg = await encodeEmoji("secret", PASS, { context: CTX });
    assert.equal(await decodeEmoji(msg, "faux", { context: CTX }), null);
});

test("message normal avec des emojis => null, pas de crash", async () => {
    assert.equal(await decodeEmoji("trop drôle 😂😂🔥 j'adore", PASS, { context: CTX }), null);
});

test("le travail reste borné sur une entrée hostile", async () => {
    // Une avalanche de faux MAGIC ne doit pas déclencher des milliers de
    // déchiffrements : ATTEMPT_CAP borne les essais.
    const hostile = "👀😡".repeat(500);
    const t0 = process.hrtime.bigint();
    assert.equal(await decodeEmoji(hostile, PASS, { context: CTX }), null);
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    assert.ok(ms < 1000, `${ms.toFixed(0)} ms pour rejeter une entrée hostile`);
});
