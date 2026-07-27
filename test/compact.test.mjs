// Mode compact (sélecteurs de variation) : 1 octet = 1 caractère invisible.

import assert from "node:assert/strict";
import test from "node:test";

import { decodeCompact, decodeHidden, encodeCompact, encodeHidden } from "../src/codec.mjs";
import { COVER, CTX, PASS, incompressible, invisibleCount, visible } from "./helpers.mjs";

test("le texte visible est exactement la couverture", async () => {
    const cover = "ouais on se voit demain à 15h";
    const msg = await encodeCompact("secret bien planqué", PASS, { cover, context: CTX });
    assert.equal(visible(msg), cover);
    assert.equal(await decodeCompact(msg, PASS, { context: CTX }), "secret bien planqué");
});

test("une couverture avec emoji porteur d'un sélecteur légitime décode quand même", async () => {
    // ❤️ = U+2764 U+FE0F : le U+FE0F est un sélecteur de variation valide qui
    // s'ajoute au flux d'octets. Le décodeur doit se recaler sur le MAGIC.
    const msg = await encodeCompact("rdv ce soir", PASS, { cover: "trop hâte ❤️ à toute", context: CTX });
    assert.equal(await decodeCompact(msg, PASS, { context: CTX }), "rdv ce soir");
});

test("couverture finissant par un emoji", async () => {
    const msg = await encodeCompact("on se retrouve à 21h", PASS, { cover: "ok ça marche 👍", context: CTX });
    assert.equal(await decodeCompact(msg, PASS, { context: CTX }), "on se retrouve à 21h");
});

test("emojis et accents dans le secret", async () => {
    const clair = "ramène les 🍕 et on lance le film 🎬 à 20h — crêperie sinon";
    const msg = await encodeCompact(clair, PASS, { cover: COVER, context: CTX });
    assert.equal(await decodeCompact(msg, PASS, { context: CTX }), clair);
});

test("mauvaise clé => null", async () => {
    const msg = await encodeCompact("secret", PASS, { cover: COVER, context: CTX });
    assert.equal(await decodeCompact(msg, "faux", { context: CTX }), null);
});

test("message normal => null", async () => {
    assert.equal(await decodeCompact("salut ça va ❤️ les gars ?", PASS, { context: CTX }), null);
});

test("compact est ~2,7x plus court que l'invisible dense", async () => {
    // Rapport théorique : 8/3 = 2,67 caractères par octet contre 1. Comparer
    // DEUX tirages uniques ne marche plus depuis que le remplissage comporte un
    // jitter aléatoire, tiré indépendamment pour chacun : le rapport observé
    // fluctuait assez pour faire échouer le test une fois sur quatre. On compare
    // donc des moyennes, où le jitter se compense.
    const clair = incompressible(300);
    let dense = 0, compact = 0;
    for (let i = 0; i < 20; i++) {
        dense += invisibleCount(await encodeHidden(clair, PASS, { cover: "ok", bits: 3, context: CTX }));
        compact += invisibleCount(await encodeCompact(clair, PASS, { cover: "ok", context: CTX }));
    }
    assert.ok(dense / compact > 2.4, `rapport observé ${(dense / compact).toFixed(2)}`);
});

test("un très long message tient dans un seul message Discord", async () => {
    // ~1900 octets utiles : le découpage multi-messages devient inutile.
    const clair = incompressible(1800);
    const msg = await encodeCompact(clair, PASS, { cover: "ok", context: CTX });
    assert.ok(msg.length < 4000, `${msg.length} unités UTF-16`);
    assert.equal(await decodeCompact(msg, PASS, { context: CTX }), clair);
});

test("les modes ne se décodent pas entre eux", async () => {
    const compact = await encodeCompact("secret", PASS, { cover: "ok", context: CTX });
    const hidden = await encodeHidden("secret", PASS, { cover: "ok", context: CTX });
    assert.equal(await decodeHidden(compact, PASS, { context: CTX }), null);
    assert.equal(await decodeCompact(hidden, PASS, { context: CTX }), null);
});
