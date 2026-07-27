// Mode invisible (zero-width) : le mode par défaut du plugin.

import assert from "node:assert/strict";
import test from "node:test";

import { decodeHidden, encodeHidden } from "../src/codec.mjs";
import { COVER, CTX, PASS, invisibleCount, len, visible } from "./helpers.mjs";

test("aller-retour, et la partie visible se limite à la couverture", async () => {
    const clair = "rdv 20h au parc, dis rien à personne";
    const msg = await encodeHidden(clair, PASS, { cover: "ok", context: CTX });
    assert.equal(visible(msg), "ok");
    assert.equal(await decodeHidden(msg, PASS, { context: CTX }), clair);
});

test("accents et emojis dans le secret", async () => {
    const clair = "T'inquiète, j'ai géré 😏 rendez-vous à la crêperie";
    const msg = await encodeHidden(clair, PASS, { cover: COVER, context: CTX });
    assert.equal(await decodeHidden(msg, PASS, { context: CTX }), clair);
});

test("mauvaise clé => null", async () => {
    const msg = await encodeHidden("secret", PASS, { cover: COVER, context: CTX });
    assert.equal(await decodeHidden(msg, "faux", { context: CTX }), null);
});

test("message normal sans payload => null", async () => {
    assert.equal(await decodeHidden("salut ça va les gars ?", PASS, { context: CTX }), null);
});

test("une couverture contenant déjà des invisibles ne corrompt pas le payload", async () => {
    // Texte copié depuis une page web, ancien message réutilisé : les symboles
    // parasites sont retirés de la couverture avant dispersion, sinon ils se
    // mélangeraient au flux de données.
    const clair = "mon secret";
    const coverSale = "salut\u2060ça\u200bva\u200d bien";
    for (const bits of [2, 3]) {
        const msg = await encodeHidden(clair, PASS, { cover: coverSale, bits, context: CTX });
        assert.equal(await decodeHidden(msg, PASS, { context: CTX }), clair, `bits=${bits}`);
    }
});

test("la densité est auto-détectée à la réception", async () => {
    const clair = "message de test un peu long pour bien remplir le payload invisible";
    for (const bits of [2, 3]) {
        const msg = await encodeHidden(clair, PASS, { cover: "ok", bits, context: CTX });
        assert.equal(await decodeHidden(msg, PASS, { context: CTX }), clair, `bits=${bits}`);
    }
});

test("3 bits envoie ~33 % de caractères invisibles en moins que 2 bits", async () => {
    // Le remplissage comporte un jitter aléatoire, tiré indépendamment pour
    // chaque message : comparer deux tirages uniques faisait échouer ce test une
    // fois sur six. On compare des moyennes, où le jitter se compense.
    const clair = "rendez-vous ce soir même endroit, ramène le matériel et préviens les autres";
    let inv2 = 0, inv3 = 0;
    for (let i = 0; i < 20; i++) {
        inv2 += invisibleCount(await encodeHidden(clair, PASS, { cover: "ok", bits: 2, context: CTX }));
        inv3 += invisibleCount(await encodeHidden(clair, PASS, { cover: "ok", bits: 3, context: CTX }));
    }
    const gain = Math.round((1 - inv3 / inv2) * 100);
    assert.ok(gain >= 25, `gain moyen trop faible : ${gain} %`);
});

test("du texte ajouté après le payload ne casse pas le décodage", async () => {
    // Un message édité ("... (modifié)"), une signature de bot : le décodeur ne
    // garde que les symboles de son alphabet.
    const clair = "on se voit à 14h";
    const msg = await encodeHidden(clair, PASS, { cover: "ok", context: CTX });
    assert.equal(await decodeHidden(msg + " (edit)", PASS, { context: CTX }), clair);
});

test("budget Discord : 400 caractères de secret tiennent sous 2000", async () => {
    const clair = "x".repeat(400);
    const msg = await encodeHidden(clair, PASS, { cover: "mdr", bits: 3, context: CTX });
    assert.ok(len(msg) < 2000, `trop long : ${len(msg)}`);
    assert.equal(await decodeHidden(msg, PASS, { context: CTX }), clair);
});
