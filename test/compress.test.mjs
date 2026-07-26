// Compression : chaque octet économisé vaut 2,7 à 4 caractères invisibles.

import assert from "node:assert/strict";
import test from "node:test";

import { decodeHidden, encodeHidden, wireSize } from "../src/codec.mjs";
import { CTX, PASS, incompressible, invisibleCount } from "./helpers.mjs";

// Message long et redondant, typique d'un vrai échange.
const LONG = "on se retrouve demain à quatorze heures devant le lycée comme d'habitude, "
    + "préviens les autres qu'on part ensemble et qu'on prend le bus de la ligne, "
    + "n'oublie pas tes affaires et surtout dis rien à personne d'accord ?";

test("aller-retour d'un long message compressible", async () => {
    const msg = await encodeHidden(LONG, PASS, { context: CTX });
    assert.equal(await decodeHidden(msg, PASS, { context: CTX }), LONG);
});

test("la compression réduit vraiment la taille envoyée", async () => {
    const octets = new TextEncoder().encode(LONG).length;
    const sans = Math.ceil(wireSize(octets) * 8 / 3); // sans compression, 3 bits/car
    const avec = invisibleCount(await encodeHidden(LONG, PASS, { cover: "ok", context: CTX }));
    assert.ok(avec < sans, `${avec} caractères contre ${sans} attendus sans compression`);
});

test("un texte peu compressible n'est jamais gonflé par la compression", async () => {
    // deflate peut grossir sur du bruit : le codec ne garde le résultat compressé
    // que s'il est plus petit, donc on ne dépasse jamais la taille brute.
    const clair = incompressible(200);
    const octets = new TextEncoder().encode(clair).length;
    const plafond = Math.ceil(wireSize(octets) * 8 / 3) + 1; // +1 : en-tête de densité
    const msg = await encodeHidden(clair, PASS, { cover: "ok", context: CTX });
    assert.ok(invisibleCount(msg) <= plafond, `${invisibleCount(msg)} > ${plafond}`);
    assert.equal(await decodeHidden(msg, PASS, { context: CTX }), clair);
});

test("message court : aller-retour intact", async () => {
    const msg = await encodeHidden("ok", PASS, { context: CTX });
    assert.equal(await decodeHidden(msg, PASS, { context: CTX }), "ok");
});

test("mauvaise clé sur un message compressé => null", async () => {
    const msg = await encodeHidden(LONG, PASS, { context: CTX });
    assert.equal(await decodeHidden(msg, "faux", { context: CTX }), null);
});

test("un texte redondant de 1500 caractères tient sous la limite Discord", async () => {
    // Sans compression, 1500 octets coûteraient ~4000 caractères invisibles.
    const clair = "rendez-vous ce soir même endroit ".repeat(47).slice(0, 1500);
    const msg = await encodeHidden(clair, PASS, { cover: "mdr", context: CTX });
    assert.ok(msg.length < 2000, `${msg.length} caractères`);
    assert.equal(await decodeHidden(msg, PASS, { context: CTX }), clair);
});
