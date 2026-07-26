// Discrétion : ce que voit un observateur, et ce que trouve un détecteur.
//
// Ces tests mesurent des propriétés qui n'ont rien d'automatique et qu'une
// refactorisation peut casser sans que rien d'autre échoue. Ils sont écrits
// avec les seuils d'un détecteur générique, pas avec des valeurs arbitraires.

import assert from "node:assert/strict";
import test from "node:test";

import { PADDING, decodeCompact, decodeHidden, encodeCompact, encodeHidden, wireSize } from "../src/codec.mjs";
import { pickCover, resetCoverHistory } from "../src/covers.mjs";
import { CTX, PASS, incompressible, isSubsequence, longestInvisibleRun, visible } from "./helpers.mjs";

// --- Signatures de format ---------------------------------------------------

test("aucun marqueur fixe n'ouvre le payload", async () => {
    // v2 démarrait le payload par un U+2060 constant : une signature publique,
    // donc un détecteur à une ligne. Le premier symbole doit maintenant varier
    // d'un message à l'autre (il dépend de la découpe aléatoire).
    const premiers = new Set();
    for (let i = 0; i < 40; i++) {
        const msg = await encodeHidden("secret", PASS, { cover: "ok ça marche", context: CTX });
        premiers.add([...msg][0]);
    }
    assert.ok(premiers.size > 1, "le message commence toujours par le même caractère");
});

test("le payload ne forme plus un bloc d'un seul tenant", async () => {
    // La détection générique cherche une longue série contiguë de caractères
    // de formatage. En v2 la série faisait toute la taille du payload.
    const clair = incompressible(200);
    const msg = await encodeHidden(clair, PASS, { cover: "ouais je te suis là-dessus", context: CTX });
    const total = [...msg].length - visible(msg).length;
    const run = longestInvisibleRun(msg);
    assert.ok(run < total / 2, `série de ${run} sur ${total} symboles : trop groupé`);
});

test("le mode compact disperse aussi ses symboles", async () => {
    const msg = await encodeCompact(incompressible(200), PASS, { cover: "ok je regarde ça", context: CTX });
    const total = [...msg].length - visible(msg).length;
    assert.ok(longestInvisibleRun(msg) < total / 2, "payload compact trop groupé");
});

test("deux envois du même secret ne produisent pas la même découpe", async () => {
    const a = await encodeHidden("toujours pareil", PASS, { cover: "ok", context: CTX });
    const b = await encodeHidden("toujours pareil", PASS, { cover: "ok", context: CTX });
    assert.notEqual(a, b);
    assert.notEqual(longestInvisibleRun(a) + "|" + a.indexOf("​"),
        longestInvisibleRun(b) + "|" + b.indexOf("​"));
});

// --- Intégrité visuelle de la couverture ------------------------------------

test("la partie visible reste exactement la couverture", async () => {
    // Disperser ne doit rien faire apparaître : c'est toute la promesse.
    for (const cover of ["ok", "ouais tranquille et toi ?", "bon bah nickel 🙌"]) {
        const msg = await encodeHidden("secret", PASS, { cover, context: CTX });
        assert.equal(visible(msg), cover, `couverture "${cover}"`);
    }
});

test("le mode compact préserve les emojis composés de la couverture", async () => {
    // Insérer un symbole au milieu de « 🏳️‍🌈 » ou « 👨‍👩‍👧 » casserait le rendu.
    // La dispersion travaille par graphèmes, et le payload est posé APRÈS le
    // dernier sélecteur de la couverture pour ne pas se mélanger au sien.
    const seg = new Intl.Segmenter();
    const count = t => [...seg.segment(t)].length;
    for (const cover of ["bravo 🏳️‍🌈 voilà", "coucou 👨‍👩‍👧 ça va", "trop hâte ❤️ à toute"]) {
        const msg = await encodeCompact("secret", PASS, { cover, context: CTX });
        assert.ok(isSubsequence(cover, msg), `couverture amputée : "${cover}"`);
        assert.equal(count(msg), count(cover), `graphème coupé : "${cover}"`);
        assert.equal(await decodeCompact(msg, PASS, { context: CTX }), "secret");
    }
});

test("le mode invisible préserve les couvertures sans liant", async () => {
    for (const cover of ["trop hâte ❤️ à toute", "ok ça marche 👍", "bien vu ⚠️ attention"]) {
        const msg = await encodeHidden("secret", PASS, { cover, context: CTX });
        assert.ok(isSubsequence(cover, msg), `couverture amputée : "${cover}"`);
        assert.equal(await decodeHidden(msg, PASS, { context: CTX }), "secret");
    }
});

test("le mode invisible ampute les emojis à liant, et c'est documenté", async () => {
    // U+200D est l'un des 8 symboles de l'alphabet 3 bits : un liant laissé
    // dans la couverture se mélangerait au flux de données. On le retire, donc
    // « 👨\u200d👩\u200d👧 » se décompose en trois emojis à l'écran. Compromis assumé,
    // épinglé ici pour qu'il ne surprenne personne — la seule autre issue
    // possible serait de corrompre le payload.
    const cover = "coucou 👨\u200d👩\u200d👧 ça va";
    const msg = await encodeHidden("secret", PASS, { cover, context: CTX });
    assert.ok(!isSubsequence(cover, msg), "le liant de la couverture devrait avoir disparu");
    assert.ok(isSubsequence("coucou 👨👩👧 ça va", msg), "le reste de la couverture doit survivre");
    assert.equal(await decodeHidden(msg, PASS, { context: CTX }), "secret");
});

// --- Longueur ---------------------------------------------------------------

test("le mode paliers regroupe des secrets de tailles très différentes", async () => {
    // Sans lui, la longueur du message envoyé suit celle du secret. Avec, des
    // secrets de 10 et 40 caractères partent à la taille du même palier.
    const tailles = new Set();
    for (const n of [10, 25, 40]) {
        const msg = await encodeCompact(incompressible(n), PASS,
            { cover: "ok", context: CTX, padding: PADDING.BUCKET });
        tailles.add([...msg].length - visible(msg).length);
    }
    assert.equal(tailles.size, 1, `tailles distinctes : ${[...tailles].join(", ")}`);
});

test("le mode paliers coûte nettement plus cher, et c'est assumé", async () => {
    // 20 octets de secret : 60 octets envoyés en blocs, 92 en paliers.
    const bloc = wireSize(20, PADDING.BLOCK);
    const palier = wireSize(20, PADDING.BUCKET);
    assert.ok(palier >= bloc * 1.5, `${palier} contre ${bloc} : le palier ne coûte rien ?`);
});

test("le mode blocs reste le défaut", async () => {
    assert.equal(wireSize(20), wireSize(20, PADDING.BLOCK));
});

// --- Couvertures ------------------------------------------------------------

test("aucune répétition dans une fenêtre courte", async () => {
    // C'est la régularité la plus visible pour un humain qui lit le salon :
    // la même phrase deux fois à trois messages d'écart.
    resetCoverHistory();
    const suite = Array.from({ length: 16 }, () => pickCover());
    assert.equal(new Set(suite).size, suite.length, `répétition dans ${suite.join(" / ")}`);
});

test("les couvertures varient aussi en forme, pas seulement en mots", async () => {
    // Un fil où tous les messages font la même longueur se remarque même si le
    // vocabulaire change.
    resetCoverHistory();
    const longueurs = new Set();
    for (let i = 0; i < 120; i++) longueurs.add(pickCover().length);
    assert.ok(longueurs.size >= 15, `seulement ${longueurs.size} longueurs distinctes`);
});

test("une liste perso remplace complètement le pool intégré", async () => {
    // Le pool intégré est dans le code source, donc connu de l'adversaire.
    resetCoverHistory();
    const pool = ["à tout de suite", "je file, à plus", "ok on se capte"];
    for (let i = 0; i < 30; i++) {
        assert.ok(pool.includes(pickCover(null, { pool })), "phrase hors de la liste perso");
    }
});

test("une liste perso est utilisée telle quelle par l'encodeur", async () => {
    const pool = ["mon message de couverture à moi"];
    const msg = await encodeHidden("secret", PASS, { context: CTX, pool });
    assert.equal(visible(msg), pool[0]);
});
