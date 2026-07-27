// Discrétion : ce que voit un observateur, et ce que trouve un détecteur.
//
// Ces tests mesurent des propriétés qui n'ont rien d'automatique et qu'une
// refactorisation peut casser sans que rien d'autre échoue. Ils sont écrits
// avec les seuils d'un détecteur générique, pas avec des valeurs arbitraires.

import assert from "node:assert/strict";
import test from "node:test";

import { PADDING, decodeCompact, decodeHidden, encodeCompact, encodeHidden, wireSize } from "../src/codec.mjs";
import { pickCover, resetCoverHistory } from "../src/covers.mjs";
import { CTX, PASS, ZW_SYMBOLS, incompressible, isSubsequence, longestInvisibleRun, visible } from "./helpers.mjs";

// --- Signatures de format ---------------------------------------------------

test("le message commence toujours par du texte visible", async () => {
    // Un message Discord ordinaire ne commence jamais par un caractère
    // invisible. En v3 la dispersion en plaçait avant la couverture dans 90 %
    // des cas (mesuré) : un détecteur d'une ligne, `/^[\u200B-\u2064]/`.
    for (let i = 0; i < 60; i++) {
        const msg = await encodeHidden("secret", PASS, { context: CTX });
        assert.ok(!ZW_SYMBOLS.includes([...msg][0]),
            `message ${i} commençant par un invisible : ${JSON.stringify(msg.slice(0, 8))}`);
    }
});

test("aucun symbole constant n'ouvre le payload", async () => {
    // Régression : jusqu'en v3 le payload débutait par un en-tête de densité
    // constant, donc le premier caractère invisible de TOUT message valait
    // ZW[1] en 3 bits — 400 fois sur 400. Le marqueur avait changé de place,
    // pas disparu. Le premier symbole doit maintenant balayer tout l'alphabet.
    const vus = new Set();
    for (let i = 0; i < 200; i++) {
        const msg = await encodeHidden("secret", PASS, { cover: "ok ça marche", context: CTX });
        vus.add(ZW_SYMBOLS.indexOf([...msg].find(c => ZW_SYMBOLS.includes(c))));
    }
    // 8 valeurs équiprobables sur 200 tirages : en manquer 3 est hors d'atteinte
    // (probabilité < 1e-9), le test n'est pas capricieux pour autant.
    assert.ok(vus.size >= 6, `seulement ${vus.size} valeurs distinctes : ${[...vus].sort()}`);
});

test("le payload ne forme plus un bloc d'un seul tenant", async () => {
    // La détection générique cherche une longue série contiguë de caractères de
    // formatage. En v2 la série faisait toute la taille du payload.
    // Seuil fondé sur la mesure : moyenne 0,149, p99 0,280, maximum observé
    // 0,356 sur 300 tirages. Assertion sur la MOYENNE d'un échantillon, qui se
    // concentre — contrairement à un tirage unique, qui rendait le test flaky.
    const clair = incompressible(200);
    const ratios = [];
    for (let i = 0; i < 30; i++) {
        const msg = await encodeHidden(clair, PASS, { cover: "ouais je te suis là-dessus", context: CTX });
        const total = [...msg].length - visible(msg).length;
        ratios.push(longestInvisibleRun(msg) / total);
    }
    const moyenne = ratios.reduce((a, b) => a + b, 0) / ratios.length;
    assert.ok(moyenne < 0.30, `série moyenne = ${(moyenne * 100).toFixed(1)} % du payload : trop groupé`);
});

test("le mode compact disperse aussi ses symboles", async () => {
    const ratios = [];
    for (let i = 0; i < 20; i++) {
        const msg = await encodeCompact(incompressible(200), PASS, { cover: "ok je regarde ça", context: CTX });
        const total = [...msg].length - visible(msg).length;
        ratios.push(longestInvisibleRun(msg) / total);
    }
    const moyenne = ratios.reduce((a, b) => a + b, 0) / ratios.length;
    assert.ok(moyenne < 0.35, `payload compact groupé à ${(moyenne * 100).toFixed(1)} %`);
});

test("deux envois du même secret ne produisent pas la même découpe", async () => {
    // Mesuré : 40 envois donnent 40 textes distincts et 24 longueurs de série
    // distinctes. Comparer deux messages sur une empreinte à deux valeurs, comme
    // avant, pouvait coïncider — d'où un test capricieux.
    const textes = new Set(), formes = new Set();
    for (let i = 0; i < 40; i++) {
        const msg = await encodeHidden("toujours pareil", PASS, { cover: "ok ça marche", context: CTX });
        textes.add(msg);
        formes.add(longestInvisibleRun(msg));
    }
    assert.equal(textes.size, 40, "deux envois identiques au caractère près");
    assert.ok(formes.size >= 10, `seulement ${formes.size} découpes distinctes sur 40`);
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
    // Comparer le texte VISIBLE, pas une sous-séquence : le payload dispersé
    // contient lui-même des liants, et l'un d'eux pourrait tomber entre deux
    // emojis et satisfaire la recherche par hasard. La règle est déterministe.
    assert.equal(visible(msg), "coucou 👨👩👧 ça va");
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
