// Les phrases de couverture sont ce qu'un observateur voit vraiment : leur
// variété est une propriété de sécurité, pas de la cosmétique.

import assert from "node:assert/strict";
import test from "node:test";

import { COVER_POOL_SIZE, MAX_AUTO_COVER_LEN, pickCover } from "../src/covers.mjs";

test("une couverture perso est reprise telle quelle, sans espaces parasites", () => {
    assert.equal(pickCover("  ouais on se voit demain  "), "ouais on se voit demain");
});

test("une couverture vide ou blanche bascule sur le tirage auto", () => {
    for (const custom of [undefined, null, "", "   "]) {
        assert.ok(pickCover(custom).length > 0);
    }
});

test("le pool dépasse 300 combinaisons", () => {
    // Un pool de 15 phrases finissait par signer le canal : la même poignée de
    // réponses, toujours suivie de centaines de caractères invisibles.
    assert.ok(COVER_POOL_SIZE > 300, `${COVER_POOL_SIZE} combinaisons`);
});

test("200 tirages donnent au moins 50 couvertures distinctes", () => {
    const vues = new Set();
    for (let i = 0; i < 200; i++) vues.add(pickCover());
    assert.ok(vues.size >= 50, `${vues.size} couvertures distinctes sur 200 tirages`);
});

test("MAX_AUTO_COVER_LEN majore vraiment les couvertures tirées", () => {
    // Sert à réserver la place dans le budget de caractères : s'il sous-estime,
    // un message peut dépasser la limite Discord.
    for (let i = 0; i < 500; i++) {
        assert.ok(pickCover().length <= MAX_AUTO_COVER_LEN);
    }
});

test("aucune couverture ne contient de caractère invisible", () => {
    // Un zero-width dans la couverture piégerait le délimiteur du payload.
    for (let i = 0; i < 300; i++) {
        assert.ok(!/[\u200B-\u200D\u2060-\u2064]/.test(pickCover()));
    }
});
