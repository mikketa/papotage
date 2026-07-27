// La règle de dépendance, vérifiée au lieu d'être documentée.
//
// Une architecture en couches ne tient que si quelque chose l'empêche de se
// défaire. Un commentaire ne l'empêche pas : il suffit d'un `import` pratique
// un soir de correctif urgent pour que le codec dépende de Discord, et plus
// rien ne soit testable hors du client.
//
//   index.tsx        infrastructure  — le seul à connaître Vencord
//     └──> plugin-core   application  — règles d'envoi et de réception
//            ├──> codec      encodages (octets <-> caractères)
//            │      └──> envelope   chiffrement
//            ├──> covers     phrases de couverture
//            └──> envelope
//
// Les dépendances pointent vers l'intérieur. Rien de ce qui est à l'intérieur
// ne sait ce qui l'entoure.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

const SRC = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src");

function importsDe(fichier) {
    const s = readFileSync(path.join(SRC, fichier), "utf8");
    return [...s.matchAll(/from\s+"([^"]+)"/g)].map(m => m[1]);
}

function importsLocaux(fichier) {
    return importsDe(fichier).filter(i => i.startsWith("./")).map(i => i.slice(2));
}

// Ce que chaque module a le droit d'importer. Une entrée vide = ne dépend de rien.
const AUTORISE = {
    "random.mjs": [],
    "envelope.mjs": ["random.mjs"],
    "covers.mjs": ["random.mjs"],
    "codec.mjs": ["envelope.mjs", "random.mjs"],
    "plugin-core.mjs": ["codec.mjs", "covers.mjs", "envelope.mjs"],
    "index.tsx": ["plugin-core.mjs"]
};

test("chaque module ne dépend que de ce qui lui est permis", () => {
    for (const [fichier, permis] of Object.entries(AUTORISE)) {
        for (const dep of importsLocaux(fichier)) {
            assert.ok(permis.includes(dep),
                `${fichier} importe ${dep}, qui n'est pas dans ses dépendances permises `
                + `(${permis.join(", ") || "aucune"})`);
        }
    }
});

test("Vencord n'est connu que du fichier de câblage", () => {
    // C'est la propriété qui rend tout le reste testable en Node. Si elle
    // tombe, la logique ne peut plus être exercée hors du client Discord.
    for (const fichier of Object.keys(AUTORISE)) {
        if (fichier === "index.tsx") continue;
        const externes = importsDe(fichier).filter(i => i.startsWith("@"));
        assert.deepEqual(externes, [],
            `${fichier} importe ${externes.join(", ")} : la logique ne serait plus testable hors de Discord`);
    }
});

test("le fichier de câblage ne court-circuite aucune couche", () => {
    // Il a le droit de connaître Vencord, mais pas d'aller chercher le codec ou
    // le chiffrement directement : la couche application expose ce qu'il faut.
    assert.deepEqual(importsLocaux("index.tsx"), ["plugin-core.mjs"]);
});

test("le chiffrement ignore tout de l'encodage et de l'affichage", () => {
    // `envelope.mjs` est la partie dont une erreur est irrattrapable. Elle doit
    // rester relisible seule, sans dérouler le reste du projet.
    const deps = importsLocaux("envelope.mjs");
    assert.ok(!deps.includes("codec.mjs"));
    assert.ok(!deps.includes("covers.mjs"));
    assert.ok(!deps.includes("plugin-core.mjs"));
});

test("le codec ne choisit pas ce que dit la couverture", () => {
    // Encoder est un mécanisme ; décider de la phrase affichée est une décision
    // de produit. Le codec reçoit la couverture, il ne la fabrique pas — sans
    // quoi il traînerait un paramètre `pool` qu'il ne fait que relayer.
    assert.ok(!importsLocaux("codec.mjs").includes("covers.mjs"));
});

test("aucun cycle entre modules", () => {
    const vus = new Map();
    const visite = (fichier, chemin) => {
        if (chemin.includes(fichier)) {
            assert.fail(`cycle : ${[...chemin, fichier].join(" -> ")}`);
        }
        if (vus.has(fichier)) return;
        vus.set(fichier, true);
        for (const dep of importsLocaux(fichier)) visite(dep, [...chemin, fichier]);
    };
    for (const fichier of Object.keys(AUTORISE)) visite(fichier, []);
});
