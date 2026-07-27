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
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

const SRC = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src");

// Ce que chaque module a le droit d'importer. Une liste vide = ne dépend de rien.
// Ce tableau EST la spécification : les commentaires ci-dessus la décrivent, lui
// seul la fait respecter.
const AUTORISE = {
    "random.mjs": [],
    "graphemes.mjs": [],
    // Le chiffrement ignore l'encodage et l'affichage : c'est ce qui permet de
    // le relire seul, sans dérouler le reste du projet.
    "envelope.mjs": ["random.mjs"],
    "covers.mjs": ["graphemes.mjs", "random.mjs"],
    // Le codec n'importe PAS covers : encoder est un mécanisme, choisir la
    // phrase affichée est une décision de produit. Les mélanger lui rendrait un
    // paramètre `pool` qu'il ne ferait que relayer.
    "codec.mjs": ["envelope.mjs", "graphemes.mjs", "random.mjs"],
    "plugin-core.mjs": ["codec.mjs", "covers.mjs", "envelope.mjs"],
    "index.tsx": ["plugin-core.mjs"]
};

// Reconnaît les cinq façons d'importer en JavaScript, pas seulement celle qu'on
// utilise aujourd'hui : guillemets simples ou doubles, import pour effet de
// bord, `export ... from`, et `import()` dynamique. Un contrôle qui ne voit
// qu'une forme se contourne sans le vouloir.
const FORMES = [
    /(?:^|\s)(?:import|export)[\s\S]*?from\s*["']([^"']+)["']/g,
    /(?:^|\s)import\s*["']([^"']+)["']/g,
    /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g
];

function importsDe(fichier) {
    const s = readFileSync(path.join(SRC, fichier), "utf8");
    const out = new Set();
    for (const re of FORMES) for (const m of s.matchAll(re)) out.add(m[1]);
    return [...out];
}

const estLocal = i => i.startsWith(".");
const nomLocal = i => i.replace(/^\.+\//, "");

test("aucun fichier source n'échappe aux règles", () => {
    // Le trou que ce test comble : les autres parcourent AUTORISE, pas le
    // disque. Un fichier ajouté et non déclaré n'était donc soumis à rien — il
    // pouvait importer Vencord et la suite restait verte. Or un correctif
    // pressé arrive justement sous forme de nouveau fichier.
    const surDisque = readdirSync(SRC).filter(f => /\.(mjs|tsx?)$/.test(f)).sort();
    assert.deepEqual(surDisque, Object.keys(AUTORISE).sort(),
        "src/ et la table AUTORISE divergent : déclare le nouveau module (et ses dépendances permises)");
});

test("chaque module ne dépend que de ce qui lui est permis", () => {
    for (const [fichier, permis] of Object.entries(AUTORISE)) {
        for (const dep of importsDe(fichier).filter(estLocal).map(nomLocal)) {
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
        const externes = importsDe(fichier).filter(i => !estLocal(i));
        assert.deepEqual(externes, [],
            `${fichier} importe ${externes.join(", ")} : la logique ne serait plus testable hors de Discord`);
    }
});

test("le fichier de câblage ne court-circuite aucune couche", () => {
    // Il a le droit de connaître Vencord, mais pas d'aller chercher le codec ou
    // le chiffrement directement : la couche application expose ce qu'il faut.
    assert.deepEqual(importsDe("index.tsx").filter(estLocal).map(nomLocal), ["plugin-core.mjs"]);
});

test("la table de dépendances est elle-même sans cycle", () => {
    // Vérifier le graphe réel ne prouverait rien : le test précédent le contraint
    // déjà à être un sous-graphe de la table. C'est la TABLE qu'un humain peut
    // rendre cyclique en y ajoutant une ligne, donc c'est elle qu'on vérifie.
    const vus = new Set();
    const visite = (fichier, chemin) => {
        assert.ok(!chemin.includes(fichier), `cycle : ${[...chemin, fichier].join(" -> ")}`);
        if (vus.has(fichier)) return;
        vus.add(fichier);
        for (const dep of AUTORISE[fichier] ?? []) visite(dep, [...chemin, fichier]);
    };
    for (const fichier of Object.keys(AUTORISE)) visite(fichier, []);
});
