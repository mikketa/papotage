// L'adversaire, écrit pour nous-mêmes.
//
//   npm run audit
//
// Les deux dernières signatures trouvées dans ce projet (l'en-tête de densité
// constant, le message commençant par un invisible) n'ont pas été repérées en
// relisant le code : elles sont sorties d'une mesure. Cet outil systématise la
// démarche — il produit un échantillon de messages et cherche dedans tout ce
// qu'un détecteur chercherait. Chaque ligne « ALERTE » est un défaut à corriger.
//
// L'audit emprunte le VRAI chemin de sélection de couverture. Le figer sur une
// phrase unique l'aveugle : c'est ce qui lui a fait manquer, une fois, que les
// couvertures courtes ne laissent pas de place pour disperser le payload.
//
// Ce qu'un détecteur exploite, par ordre de facilité :
//   1. une valeur constante quelque part (marqueur, en-tête, position) ;
//   2. une position privilégiée (début, fin de message) ;
//   3. une distribution non uniforme des symboles ;
//   4. un ensemble restreint de valeurs possibles (longueurs quantifiées).

import { encodeCompact, encodeHidden } from "../src/codec.mjs";
import { pickCover } from "../src/covers.mjs";
import { CTX, PASS, ZW_SYMBOLS, longestInvisibleRun } from "../test/helpers.mjs";

const N = 600;
const VS = /[\u{FE00}-\u{FE0F}]|[\u{E0100}-\u{E01EF}]/u;
const alertes = [];

function verdict(ok, libelle, detail) {
    if (!ok) alertes.push(libelle);
    console.log(`  ${ok ? "ok    " : "ALERTE"}  ${libelle.padEnd(46)} ${detail}`);
}

function pourcent(n, total) {
    return `${((n / total) * 100).toFixed(1)} %`;
}

async function echantillon(encode, secret) {
    const out = [];
    for (let i = 0; i < N; i++) out.push(await encode(secret));
    return out;
}

function analyse(nom, messages, estSymbole) {
    console.log(`\n=== ${nom} (${messages.length} messages) ===`);

    // 1. positions privilégiées
    const debut = messages.filter(m => estSymbole([...m][0])).length;
    const fin = messages.filter(m => estSymbole([...m].at(-1))).length;
    verdict(debut === 0, "aucun message ne COMMENCE par un symbole", pourcent(debut, messages.length));
    verdict(fin === 0, "aucun message ne FINIT par un symbole", pourcent(fin, messages.length));

    // 2. valeur constante en tête de payload
    const premiers = new Map();
    for (const m of messages) {
        const s = [...m].find(estSymbole);
        premiers.set(s, (premiers.get(s) ?? 0) + 1);
    }
    const dominant = Math.max(...premiers.values());
    verdict(dominant < messages.length * 0.5, "le 1er symbole n'est pas une constante",
        `${premiers.size} valeurs, la plus fréquente à ${pourcent(dominant, messages.length)}`);

    // 3. uniformité des symboles (mode invisible seulement : alphabet connu)
    if (estSymbole === estZW) {
        const compte = new Array(8).fill(0);
        let total = 0;
        for (const m of messages) {
            for (const c of m) {
                const i = ZW_SYMBOLS.indexOf(c);
                if (i >= 0) { compte[i]++; total++; }
            }
        }
        // L'uniformité se juge sur l'alphabet RÉELLEMENT employé : le mode
        // 2 bits n'utilise que 4 symboles sur 8, ce n'est pas un défaut.
        const utilises = compte.filter(c => c > 0);
        const attendu = total / utilises.length;
        const ecart = Math.max(...utilises.map(c => Math.abs(c - attendu) / attendu));
        verdict(ecart < 0.05, `les ${utilises.length} symboles employés sont équiprobables`,
            `écart max à l'uniforme : ${(ecart * 100).toFixed(2)} %`);
    }

    // 4. longueurs quantifiées : combien de tailles distinctes pour un même secret ?
    const tailles = new Set(messages.map(m => [...m].filter(estSymbole).length));
    verdict(tailles.size > 1, "la taille du payload n'est pas unique",
        `${tailles.size} valeurs distinctes : ${[...tailles].sort((a, b) => a - b).slice(0, 6).join(", ")}`);

    // 5. découpe : la plus longue série contiguë
    const runs = messages.map(m => longestInvisibleRun(m, estSymbole));
    const totaux = messages.map(m => [...m].filter(estSymbole).length);
    const moyRun = runs.reduce((a, b) => a + b, 0) / runs.length;
    const totalMoy = totaux.reduce((a, b) => a + b, 0) / totaux.length;
    verdict(moyRun / totalMoy < 0.35, "le payload n'est pas groupé en un bloc",
        `série moyenne = ${pourcent(moyRun, totalMoy)} du payload`);

    // La moyenne ne suffit pas : un détecteur n'a besoin que des messages qui
    // sortent du lot. Une moyenne de 27 % masquait 2 % de messages en un seul
    // bloc — c'est précisément ce qui a laissé passer une régression.
    const ratios = runs.map((r, i) => r / totaux[i]).sort((a, b) => a - b);
    const bloc = ratios.filter(r => r > 0.9).length;
    verdict(bloc === 0, "AUCUN message n'est groupé en un seul bloc",
        `${bloc}/${messages.length} au-delà de 90 %, pire cas ${pourcent(ratios.at(-1), 1)}`);
    verdict(ratios[Math.floor(0.99 * (ratios.length - 1))] < 0.75, "le 99e centile reste dispersé",
        `p99 = ${pourcent(ratios[Math.floor(0.99 * (ratios.length - 1))], 1)}`);

    // 6. les messages sont-ils tous distincts ?
    verdict(new Set(messages).size === messages.length, "aucun message identique à un autre",
        `${new Set(messages).size}/${messages.length} distincts`);
}

const estZW = c => c !== undefined && ZW_SYMBOLS.includes(c);
const estVS = c => c !== undefined && VS.test(c);

console.log("Audit stéganographique — chaque ALERTE est une régularité exploitable.");

analyse("mode invisible dense (3 bits)",
    await echantillon(s => encodeHidden(s, PASS, { cover: pickCover(), context: CTX }), "rendez-vous à 20h"), estZW);

analyse("mode invisible sûr (2 bits)",
    await echantillon(s => encodeHidden(s, PASS, { cover: pickCover(), bits: 2, context: CTX }), "rendez-vous à 20h"), estZW);

analyse("mode compact (sélecteurs de variation)",
    await echantillon(s => encodeCompact(s, PASS, { cover: pickCover(), context: CTX }), "rendez-vous à 20h"), estVS);

console.log(`\n${alertes.length === 0 ? "Aucune régularité détectée." : `${alertes.length} régularité(s) exploitable(s) :`}`);
for (const a of alertes) console.log(`  - ${a}`);
process.exit(alertes.length ? 1 : 0);
