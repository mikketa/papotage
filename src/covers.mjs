// Phrases de couverture : ce que voit un observateur qui n'a pas le plugin.
//
// Le point faible d'un canal stéganographique, ce n'est pas le chiffrement,
// c'est la régularité. Trois régularités se repèrent à l'œil nu, sans aucun
// outil, juste en lisant le salon :
//
//   1. le vocabulaire — toujours les mêmes phrases ;
//   2. la FORME — toujours la même longueur, la même structure ;
//   3. la répétition rapprochée — deux fois la même phrase à trois messages
//      d'écart, ce qu'un tirage aléatoire uniforme produit très vite.
//
// D'où : plusieurs gabarits de phrase (du "ok" sec à la question complète),
// composés à partir de pools séparés, et une mémoire des derniers tirages pour
// ne pas se répéter. Un utilisateur qui préfère ses propres phrases peut
// fournir sa liste : le pool ci-dessous est public, donc connu de l'adversaire.

import { pickOne as pick, randomInt } from "./random.mjs";

const SHORT = [
    "ok", "ouais", "mdr", "ah ok", "hmm", "jsp", "carrément", "ptdr",
    "grave", "clair", "ça marche", "nickel", "ah bon", "yes", "bah ouais",
    "mouais", "ah si", "voilà", "exact", "tranquille"
];

const OPENERS = [
    "ok ça marche",
    "ah ouais carrément",
    "mdr t'es sérieux",
    "ouais je te suis là-dessus",
    "franchement pas faux",
    "haha ok je note",
    "nickel on fait comme ça",
    "attends je check et je reviens",
    "ptdr ouais grave",
    "hmm ok pourquoi pas",
    "genre ouais je vois",
    "bah écoute ça me va",
    "ah d'accord je comprends mieux",
    "oui oui t'inquiète",
    "mouais à voir",
    "ok reçu",
    "ah bah tiens",
    "bon bah nickel",
    "j'avoue ouais",
    "ah mais oui suis bête",
    "ouais non t'as raison",
    "attends deux secondes",
    "ok je regarde ça",
    "haha n'importe quoi",
    "bon ok ça marche pour moi",
    "ouais enfin bon",
    "ah ok je vois le truc",
    "mdr arrête",
    "ouais c'est clair",
    "bah oui logique",
    "ok noté merci",
    "hmm je sais pas trop",
    "ah si si je me souviens",
    "ouais ça se tente",
    "bon on verra bien",
    "ok parfait",
    "ah mince ok",
    "ouais pas de souci",
    "bon bref",
    "ah ouais quand même"
];

// Deuxième proposition, pour les gabarits en deux temps.
const FOLLOWS = [
    "je te redis",
    "on verra",
    "faut voir",
    "j'y pense",
    "je note",
    "ça marche",
    "pas de souci",
    "je te tiens au courant",
    "à voir demain",
    "on en reparle",
    "je check",
    "faut que j'y réfléchisse"
];

const QUESTIONS = [
    "t'en penses quoi ?",
    "tu fais quoi ce soir ?",
    "c'est bon pour toi ?",
    "on dit quoi du coup ?",
    "t'es dispo quand ?",
    "ça te va ?",
    "tu confirmes ?",
    "et sinon quoi de neuf ?",
    "tu pars à quelle heure ?",
    "c'était bien ?"
];

// Suffixes optionnels. La chaîne vide domine : une phrase sur deux avec emoji
// serait elle-même une signature.
const TAILS = ["", "", "", "", "", "", " 👍", " 😂", " 🤔", " 😅", " 🙌", " 🤷", " 😬", " 🔥"];

// Gabarits, avec leur poids. La variété de FORME compte autant que celle du
// vocabulaire : un fil où tous les messages font la même longueur se voit.
const SHAPES = [
    { weight: 20, build: () => pick(SHORT) },
    { weight: 28, build: () => pick(OPENERS) },
    { weight: 22, build: () => pick(OPENERS) + pick(TAILS) },
    { weight: 15, build: () => `${pick(OPENERS)}, ${pick(FOLLOWS)}` },
    { weight: 10, build: () => pick(QUESTIONS) },
    { weight: 5, build: () => `${pick(SHORT)}, ${pick(FOLLOWS)}` }
];

const TOTAL_WEIGHT = SHAPES.reduce((n, s) => n + s.weight, 0);

// Nombre de sorties distinctes possibles, tous gabarits confondus.
export const COVER_POOL_SIZE =
    SHORT.length
    + OPENERS.length
    + OPENERS.length * new Set(TAILS).size
    + OPENERS.length * FOLLOWS.length
    + QUESTIONS.length
    + SHORT.length * FOLLOWS.length;

// Majorant de la longueur d'une couverture automatique.
const longest = list => Math.max(...list.map(s => s.length));
export const MAX_AUTO_COVER_LEN =
    longest(OPENERS) + 2 + longest(FOLLOWS) + longest(TAILS);

// Mémoire des dernières couvertures produites. Sans elle, un tirage uniforme
// sur 40 ouvertures répète la même phrase au bout de ~8 messages (paradoxe des
// anniversaires) — exactement le motif qu'un lecteur du salon remarque.
const RECENT_MAX = 16;
const recent = [];

function remember(cover) {
    recent.push(cover);
    if (recent.length > RECENT_MAX) recent.shift();
    return cover;
}

// Tire jusqu'à obtenir une phrase absente des derniers tirages. Le nombre
// d'essais est borné : avec un pool minuscule fourni par l'utilisateur, on
// finit par accepter une répétition plutôt que de boucler.
function pickFresh(generate, tries = 12) {
    let cover = generate();
    for (let i = 0; i < tries && recent.includes(cover); i++) cover = generate();
    return remember(cover);
}

function generateAuto() {
    let roll = randomInt(TOTAL_WEIGHT);
    for (const shape of SHAPES) {
        if (roll < shape.weight) return shape.build();
        roll -= shape.weight;
    }
    return pick(OPENERS); // inatteignable, filet de sécurité
}

// Découpe une liste fournie par l'utilisateur. Le champ de réglage Vencord est
// mono-ligne, donc on accepte aussi le point-virgule comme séparateur.
export function parseCoverPool(text) {
    if (!text) return [];
    return text.split(/[\n;]/).map(s => s.trim()).filter(Boolean);
}

// Couverture à utiliser :
//   1. `custom` — phrase imposée pour ce message précis ;
//   2. `pool`   — liste perso de l'utilisateur (le pool intégré est public,
//                 donc connu de quiconque lit le code) ;
//   3. sinon    — génération par gabarits.
export function pickCover(custom, { pool } = {}) {
    if (custom && custom.trim()) return custom.trim();
    if (pool && pool.length) return pickFresh(() => pick(pool));
    return pickFresh(generateAuto);
}

// Vide la mémoire anti-répétition (tests, changement de pool).
export function resetCoverHistory() {
    recent.length = 0;
}
