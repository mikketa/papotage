// Découpage en graphèmes, partagé par le codec et le générateur de couvertures.
//
// Un « caractère » au sens de l'utilisateur peut occuper plusieurs points de
// code (« ❤️ » en fait deux, « 👨‍👩‍👧 » cinq). Compter ou découper autrement casse
// le rendu ou fausse le nombre d'emplacements où disperser un payload.

const SEGMENTER = typeof Intl !== "undefined" && Intl.Segmenter ? new Intl.Segmenter() : null;

export function graphemes(s) {
    if (!SEGMENTER) return [...s]; // repli : points de code
    const out = [];
    for (const { segment } of SEGMENTER.segment(s)) out.push(segment);
    return out;
}

// Un graphème ne peut dépasser une unité UTF-16 que de deux façons : un point
// de code hors du plan de base (donc un demi-codet haut) ou une marque qui
// fusionne avec le précédent (liant, sélecteur de variation, diacritique). En
// l'absence des deux, `s.length` EST le compte exact et le segmenteur est
// inutile — 0,35 µs contre 17,8 µs (mesuré), et c'est le cas de toutes les
// phrases de couverture intégrées, comptées à chaque tirage.
const COMPOSABLE = /[\u0300-\u036f\u200d\ufe00-\ufe0f\ud800-\udbff]/;

export function graphemeCount(s) {
    return COMPOSABLE.test(s) ? graphemes(s).length : s.length;
}
