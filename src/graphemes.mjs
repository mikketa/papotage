// Découpage en graphèmes, partagé par le codec et le générateur de couvertures.
//
// Deux modules en ont besoin pour la même raison : un « caractère » au sens de
// l'utilisateur peut occuper plusieurs points de code (« ❤️ » en fait deux,
// « 👨‍👩‍👧 » cinq). Compter ou découper autrement casse le rendu ou fausse le
// nombre d'emplacements disponibles pour disperser un payload.

const SEGMENTER = typeof Intl !== "undefined" && Intl.Segmenter ? new Intl.Segmenter() : null;

export function graphemes(s) {
    if (!SEGMENTER) return [...s]; // repli : points de code
    const out = [];
    for (const { segment } of SEGMENTER.segment(s)) out.push(segment);
    return out;
}

// Caractères susceptibles de fusionner avec le précédent : liant, sélecteurs de
// variation, teintes de peau, indicateurs régionaux (drapeaux), diacritiques.
// En leur absence, un point de code = un graphème, et le comptage se passe du
// segmenteur — 0,35 µs contre 17,8 µs (mesuré). C'est le cas de toutes les
// phrases de couverture intégrées, et le comptage sert à chaque tirage.
const COMPOSANTS = /[\u0300-\u036f\u200d\ufe00-\ufe0f]|[\u{1F3FB}-\u{1F3FF}]|[\u{1F1E6}-\u{1F1FF}]|[\u{E0100}-\u{E01EF}]/u;

export function graphemeCount(s) {
    return COMPOSANTS.test(s) ? graphemes(s).length : [...s].length;
}
