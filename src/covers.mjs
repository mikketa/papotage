// Phrases de couverture : ce que voit un observateur qui n'a pas le plugin.
//
// Le point faible d'un stégano-canal, ce n'est pas le chiffrement : c'est la
// répétition. Un pool de 15 phrases fixes finit par signer le canal ("cette
// personne écrit toujours les 15 mêmes réponses, toujours suivies de 400
// caractères invisibles"). On compose donc la couverture à partir de deux
// pools -> quelques centaines de combinaisons, sans écrire 300 phrases à la main.
//
// Les phrases sont volontairement "réactives" (backchannel : accusé de réception,
// approbation, hésitation) : ça passe crédiblement après n'importe quel message,
// donc un fil entier en couvertures auto reste plausible.

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
    "carrément ouais",
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
    "franchement ouais",
    "bon on verra bien",
    "ok parfait",
    "ah mince ok",
    "ouais pas de souci"
];

// Suffixes optionnels. La chaîne vide est répétée pour que la majorité des
// couvertures restent nues (une phrase sur deux avec emoji ferait tache).
const TAILS = [
    "", "", "", "", "", "",
    " 👍", " 😂", " 🤔", " 😅", " 🙌", " 🤷", " 😬", " 🔥"
];

export const COVER_POOL_SIZE = OPENERS.length * TAILS.length;

// Longueur maximale qu'une couverture auto peut atteindre — sert à réserver la
// place dans le budget de caractères avant même d'avoir tiré la phrase.
export const MAX_AUTO_COVER_LEN = Math.max(...OPENERS.map(o => o.length))
    + Math.max(...TAILS.map(t => t.length));

function randIndex(n) {
    // Rejet des valeurs qui déborderaient du dernier bloc complet : tirage
    // uniforme, contrairement à un simple modulo.
    const limit = Math.floor(0x1_0000_0000 / n) * n;
    const buf = new Uint32Array(1);
    for (;;) {
        crypto.getRandomValues(buf);
        if (buf[0] < limit) return buf[0] % n;
    }
}

export function pickFrom(list) {
    return list[randIndex(list.length)];
}

// Couverture à utiliser : la phrase perso si l'appelant en fournit une, sinon
// une combinaison tirée au hasard.
export function pickCover(custom) {
    if (custom && custom.trim()) return custom.trim();
    return pickFrom(OPENERS) + pickFrom(TAILS);
}
