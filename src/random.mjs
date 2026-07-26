// Tirage aléatoire uniforme, partagé par le codec et le générateur de
// couvertures.
//
// Deux exigences, mesurées plutôt que supposées :
//
// 1. Uniformité stricte. `getRandomValues() % n` privilégie légèrement les
//    petites valeurs dès que n ne divise pas 2^32, et ces biais portent sur des
//    distributions qu'un adversaire peut observer longtemps (choix des phrases
//    de couverture, position des symboles cachés). D'où le rejet.
//
// 2. Coût. Un appel à `crypto.getRandomValues` coûte ~3 µs quel que soit le
//    nombre de valeurs demandées : 1 valeur ou 64, c'est le même prix. Disperser
//    un payload dans une couverture de 60 graphèmes demandait 60 appels, soit
//    ~180 µs par message — plus que le chiffrement lui-même. On remplit donc un
//    tampon en bloc et on y puise.
//
// Mettre en tampon la sortie d'un CSPRNG ne l'affaiblit pas : les octets sont
// déjà générés, ils attendent simplement d'être consommés.

const POOL = new Uint32Array(256);
let poolAt = POOL.length; // force un remplissage au premier appel

function nextWord() {
    if (poolAt >= POOL.length) {
        crypto.getRandomValues(POOL);
        poolAt = 0;
    }
    return POOL[poolAt++];
}

export function randomInt(n) {
    if (n <= 1) return 0;
    // Rejet des valeurs qui déborderaient du dernier bloc complet.
    const limit = Math.floor(0x1_0000_0000 / n) * n;
    for (;;) {
        const v = nextWord();
        if (v < limit) return v % n;
    }
}

// `count` entiers uniformes dans [0, n[. Même garantie qu'un appel par valeur,
// sans le coût d'un appel système par valeur.
export function randomInts(count, n) {
    const out = new Array(count);
    for (let i = 0; i < count; i++) out[i] = randomInt(n);
    return out;
}

export function pickOne(list) {
    return list[randomInt(list.length)];
}
