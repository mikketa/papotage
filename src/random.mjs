// Tirage aléatoire uniforme, partagé par le codec et le générateur de
// couvertures. Uniforme au sens strict : `getRandomValues() % n` privilégie
// légèrement les petites valeurs dès que n ne divise pas 2^32, et ces biais
// se voient sur des distributions qu'un adversaire peut observer longtemps
// (choix des phrases, position des symboles cachés).

export function randomInt(n) {
    if (n <= 1) return 0;
    const limit = Math.floor(0x1_0000_0000 / n) * n;
    const buf = new Uint32Array(1);
    for (;;) {
        crypto.getRandomValues(buf);
        if (buf[0] < limit) return buf[0] % n;
    }
}

export function pickOne(list) {
    return list[randomInt(list.length)];
}
