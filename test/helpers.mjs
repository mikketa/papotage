// Outils partagés par les suites de test.

export const PASS = "motdepasse-secret";
export const CTX = "123456789012345678";      // identifiant de salon fictif
export const OTHER_CTX = "987654321098765432";

const ZERO_WIDTH = /[\u200B-\u200D\u2060-\u2064]/g;
const VARIATION = /[\u{FE00}-\u{FE0F}]|[\u{E0100}-\u{E01EF}]/gu;

// Ce qu'un humain voit réellement dans Discord.
export const visible = s => s.replace(ZERO_WIDTH, "").replace(VARIATION, "");

// Longueur en points de code (≠ s.length dès qu'il y a des caractères hors BMP).
export const len = s => [...s].length;

export const invisibleCount = s => len(s) - len(visible(s));

// Texte haute-entropie déterministe (LCG) : la compression ne mord pas dessus,
// donc les tests de taille mesurent bien le pire cas.
export function incompressible(n) {
    const abc = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,!?";
    let s = "", x = 0x9e3779b9 >>> 0;
    for (let i = 0; i < n; i++) {
        x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
        s += abc[(x >>> 16) % abc.length];
    }
    return s;
}

// Suite pseudo-aléatoire reproductible, pour le fuzzing.
export function makeRng(seed = 1) {
    let x = seed >>> 0 || 1;
    return () => {
        x ^= x << 13; x >>>= 0;
        x ^= x >>> 17;
        x ^= x << 5; x >>>= 0;
        return x / 0x1_0000_0000;
    };
}

// Plus longue série CONTIGUË de caractères invisibles : c'est ce que cherche un
// détecteur générique, donc la métrique à surveiller.
export function longestInvisibleRun(s) {
    let best = 0, cur = 0;
    for (const ch of s) {
        const cp = ch.codePointAt(0);
        const inv = (cp >= 0x200b && cp <= 0x200d) || (cp >= 0x2060 && cp <= 0x2064)
            || (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);
        cur = inv ? cur + 1 : 0;
        if (cur > best) best = cur;
    }
    return best;
}

// Vrai si tous les points de code de `needle` apparaissent dans `hay` dans le
// même ordre : prouve qu'une couverture n'a été ni amputée ni réordonnée, même
// si des symboles ont été insérés au milieu.
export function isSubsequence(needle, hay) {
    const want = [...needle];
    let i = 0;
    for (const ch of hay) if (i < want.length && ch === want[i]) i++;
    return i === want.length;
}
