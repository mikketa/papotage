import { encodeHidden, decodeHidden } from "../src/codec.mjs";

const PASS = "motdepasse-secret";
let ok = 0, ko = 0;
const check = async (n, f) => { try { await f(); console.log("✅", n); ok++; } catch (e) { console.log("❌", n, "-", e.message); ko++; } };
const assert = (c, m) => { if (!c) throw new Error(m || "assertion"); };
const len = s => [...s].length;

// Texte long et redondant (typique d'un vrai message) : la compression doit mordre.
const LONG = "on se retrouve demain à quatorze heures devant le lycée comme d'habitude, "
    + "préviens les autres qu'on part ensemble et qu'on prend le bus de la ligne, "
    + "n'oublie pas tes affaires et surtout dis rien à personne d'accord ?";

await check("aller-retour d'un long message compressible", async () => {
    const out = await decodeHidden(await encodeHidden(LONG, PASS), PASS);
    assert(out === LONG, "le texte déchiffré diffère de l'original");
});

await check("la compression réduit vraiment la taille envoyée", async () => {
    // 4 caractères invisibles par octet (2 bits) : sans compression, ~ (longueur+9)*4
    // (9 = overhead nonce 5 o + tag 4 o).
    const octets = new TextEncoder().encode(LONG).length;
    const sansCompression = (octets + 9) * 4;
    const msg = await encodeHidden(LONG, PASS, "ok");
    console.log(`   ${octets} octets clairs -> ${len(msg)} car. envoyés (au lieu de ~${sansCompression} sans compression)`);
    assert(len(msg) < sansCompression, "la compression n'a pas réduit la taille");
});

await check("un message trop long SANS compression passe maintenant sous 2000", async () => {
    // 512 caractères répétitifs : (512+12)*4 = 2096 > 2000 sans compression.
    const clair = "rendez-vous ce soir même endroit ".repeat(16).slice(0, 512);
    const msg = await encodeHidden(clair, PASS, "mdr");
    console.log(`   512 car. redondants -> ${len(msg)} car. envoyés (limite 2000)`);
    assert(len(msg) < 2000, `encore trop long: ${len(msg)}`);
    assert(await decodeHidden(msg, PASS) === clair, "aller-retour cassé sur 512 car.");
});

await check("message court : pas de compression, mais aller-retour intact", async () => {
    const clair = "ok";
    assert(await decodeHidden(await encodeHidden(clair, PASS), PASS) === clair);
});

await check("mauvaise clé sur un message compressé => null", async () => {
    assert(await decodeHidden(await encodeHidden(LONG, PASS), "faux") === null);
});

console.log(`\n${ok} réussis, ${ko} échoués`);
process.exit(ko ? 1 : 0);
