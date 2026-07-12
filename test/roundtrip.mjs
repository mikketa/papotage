import { encode, decode } from "../src/codec.mjs";

const PASS = "motdepasse-secret";
let ok = 0, ko = 0;

async function check(name, fn) {
    try { await fn(); console.log("✅", name); ok++; }
    catch (e) { console.log("❌", name, "-", e.message); ko++; }
}

function assert(cond, msg) { if (!cond) throw new Error(msg || "assertion"); }

await check("aller-retour message simple", async () => {
    const clair = "salut ça va ?";
    const phrase = await encode(clair, PASS);
    console.log("   phrase:", phrase);
    const out = await decode(phrase, PASS);
    assert(out === clair, `attendu "${clair}", reçu "${out}"`);
});

await check("aller-retour avec accents et emojis", async () => {
    const clair = "Rendez-vous à 20h dans le café à côté 😎🔥 — n'oublie pas !";
    const phrase = await encode(clair, PASS);
    const out = await decode(phrase, PASS);
    assert(out === clair, `reçu "${out}"`);
});

await check("aller-retour message long", async () => {
    const clair = "Lorem ipsum dolor sit amet ".repeat(10).trim();
    const out = await decode(await encode(clair, PASS), PASS);
    assert(out === clair);
});

await check("mauvaise clé => null", async () => {
    const phrase = await encode("secret", PASS);
    const out = await decode(phrase, "mauvais-mot-de-passe");
    assert(out === null, `devrait être null, reçu "${out}"`);
});

await check("message normal (non-Papotage) => null", async () => {
    const out = await decode("Salut les gars, ça va bien ?", PASS);
    assert(out === null, `devrait être null, reçu "${out}"`);
});

await check("phrase faite de vrais mots-liste mais pas chiffrée => null (pas de crash)", async () => {
    const out = await decode("Le chat mange son pain vite.", PASS);
    assert(out === null, `devrait être null, reçu "${out}"`);
});

await check("longueur de sortie (info)", async () => {
    const phrase = await encode("ok", PASS);
    console.log("   'ok' (2 caractères) ->", phrase.split(".").filter(s => s.trim()).length, "phrases");
});

console.log(`\n${ok} réussis, ${ko} échoués`);
process.exit(ko ? 1 : 0);
