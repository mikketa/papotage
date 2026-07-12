import { encodeMulti, decodePart, reassemble, parseInput } from "../src/codec.mjs";

const PASS = "motdepasse-secret";
let ok = 0, ko = 0;
const check = async (n, f) => { try { await f(); console.log("✅", n); ok++; } catch (e) { console.log("❌", n, "-", e.message); ko++; } };
const assert = (c, m) => { if (!c) throw new Error(m || "assertion"); };
const visible = s => s.replace(/[​‌‍⁠︀-️]/g, "").replace(/[\u{e0100}-\u{e01ef}]/gu, "");

// Simule la réception : recolle les morceaux et déchiffre
async function receive(parts) {
    const buf = {};
    let done = null;
    for (const p of parts) {
        const part = decodePart(p);
        if (!part) continue;
        (buf[part.id] ??= { total: part.total, chunks: [] }).chunks[part.index] = part.chunk;
        const b = buf[part.id];
        if (b.chunks.filter(Boolean).length === b.total)
            done = await reassemble(b.chunks, PASS);
    }
    return done;
}

await check("message court = 1 seul message", async () => {
    const clair = "rdv 20h au parc";
    const parts = await encodeMulti(clair, PASS);
    assert(parts.length === 1, `${parts.length} parts`);
    console.log(`   "${clair}" -> 1 message de ${parts[0].length} caractères, visible: "${visible(parts[0])}"`);
    assert(await receive(parts) === clair);
});

await check("accents + emojis", async () => {
    const clair = "T'inquiète 😏 j'ai géré, on se voit à la crêperie à 14h précises";
    assert(await receive(await encodeMulti(clair, PASS)) === clair);
});

await check("message de 850 caractères tient en 1 message", async () => {
    const clair = "a".repeat(850);
    const parts = await encodeMulti(clair, PASS);
    console.log(`   850 car. -> ${parts.length} message(s), ${parts[0].length} caractères`);
    assert(parts.length === 1, `${parts.length} parts`);
    assert(parts[0].length < 2000);
    assert(await receive(parts) === clair);
});

await check("message très long = découpé et recollé", async () => {
    const clair = "Lorem ipsum dolor sit amet consectetur. ".repeat(120).trim(); // ~4700 car.
    const parts = await encodeMulti(clair, PASS);
    console.log(`   ${clair.length} car. -> ${parts.length} messages (chacun < 2000)`);
    assert(parts.length > 1, "devrait être découpé");
    for (const p of parts) assert(p.length < 2000, `part trop longue: ${p.length}`);
    assert(await receive(parts) === clair, "recollage échoué");
});

await check("morceaux reçus dans le désordre", async () => {
    const clair = "x".repeat(3000);
    const parts = await encodeMulti(clair, PASS);
    const shuffled = [...parts].reverse();
    assert(await receive(shuffled) === clair);
});

await check("mauvaise clé => null", async () => {
    const buf = {};
    for (const p of await encodeMulti("secret", PASS)) {
        const part = decodePart(p);
        (buf[part.id] ??= { chunks: [] }).chunks[part.index] = part.chunk;
        const r = await reassemble(buf[part.id].chunks, "faux");
        assert(r === null);
    }
});

await check("message normal => decodePart null", async () => {
    assert(decodePart("salut ça va ❤️ les gars ?") === null);
});

await check("comparaison densité", async () => {
    const parts = await encodeMulti("ok", PASS);
    console.log(`   'ok' -> ${parts[0].length} caractères envoyés (mode zero-width : ~179)`);
});

// --- Discrétion ---
await check("le texte VISIBLE est exactement la couverture (rien qui dépasse)", async () => {
    const cover = "ouais on se voit demain à 15h";
    const parts = await encodeMulti("secret bien planqué", PASS, undefined, cover);
    assert(visible(parts[0]) === cover, `visible = "${visible(parts[0])}"`);
    assert(await receive(parts) === "secret bien planqué");
});

await check("couverture avec emoji (VS légitime) => décodage OK quand même", async () => {
    // ❤️ contient un sélecteur de variation légitime : ne doit pas casser le décodage
    const parts = await encodeMulti("rdv ce soir", PASS, undefined, "trop hâte ❤️ à toute");
    assert(await receive(parts) === "rdv ce soir");
});

await check("couvertures variées entre les morceaux d'un long message", async () => {
    const parts = await encodeMulti("z".repeat(2500), PASS);
    const covers = new Set(parts.map(visible));
    console.log(`   ${parts.length} morceaux, ${covers.size} couvertures différentes`);
    assert(covers.size > 1, "les couvertures devraient varier");
});

// --- Emojis + couverture manuelle ---
await check("couverture finissant par un emoji => round-trip OK", async () => {
    const parts = await encodeMulti("on se retrouve à 21h", PASS, undefined, "ok ça marche 👍");
    assert(await receive(parts) === "on se retrouve à 21h");
});

await check("emoji au milieu de la phrase secrète", async () => {
    const clair = "ramène les 🍕 et on lance le film 🎬 à 20h";
    assert(await receive(await encodeMulti(clair, PASS)) === clair);
});

await check("parseInput : 'phrase | secret' sépare bien", async () => {
    const { cover, secret } = parseInput("salut ça va ? | rdv 20h au parc");
    assert(cover === "salut ça va ?", `cover = "${cover}"`);
    assert(secret === "rdv 20h au parc", `secret = "${secret}"`);
});

await check("parseInput : sans séparateur => tout est secret", async () => {
    const { cover, secret } = parseInput("juste un message secret");
    assert(cover === null);
    assert(secret === "juste un message secret");
});

await check("parseInput : coupe au premier séparateur (secret peut en contenir)", async () => {
    const { cover, secret } = parseInput("ouais | a | b | c");
    assert(cover === "ouais");
    assert(secret === "a | b | c", `secret = "${secret}"`);
});

await check("flux complet : couverture humaine cohérente + secret", async () => {
    const { cover, secret } = parseInput("ouais tranquille et toi ? 😄 | le colis est planqué sous l'escalier");
    const parts = await encodeMulti(secret, PASS, undefined, cover);
    assert(visible(parts[0]).startsWith("ouais tranquille et toi"), `visible = "${visible(parts[0])}"`);
    assert(await receive(parts) === "le colis est planqué sous l'escalier");
});

console.log(`\n${ok} réussis, ${ko} échoués`);
process.exit(ko ? 1 : 0);
