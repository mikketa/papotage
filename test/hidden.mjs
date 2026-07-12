import { encodeHidden, decodeHidden } from "../src/codec.mjs";

const PASS = "motdepasse-secret";
let ok = 0, ko = 0;
const check = async (n, f) => { try { await f(); console.log("✅", n); ok++; } catch (e) { console.log("❌", n, "-", e.message); ko++; } };
const assert = (c, m) => { if (!c) throw new Error(m || "assertion"); };
const visible = s => s.replace(/[​‌‍⁠﻿]/g, ""); // ce qu'un humain voit
const len = s => [...s].length;

await check("aller-retour + partie visible courte", async () => {
    const clair = "rdv 20h au parc, dis rien à personne";
    const msg = await encodeHidden(clair, PASS, "ok");
    assert(visible(msg) === "ok", `visible = "${visible(msg)}"`);
    console.log(`   visible: "${visible(msg)}" | longueur totale: ${len(msg)} caractères (dont invisibles)`);
    const out = await decodeHidden(msg, PASS);
    assert(out === clair, `reçu "${out}"`);
});

await check("accents + emojis", async () => {
    const clair = "T'inquiète, j'ai géré 😏 rendez-vous à la crêperie";
    const out = await decodeHidden(await encodeHidden(clair, PASS), PASS);
    assert(out === clair, `reçu "${out}"`);
});

await check("mauvaise clé => null", async () => {
    const out = await decodeHidden(await encodeHidden("secret", PASS), "faux");
    assert(out === null);
});

await check("message normal sans payload => null", async () => {
    assert(await decodeHidden("salut ça va les gars ?", PASS) === null);
});

await check("budget Discord : message de 150 caractères tient sous 2000", async () => {
    const clair = "x".repeat(150);
    const msg = await encodeHidden(clair, PASS, "mdr");
    console.log(`   150 caractères secrets -> ${len(msg)} caractères envoyés (limite 2000)`);
    assert(len(msg) < 2000, `trop long: ${len(msg)}`);
    assert(await decodeHidden(msg, PASS) === clair);
});

await check("longueur max approximative", async () => {
    for (const n of [10, 50, 100, 200, 230]) {
        const msg = await encodeHidden("x".repeat(n), PASS, "ok");
        console.log(`   ${n} car. -> ${len(msg)} car. envoyés ${len(msg) < 2000 ? "✓" : "✗ DÉPASSE"}`);
    }
});

console.log(`\n${ok} réussis, ${ko} échoués`);
process.exit(ko ? 1 : 0);
