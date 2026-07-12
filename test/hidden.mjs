import { encodeHidden, decodeHidden } from "../src/codec.mjs";

const PASS = "motdepasse-secret";
let ok = 0, ko = 0;
const check = async (n, f) => { try { await f(); console.log("✅", n); ok++; } catch (e) { console.log("❌", n, "-", e.message); ko++; } };
const assert = (c, m) => { if (!c) throw new Error(m || "assertion"); };
const visible = s => s.replace(/[​-‍⁠-⁤﻿]/g, ""); // ce qu'un humain voit
const len = s => [...s].length;
const invisibles = s => len(s) - len(visible(s));

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

await check("densité 3 bits : aller-retour intact (accents/emojis)", async () => {
    const clair = "on se voit à 14h au café ☕ ramène les 📄, dis rien";
    const msg = await encodeHidden(clair, PASS, "ok", 3);
    assert(await decodeHidden(msg, PASS) === clair, "aller-retour 3 bits cassé");
});

await check("auto-détection : 2 et 3 bits se décodent sans rien préciser", async () => {
    const clair = "message de test un peu long pour bien remplir le payload invisible";
    assert(await decodeHidden(await encodeHidden(clair, PASS, "ok", 2), PASS) === clair, "2 bits");
    assert(await decodeHidden(await encodeHidden(clair, PASS, "ok", 3), PASS) === clair, "3 bits");
});

await check("3 bits envoie ~33 % de caractères invisibles en moins que 2 bits", async () => {
    const clair = "rendez-vous ce soir même endroit, ramène le matériel et préviens les autres";
    const inv2 = invisibles(await encodeHidden(clair, PASS, "ok", 2));
    const inv3 = invisibles(await encodeHidden(clair, PASS, "ok", 3));
    const gain = Math.round((1 - inv3 / inv2) * 100);
    console.log(`   invisibles : 2 bits = ${inv2}, 3 bits = ${inv3} (-${gain} %)`);
    assert(inv3 < inv2, "3 bits devrait être plus court");
    assert(gain >= 25, `gain trop faible: ${gain} %`);
});

await check("budget Discord : message de 150 caractères tient sous 2000", async () => {
    const clair = "x".repeat(150);
    const msg = await encodeHidden(clair, PASS, "mdr", 3);
    console.log(`   150 caractères secrets -> ${len(msg)} caractères envoyés (limite 2000)`);
    assert(len(msg) < 2000, `trop long: ${len(msg)}`);
    assert(await decodeHidden(msg, PASS) === clair);
});

console.log(`\n${ok} réussis, ${ko} échoués`);
process.exit(ko ? 1 : 0);
