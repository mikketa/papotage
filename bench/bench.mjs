// Mesures de performance. Pas un test : à lancer à la main avec
//   npm run bench
// Sert à décider quoi optimiser sur des chiffres, et à vérifier après coup que
// l'optimisation en était une.

import { decodeHidden, encodeHidden } from "../src/codec.mjs";
import { decodeIncoming, detectMode, encodeOutgoing } from "../src/plugin-core.mjs";
import { CTX, PASS, incompressible } from "../test/helpers.mjs";

const base = { passphrase: PASS, context: CTX };

function bench(label, iterations, fn) {
    const t0 = process.hrtime.bigint();
    for (let i = 0; i < iterations; i++) fn(i);
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    const each = (ms / iterations) * 1000;
    console.log(`  ${label.padEnd(52)} ${ms.toFixed(1).padStart(8)} ms  (${each.toFixed(1)} µs/op)`);
    return ms;
}

async function benchAsync(label, iterations, fn) {
    const t0 = process.hrtime.bigint();
    for (let i = 0; i < iterations; i++) await fn(i);
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    console.log(`  ${label.padEnd(52)} ${ms.toFixed(1).padStart(8)} ms  (${(ms / iterations).toFixed(3)} ms/op)`);
    return ms;
}

// Un salon réaliste : une poignée de messages Papotage noyés dans du bavardage.
const chatter = [
    "salut ça va ?", "mdr", "ouais je suis d'accord", "👍", "```js\nconst a = 1;\n```",
    "j'arrive dans 5 min", "regarde ❤️ c'est mignon", "trop drôle 😂😂🔥",
    "quelqu'un a vu le lien ?", "non mais franchement"
];

console.log("\n=== Pré-filtre (appelé sur CHAQUE message de CHAQUE scan) ===");
const encoded = await encodeOutgoing({ ...base, raw: "rendez-vous à 20h au parc" });
const longNormal = "lorem ipsum dolor sit amet ".repeat(70); // ~1900 car., message bavard
bench("detectMode sur un message ordinaire court", 200_000, i => detectMode(chatter[i % chatter.length]));
bench("detectMode sur un message ordinaire long (1900 car.)", 20_000, () => detectMode(longNormal));
bench("detectMode sur un message Papotage", 50_000, () => detectMode(encoded));

console.log("\n=== Scan d'un salon : 500 messages dont 5 % chiffrés ===");
const channel = Array.from({ length: 500 }, (_, i) =>
    i % 20 === 0 ? encoded : chatter[i % chatter.length]);
bench("500 messages : pré-filtre seul", 100, () => { for (const m of channel) detectMode(m); });

console.log("\n=== Chiffrement / déchiffrement (clé déjà dérivée) ===");
await benchAsync("encodeOutgoing, secret de 25 caractères", 300, () =>
    encodeOutgoing({ ...base, raw: "rendez-vous à 20h au parc" }));
await benchAsync("encodeOutgoing, secret de 500 caractères", 200, () =>
    encodeOutgoing({ ...base, raw: incompressible(500), defaultCover: "ok" }));
await benchAsync("decodeIncoming, secret de 25 caractères", 300, () =>
    decodeIncoming({ content: encoded, ...base }));

const big = await encodeHidden(incompressible(500), PASS, { cover: "ok", context: CTX });
await benchAsync("decodeHidden, secret de 500 caractères", 200, () =>
    decodeHidden(big, PASS, { context: CTX }));

console.log("\n=== Coût d'un salon entier déchiffré (500 messages) ===");
await benchAsync("500 messages : pré-filtre + déchiffrement des 25 vrais", 5, async () => {
    for (const m of channel) await decodeIncoming({ content: m, ...base });
});
console.log();
