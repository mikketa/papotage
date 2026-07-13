import { encodeEmoji, decodeEmoji } from "../src/codec.mjs";

const PASS = "motdepasse-secret";
let ok = 0, ko = 0;
const check = async (n, f) => { try { await f(); console.log("✅", n); ok++; } catch (e) { console.log("❌", n, "-", e.message); ko++; } };
const assert = (c, m) => { if (!c) throw new Error(m || "assertion"); };
const emojiCount = s => [...s].filter(c => /\p{Emoji_Presentation}/u.test(c)).length;

await check("aller-retour simple", async () => {
    const clair = "rdv 20h";
    const msg = await encodeEmoji(clair, PASS);
    console.log(`   "${clair}" -> ${msg}`);
    console.log(`   (${emojiCount(msg)} emojis)`);
    assert(await decodeEmoji(msg, PASS) === clair);
});

await check("accents + emojis dans le secret", async () => {
    const clair = "ramène la clé 🔑 à 14h précises";
    assert(await decodeEmoji(await encodeEmoji(clair, PASS), PASS) === clair);
});

await check("avec couverture texte", async () => {
    const msg = await encodeEmoji("le code c'est 4271", PASS, "ptdr regarde ça");
    assert(msg.startsWith("ptdr regarde ça "), `msg = "${msg.slice(0, 30)}..."`);
    assert(await decodeEmoji(msg, PASS) === "le code c'est 4271");
});

await check("couverture contenant des emojis du dico (faux MAGIC 👀😡) => décode quand même", async () => {
    // Régression : 0xC7 (MAGIC) se rend 👀😡. Une couverture avec ces emojis
    // insérait un faux MAGIC ; le décodeur doit itérer jusqu'au vrai.
    for (const cover of ["👀😡 lol", "regarde 🔥💀 ça", "😀 test 💯"]) {
        const msg = await encodeEmoji("code", PASS, cover);
        assert(await decodeEmoji(msg, PASS) === "code", `cassé avec couverture "${cover}"`);
    }
});

await check("mauvaise clé => null", async () => {
    assert(await decodeEmoji(await encodeEmoji("secret", PASS), "faux") === null);
});

await check("message normal (emojis naturels) => null, pas de crash", async () => {
    assert(await decodeEmoji("trop drôle 😂😂🔥 j'adore", PASS) === null);
});

await check("longueur : combien d'emojis selon le secret", async () => {
    for (const n of [2, 10, 30, 60]) {
        const msg = await encodeEmoji("x".repeat(n), PASS);
        console.log(`   ${n} car. -> ${emojiCount(msg)} emojis`);
    }
});

console.log(`\n${ok} réussis, ${ko} échoués`);
process.exit(ko ? 1 : 0);
