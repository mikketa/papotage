// 4 listes de 32 mots (5 bits par mot). L'ordre EST le protocole : ne jamais
// réordonner ni modifier une liste sans changer la version, sinon incompatible.
// Slot 0 -> L0, slot 1 -> L1, slot 2 -> L2, slot 3 -> L3, puis on recommence.

export const L0 = [
    "chat", "chien", "voisin", "prof", "copain", "gamin", "mec", "type",
    "pote", "frère", "cousin", "boss", "client", "joueur", "pilote", "chef",
    "gardien", "boulanger", "facteur", "docteur", "pêcheur", "fermier", "touriste", "serveur",
    "vendeur", "coiffeur", "plombier", "jardinier", "peintre", "chanteur", "danseur", "sportif"
];

export const L1 = [
    "mange", "regarde", "cherche", "attrape", "pousse", "tire", "lave", "casse",
    "répare", "achète", "vend", "prépare", "cuisine", "dessine", "peint", "chante",
    "écoute", "appelle", "attend", "suit", "dépasse", "évite", "oublie", "retrouve",
    "montre", "cache", "jette", "ramasse", "plie", "coupe", "colle", "ouvre"
];

export const L2 = [
    "pain", "café", "vélo", "sac", "livre", "stylo", "ballon", "chiot",
    "jardin", "mur", "toit", "jouet", "repas", "gâteau", "journal", "téléphone",
    "ordi", "casque", "manteau", "chapeau", "parapluie", "panier", "seau", "balai",
    "marteau", "clou", "tuyau", "câble", "carton", "cadeau", "bouquet", "croquis"
];

export const L3 = [
    "vite", "lentement", "doucement", "fort", "bien", "mal", "souvent", "parfois",
    "hier", "tôt", "tard", "dehors", "dedans", "ensemble", "seul", "gaiement",
    "tristement", "calmement", "poliment", "rapidement", "prudemment", "joyeusement", "discrètement", "fièrement",
    "gentiment", "bêtement", "tranquillement", "nerveusement", "patiemment", "sagement", "timidement", "franchement"
];

export const LISTS = [L0, L1, L2, L3];

// Mots de liaison insérés pour faire "vraie phrase". Ne portent aucune donnée :
// le décodeur les ignore. Aucun mot des listes ne doit y figurer.
export const GLUE = new Set(["le", "son"]);
