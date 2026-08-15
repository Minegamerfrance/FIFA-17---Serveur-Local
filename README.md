# ⚽ FIFA 17 Local Server Revival

![Status](https://img.shields.io/badge/status-development-orange)
![FIFA](https://img.shields.io/badge/FIFA-17-yellow)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![Contributions](https://img.shields.io/badge/contributions-welcome-brightgreen)

## 📖 Présentation

Ce projet expérimental a pour objectif d'étudier et de reconstruire suffisamment de services en ligne utilisés par **FIFA 17** afin de permettre au jeu de communiquer avec un **serveur local**.

L'objectif principal à long terme est de réussir à restaurer autant que possible le fonctionnement des fonctionnalités en ligne de FIFA 17, avec un intérêt particulier pour **FIFA Ultimate Team (FUT 17)**.

> ⚠️ Le projet est actuellement en développement et n'est pas encore fonctionnel pour une utilisation normale de FUT.

---

# 🚧 État actuel

Le projet a déjà dépassé plusieurs étapes importantes de l'initialisation des services en ligne.

### ✅ Fonctionne actuellement

- Communication entre FIFA 17 et le serveur local
- Serveur LSX local
- Échanges Blaze expérimentaux
- Authentification locale expérimentale
- `Auth10`
- `PostAuth`
- Chargement de paramètres joueur
- Reconnaissance du compte local
- Droits FIFA 17 / FUT
- Requêtes catalogue
- Requêtes d'offres
- Portefeuille local
- Réponses LSX générées localement
- Outils de diagnostic réseau
- Instrumentation Frida utilisée pendant les recherches

---

# ❌ Blocage actuel

Le jeu arrive maintenant beaucoup plus loin dans son processus de connexion.

Le déroulement observé ressemble actuellement à :

```text
Démarrage FIFA 17
        ↓
Connexion au serveur local
        ↓
Authentification
        ↓
Auth10
        ↓
PostAuth
        ↓
Chargement des données joueur
        ↓
Droits FIFA / FUT
        ↓
Catalogue / offres
        ↓
Portefeuille
        ↓
Initialisation des services en ligne
        ↓
❌ Blocage de l'interface
```

FIFA 17 affiche finalement un **panneau/écran blanc**.

La connexion réseau peut continuer à travailler derrière cette interface, mais le processus de connexion ne semble jamais être considéré comme complètement terminé par le jeu.

Le travail actuel consiste donc principalement à identifier **la dernière réponse, notification ou transition attendue par FIFA 17 pour terminer l'initialisation**.

---

# 🔬 Recherche et diagnostic

Le dépôt contient de nombreux outils et anciennes expériences utilisés pendant le reverse engineering.

Par exemple :

```text
tools/
├── versions/
│   ├── v54/
│   ├── v67/
│   ├── v73-FINAL/
│   ├── ...
│   ├── v109-STABLE/
│   ├── v110-PEEK/
│   ├── v111-CONSUME/
│   ├── v112-DECISION/
│   ├── v113-FIRE2/
│   └── v114-AUTH-PLST/
│
├── watch-fifa-net.ts
├── xref-gsi.py
├── xref-gsi-fast.py
├── xref-gsi-deep.py
├── xref-offline.py
└── ...
```

Les différentes versions sont conservées afin de garder une trace des expériences et des comportements observés.

---

# 🧪 Frida

Plusieurs scripts Frida sont présents dans le projet.

Ils ont notamment été utilisés pour :

- observer le comportement réseau de FIFA 17 ;
- suivre certaines fonctions du jeu ;
- étudier les étapes de connexion ;
- identifier les réponses consommées par FIFA ;
- tester différentes hypothèses concernant l'initialisation des services.

Exemple :

```text
tools/versions/v114-AUTH-PLST/
├── frida-ssl-bypass.js
├── frida-hook-offline-xrefs.js
├── NOTES.txt
├── RESTORE.txt
├── STRATEGY-RESET.md
├── src/
└── tools/
```

---

# 🎯 Objectif actuel

La priorité n'est plus simplement de faire passer l'authentification.

Une partie importante de cette chaîne fonctionne désormais.

La priorité est d'identifier ce qui manque **après l'initialisation des services**, afin que FIFA 17 considère la connexion comme terminée et quitte correctement l'écran de chargement.

Les contributions sur les sujets suivants sont particulièrement bienvenues :

- protocoles Blaze ;
- LSX / Origin ;
- reverse engineering ;
- analyse réseau ;
- Frida ;
- TypeScript / Node.js ;
- analyse de binaires ;
- anciens services EA/FIFA ;
- FIFA Ultimate Team.

---

# 🖥️ MNG Launcher

Un launcher séparé a également été développé pour simplifier les tests et éviter de lancer manuellement tous les composants du projet.

Il permet notamment de :

- configurer le serveur ;
- créer une session locale ;
- démarrer/arrêter le serveur ;
- tester les services ;
- lancer FIFA 17 ;
- consulter les journaux.

Le launcher possède son propre dépôt :

👉 [MNG Launcher - FIFA 17 Local Server](https://github.com/Minegamerfrance/Luncher-MNG-for-serveur)

---

# 🤝 Je recherche de l'aide

Le projet est ouvert aux personnes souhaitant participer.

Si vous avez de l'expérience avec :

**FIFA / EA • Blaze • LSX • Frida • reverse engineering • protocoles réseau • Node.js / TypeScript**

votre aide est la bienvenue.

Vous pouvez :

1. ouvrir une **Issue** ;
2. proposer une hypothèse concernant le blocage ;
3. analyser le code ou les traces ;
4. proposer une correction ;
5. créer une **Pull Request**.

Même une petite découverte peut aider à faire avancer le projet.

---

# 📸 Captures

Des captures du serveur, du launcher et de l'état actuel de FIFA 17 pourront être ajoutées ici.

<!-- Exemple :
![FIFA 17 Local Server](docs/images/server.png)
-->

---

# ⚠️ Disclaimer

Ce projet est un projet communautaire et expérimental réalisé à des fins de recherche, d'apprentissage, de préservation et d'interopérabilité.

Il n'est **ni affilié, ni approuvé, ni sponsorisé par Electronic Arts (EA)**.

**FIFA**, **FIFA 17**, **EA Sports** et les marques associées appartiennent à leurs propriétaires respectifs.

Le projet ne fournit pas de copie de FIFA 17. Les utilisateurs doivent posséder leurs propres fichiers de jeu obtenus légalement.

---

# ⭐ FIFA 17 Revival

Le projet est encore loin d'être terminé, mais plusieurs étapes de la connexion ont déjà pu être reproduites localement.

L'objectif est maintenant de comprendre les dernières étapes nécessaires au chargement complet des services.

**Contributions, recherches et tests sont les bienvenus.**
