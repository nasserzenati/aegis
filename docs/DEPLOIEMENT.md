# Déployer la démo pour le portfolio (ouverture instantanée)

## Le problème avec Streamlit Community Cloud

Le tier gratuit **endort l'application** après quelques jours sans visite.
Le premier visiteur suivant déclenche un redémarrage complet du serveur
Python (2-3 minutes). C'est structurel au produit gratuit — aucun réglage ne
l'enlève, et les alternatives gratuites équivalentes (Render, Railway,
Hugging Face Spaces) hibernent aussi.

## La solution : l'export statique

Un portfolio n'a pas besoin d'un serveur Python : il a besoin d'une page qui
s'ouvre immédiatement. D'où `dashboard/export_static.py`, qui fige le
dashboard en **un seul fichier HTML autonome** (CSS inline, graphiques SVG
générés en Python, zéro JavaScript externe, zéro dépendance) :

    python dashboard/export_static.py     # -> docs/demo/index.html (~17 Ko)

17 Ko servis statiquement = ouverture instantanée, partout, pour toujours.

## Ce qu'il y a dans docs/

    docs/demo/index.html        <- snapshot statique du dashboard
    docs/portfolio/index.html   <- la page documentation pour le portfolio
    docs/GUIDE.md               <- le guide interne (pas à publier)
    docs/DEPLOIEMENT.md         <- ce fichier

## Options d'hébergement (toutes instantanées, toutes gratuites)

### Option A — directement dans le portfolio (le plus simple)
Copie `docs/demo/index.html` et `docs/portfolio/index.html` chez ton
hébergeur de portfolio, comme n'importe quelle page. Lien ou iframe :

    <a href="/aegis/demo/">Voir la démo Aegis</a>
    <!-- ou -->
    <iframe src="/aegis/demo/" style="width:100%;height:800px;border:0"></iframe>

### Option B — GitHub Pages (si le repo est sur GitHub)
1. Pousser le repo avec le dossier `docs/`.
2. GitHub → Settings → Pages → Source : branche `main`, dossier `/docs`.
3. Les pages sont servies sur `https://<user>.github.io/aegis/demo/`
   et `.../aegis/portfolio/`.

### Option C — Netlify / Cloudflare Pages
Glisser-déposer le dossier `docs/` sur netlify.com/drop : URL publique en
30 secondes, CDN mondial, gratuit.

## Et si on veut quand même la version interactive en ligne ?

- **Garder Streamlit Cloud** comme lien secondaire « démo interactive
  (démarrage ~2 min) » — le statique reste la porte d'entrée.
- **Payer un always-on** (~5 $/mois : Railway, Fly.io machine persistante)
  si la version interactive devient importante.
- La vraie démo interactive reste locale de toute façon :
  `streamlit run dashboard/app.py` (le modèle Ollama est local par design).

## Mettre à jour le snapshot

Après de nouveaux runs de l'agent (nouvelles données dans `audit.db`) :

    python dashboard/export_static.py

puis re-déployer le fichier (ou `git push` si GitHub Pages).
