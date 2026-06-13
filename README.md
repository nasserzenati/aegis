
## What works / where it breaks (notes de terrain)
- Le modele local 8B fournit parfois un chemin relatif que le serveur MCP rejette ;
  l'agent doit etre guide (lister le dossier d'abord). Limite d'orchestration, pas de securite.
- Le firewall v1 est heuristique (motifs regex) : attrape override d'instructions et
  exfiltration evidente, mais contournable par paraphrase/encodage. v2 = classifieur leger.
- Latence : ~15-25 tok/s sur M1 16 Go ; usable en demo, lent sur les chaines d'appels longues.
