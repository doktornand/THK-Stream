# 🛡️ THK — Threat Intelligence Hub

Interface Streamlit pour l'analyse multi-sources d'IPs et de domaines suspects.  
Basé sur [TH-K1e.py](https://github.com/doktornand/THK) de doktornand.

---

## 🚀 Déploiement sur Streamlit Community Cloud

### 1. Préparer le dépôt GitHub

Créez un nouveau dépôt GitHub (public ou privé) et poussez-y ces 4 fichiers :

```
thk_streamlit/
├── app.py
├── analyzer.py
├── requirements.txt
└── .streamlit/
    └── config.toml
```

```bash
git init
git add .
git commit -m "THK Streamlit app"
git remote add origin https://github.com/<votre-compte>/<votre-repo>.git
git push -u origin main
```

### 2. Déployer sur streamlit.io

1. Connectez-vous sur **[share.streamlit.io](https://share.streamlit.io)**
2. Cliquez sur **"New app"**
3. Choisissez votre dépôt GitHub et la branche `main`
4. Fichier principal : `app.py`
5. Cliquez sur **"Deploy"** → votre app sera disponible en 2-3 minutes

### 3. (Optionnel) Secrets via Streamlit Cloud

Pour ne pas ressaisir les clés API à chaque session, vous pouvez les stocker dans les **Secrets** de Streamlit Cloud :

1. Dans votre app déployée → **Settings → Secrets**
2. Ajoutez :

```toml
VIRUSTOTAL_API_KEY = "votre-clé"
ABUSEIPDB_API_KEY  = "votre-clé"
SHODAN_API_KEY     = "votre-clé"
GREYNOISE_API_KEY  = "votre-clé"
# etc.
```

3. Dans `app.py`, ajoutez en haut de la section clés API :

```python
import streamlit as st
for k, env in [
    ("virustotal", "VIRUSTOTAL_API_KEY"),
    ("abuseipdb",  "ABUSEIPDB_API_KEY"),
    ("shodan",     "SHODAN_API_KEY"),
    ("greynoise",  "GREYNOISE_API_KEY"),
]:
    if env in st.secrets and not api_keys.get(k):
        api_keys[k] = st.secrets[env]
```

---

## 🔑 Clés API nécessaires

| Service | Lien d'inscription | Gratuit ? |
|---|---|---|
| VirusTotal | https://www.virustotal.com/gui/join-us | ✅ 500 req/jour |
| AbuseIPDB | https://www.abuseipdb.com/register | ✅ 1 000 req/jour |
| Shodan | https://account.shodan.io/register | ✅ limité |
| GreyNoise | https://viz.greynoise.io/signup | ✅ community |
| AlienVault OTX | https://otx.alienvault.com/ | ✅ gratuit |
| Censys | https://search.censys.io/ | ✅ 250 req/mois |
| SecurityTrails | https://securitytrails.com/ | ✅ 50 req/mois |
| LeakIX | https://leakix.net/ | ✅ limité |
| HetrixTools | https://hetrixtools.com/ | ✅ limité |

---

## 📦 Structure du projet

| Fichier | Rôle |
|---|---|
| `app.py` | Interface Streamlit (UI, routing, affichage) |
| `analyzer.py` | Moteur d'analyse async (requêtes, scoring) |
| `requirements.txt` | Dépendances Python |
| `.streamlit/config.toml` | Thème et configuration Streamlit |

---

## 🧑‍💻 Lancer en local

```bash
pip install -r requirements.txt
streamlit run app.py
```

---

## ⚡ Fonctionnalités

- **9 sources** interrogées en parallèle (asyncio + aiohttp)
- **Score de risque 0–100** agrégé avec niveaux : FAIBLE / MOYEN / ÉLEVÉ / CRITIQUE
- **Analyse batch** : plusieurs IPs/domaines simultanément
- **Export JSON & CSV** des résultats
- **Historique** de session avec tableau interactif
- **Interface dark mode** responsive et moderne
