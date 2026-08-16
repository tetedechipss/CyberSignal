# CyberSignal

MVP local pour generer un Cyber Exposure Brief pour PME/ETI.

## Installation

```bash
pip install -r requirements.txt
```

## Application

```bash
streamlit run ui/streamlit_app.py
```

## Referentiel CVE local

Import court pour validation :

```bash
python -m app.cve_cli init --since 2026-07-01
```

Import de l'historique complet, a lancer explicitement :

```bash
python -m app.cve_cli init --all-history
```

Synchronisation incrementale NVD puis mise a jour EPSS et CISA KEV :

```bash
python -m app.cve_cli sync
```

Etat du referentiel :

```bash
python -m app.cve_cli status
```

`NVD_API_KEY` est facultative mais recommandee pour l'import complet. Le delai
entre appels NVD peut etre ajuste avec `NVD_REQUEST_DELAY_SECONDS`.

Les correspondances entre assets et CPE sont maintenues dans
`config/technology_mappings.yaml`.
