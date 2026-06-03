import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))

import streamlit as st
from sqlmodel import Session, select

from app.database import init_db, engine
from app.models import Company, Asset, Finding
from app.services.collector import collect_for_company
from app.report import generate_company_report

init_db()

st.set_page_config(page_title="CyberSignal", layout="wide")

st.title("CyberSignal")
st.caption("MVP local de veille d'exposition cyber pour PME/ETI")

with st.sidebar:
    st.header("Créer une entreprise")

    name = st.text_input("Nom")
    sector = st.text_input("Secteur")
    country = st.text_input("Pays", value="France")

    if st.button("Créer"):
        if name:
            with Session(engine) as session:
                company = Company(name=name, sector=sector, country=country)
                session.add(company)
                session.commit()
                st.success(f"Entreprise créée : {name}")
        else:
            st.error("Le nom est obligatoire.")

with Session(engine) as session:
    companies = session.exec(select(Company)).all()

if not companies:
    st.info("Commence par créer une entreprise dans la barre latérale.")
    st.stop()

company_labels = {f"{c.id} — {c.name}": c.id for c in companies}
selected_label = st.selectbox("Entreprise", list(company_labels.keys()))
company_id = company_labels[selected_label]

st.divider()

col1, col2 = st.columns(2)

with col1:
    st.subheader("Ajouter un asset")

    asset_type = st.selectbox("Type", ["technology", "domain", "keyword"])
    asset_value = st.text_input(
        "Valeur",
        placeholder="Ex : WordPress, Fortinet, example.com",
    )

    if st.button("Ajouter asset"):
        if asset_value:
            with Session(engine) as session:
                asset = Asset(
                    company_id=company_id,
                    asset_type=asset_type,
                    value=asset_value,
                )

                session.add(asset)
                session.commit()

                st.success("Asset ajouté.")
        else:
            st.error("La valeur est obligatoire.")

with col2:
    st.subheader("Actions")

    if st.button("Lancer collecte vulnérabilités"):
        ids = collect_for_company(company_id)
        st.success(f"{len(ids)} findings créés.")

    if st.button("Générer rapport Markdown"):
        path = generate_company_report(company_id)
        st.success(f"Rapport généré : {path}")
        st.code(path)

st.divider()

with Session(engine) as session:
    assets = session.exec(
        select(Asset).where(Asset.company_id == company_id)
    ).all()

    findings = session.exec(
        select(Finding)
        .where(Finding.company_id == company_id)
        .order_by(Finding.score.desc())
    ).all()

st.subheader("Assets surveillés")

if assets:
    st.dataframe(
        [{"type": a.asset_type, "value": a.value} for a in assets],
        use_container_width=True,
    )
else:
    st.info("Aucun asset pour cette entreprise.")

st.subheader("Findings")

if findings:
    st.dataframe(
        [
            {
                "severity": f.severity,
                "score": f.score,
                "confidence": f.confidence,
                "asset": f.related_asset,
                "cve": f.cve_id,
                "title": f.title,
                "url": f.url,
            }
            for f in findings
        ],
        use_container_width=True,
    )
else:
    st.info("Aucun finding pour le moment.")