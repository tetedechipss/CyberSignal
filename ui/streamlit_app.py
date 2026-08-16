import sys
from datetime import datetime, time, timedelta, timezone
from pathlib import Path

import streamlit as st
import streamlit.components.v1 as components
from sqlmodel import Session, select

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))

from app.database import init_db, engine
from app.models import Company, Asset
from app.report import generate_company_report
from app.services.collector import collect_for_company
from app.services.company_management import (
    delete_company,
    delete_company_technologies,
    ignore_company_cves,
    restore_company_cve,
)
from app.services.cve_presentation import format_company_finding_rows, format_cve_row
from app.services.cve_repository import get_company_cve_findings, search_cve_page
from app.services.trends import (
    add_blocklist_word,
    aggregate_trend_events,
    collect_vulnerability_trend_events,
    get_blocklist_size,
    get_country_filter_options,
    load_trend_sources,
    render_word_cloud_html,
)


init_db()

st.set_page_config(page_title="CyberSignal", layout="wide")

TREND_DATASET_KEY = "trends_dataset"
TREND_BLOCKLIST_MESSAGE_KEY = "trends_blocklist_message"
COMPANY_MESSAGE_KEY = "company_message"
ACTIVE_COMPANY_KEY = "active_company_id"
EDITING_ASSETS_KEY = "editing_assets_company_id"
EDITING_FINDINGS_KEY = "editing_findings_company_id"
PENDING_ASSET_DELETE_KEY = "pending_asset_delete"
PENDING_FINDING_IGNORE_KEY = "pending_finding_ignore"
PENDING_COMPANY_DELETE_KEY = "pending_company_delete"


@st.cache_data(ttl=3600, show_spinner=False)
def load_trend_source_options() -> tuple[list[str], int]:
    sources = load_trend_sources()
    return get_country_filter_options(sources), len(sources)


def get_or_collect_trend_dataset(max_feeds: int) -> dict:
    if TREND_DATASET_KEY not in st.session_state:
        with st.spinner("Collecte RSS et extraction des mots..."):
            st.session_state[TREND_DATASET_KEY] = collect_vulnerability_trend_events(
                max_feeds=max_feeds,
            )

    return st.session_state[TREND_DATASET_KEY]


def refresh_trend_dataset(max_feeds: int) -> dict:
    with st.spinner("Actualisation des tendances..."):
        st.session_state[TREND_DATASET_KEY] = collect_vulnerability_trend_events(
            max_feeds=max_feeds,
        )

    return st.session_state[TREND_DATASET_KEY]


def get_time_range_from_controls() -> tuple[datetime, datetime, str]:
    now = datetime.now(timezone.utc)
    period = st.selectbox(
        "Periode temporelle",
        [
            "Dernieres 6h",
            "Dernieres 12h",
            "Dernieres 24h",
            "7 jours",
            "30 jours",
            "Plage personnalisee",
        ],
        index=2,
    )

    quick_ranges = {
        "Dernieres 6h": timedelta(hours=6),
        "Dernieres 12h": timedelta(hours=12),
        "Dernieres 24h": timedelta(hours=24),
        "7 jours": timedelta(days=7),
        "30 jours": timedelta(days=30),
    }

    if period != "Plage personnalisee":
        start_at = now - quick_ranges[period]
        return start_at, now, period

    start_date = st.date_input("Date de debut", value=(now - timedelta(days=7)).date())
    start_time = st.time_input("Heure de debut", value=time(0, 0))
    end_date = st.date_input("Date de fin", value=now.date())
    end_time = st.time_input(
        "Heure de fin",
        value=datetime.now().time().replace(microsecond=0),
    )
    start_at = datetime.combine(start_date, start_time, tzinfo=timezone.utc)
    end_at = datetime.combine(end_date, end_time, tzinfo=timezone.utc)

    if start_at > end_at:
        st.warning("La date de debut est apres la date de fin. La plage a ete inversee.")
        start_at, end_at = end_at, start_at

    return start_at, end_at, "Plage personnalisee"


def render_cve_search() -> None:
    st.subheader("CVE recentes")
    today = datetime.now(timezone.utc).date()
    default_start = today - timedelta(days=1)

    date_col, technology_col, options_col = st.columns([2, 2, 2])
    with date_col:
        date_from_value = st.date_input(
            "Date de debut",
            value=default_start,
            key="cve_date_from",
        )
        date_to_value = st.date_input(
            "Date de fin",
            value=today,
            key="cve_date_to",
        )
    with technology_col:
        technology = st.text_input(
            "Technologie, vendor ou produit",
            placeholder="Ex : Fortinet, Windows, Exchange",
            key="cve_technology_filter",
        )
        kev_only = st.checkbox("KEV uniquement", key="cve_kev_only")
    with options_col:
        sort_label = st.selectbox(
            "Trier par",
            ["Plus recentes", "Plus critiques", "EPSS le plus eleve"],
            key="cve_sort",
        )
        page_size = st.selectbox(
            "Resultats par page",
            [100, 250, 500],
            key="cve_page_size",
        )

    if date_from_value > date_to_value:
        st.warning("La date de debut est apres la date de fin.")
        return

    date_from = datetime.combine(date_from_value, time.min, tzinfo=timezone.utc)
    date_to = datetime.combine(date_to_value, time.max, tzinfo=timezone.utc)
    sort_by = {
        "Plus recentes": "published_at",
        "Plus critiques": "cvss",
        "EPSS le plus eleve": "epss",
    }[sort_label]
    filter_key = (
        f"{date_from_value}_{date_to_value}_{technology.strip().lower()}_"
        f"{kev_only}_{sort_by}_{page_size}"
    )

    with Session(engine) as session:
        first_page = search_cve_page(
            session,
            date_from=date_from,
            date_to=date_to,
            technology=technology,
            kev_only=kev_only,
            sort_by=sort_by,
            limit=page_size,
            offset=0,
        )
        total = first_page["total"]
        total_pages = max(1, (total + page_size - 1) // page_size)
        page = int(
            st.number_input(
                f"Page sur {total_pages}",
                min_value=1,
                max_value=total_pages,
                value=1,
                step=1,
                key=f"cve_page_{filter_key}",
            )
        )
        page_data = first_page
        if page > 1:
            page_data = search_cve_page(
                session,
                date_from=date_from,
                date_to=date_to,
                technology=technology,
                kev_only=kev_only,
                sort_by=sort_by,
                limit=page_size,
                offset=(page - 1) * page_size,
            )

    st.caption(f"{total:,} CVE trouvees - Page {page} / {total_pages}".replace(",", " "))
    if not page_data["items"]:
        st.info("Aucune CVE ne correspond aux filtres selectionnes.")
        return

    rows = []
    for item in page_data["items"]:
        rows.append(format_cve_row(item["cve"], item["products"]))
    st.dataframe(rows, use_container_width=True, hide_index=True)


def clear_company_table_state(
    company_id: int | None,
    *,
    assets: bool = True,
    findings: bool = True,
) -> None:
    if assets:
        st.session_state.pop(EDITING_ASSETS_KEY, None)
        st.session_state.pop(PENDING_ASSET_DELETE_KEY, None)
        if company_id is not None:
            revision_key = f"asset_editor_revision_{company_id}"
            st.session_state[revision_key] = st.session_state.get(revision_key, 0) + 1
    if findings:
        st.session_state.pop(EDITING_FINDINGS_KEY, None)
        st.session_state.pop(PENDING_FINDING_IGNORE_KEY, None)
        if company_id is not None:
            revision_key = f"finding_editor_revision_{company_id}"
            st.session_state[revision_key] = st.session_state.get(revision_key, 0) + 1


def selected_editor_values(editor_data, value_column: str) -> list:
    records = (
        editor_data.to_dict("records")
        if hasattr(editor_data, "to_dict")
        else editor_data
    )
    return list(
        dict.fromkeys(
            row[value_column]
            for row in records
            if row.get("Sélection") and row.get(value_column) is not None
        )
    )


def render_company_tab(companies: list[Company]) -> None:
    st.subheader("Suivi des entreprises")
    company_message = st.session_state.pop(COMPANY_MESSAGE_KEY, None)
    if company_message:
        level, message = company_message
        if level == "success":
            st.success(message)
        else:
            st.info(message)

    with st.expander("Creer une entreprise", expanded=not companies):
        name = st.text_input("Nom", key="company_create_name")
        sector = st.text_input("Secteur", key="company_create_sector")
        country = st.text_input("Pays", value="France", key="company_create_country")
        if st.button("Creer", key="create_company"):
            if name:
                with Session(engine) as session:
                    session.add(Company(name=name, sector=sector, country=country))
                    session.commit()
                st.session_state[COMPANY_MESSAGE_KEY] = (
                    "success",
                    f"Entreprise creee : {name}",
                )
                st.rerun()
            else:
                st.error("Le nom est obligatoire.")

    if not companies:
        st.info("Commence par creer une entreprise ci-dessus.")
        return

    company_labels = {f"{c.id} - {c.name}": c.id for c in companies}
    selected_label = st.selectbox(
        "Entreprise",
        list(company_labels.keys()),
        key="selected_company",
    )
    company_id = company_labels[selected_label]
    company_name = next(company.name for company in companies if company.id == company_id)
    previous_company_id = st.session_state.get(ACTIVE_COMPANY_KEY)
    if previous_company_id != company_id:
        clear_company_table_state(previous_company_id)
        st.session_state.pop(PENDING_COMPANY_DELETE_KEY, None)
        st.session_state[ACTIVE_COMPANY_KEY] = company_id

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

                    clear_company_table_state(company_id, findings=False)
                    st.success("Asset ajoute.")
            else:
                st.error("La valeur est obligatoire.")

    with col2:
        st.subheader("Actions")

        if st.button("Lancer collecte vulnerabilites"):
            clear_company_table_state(company_id)
            ids = collect_for_company(company_id)
            st.success(f"{len(ids)} findings crees.")

        if st.button("Generer rapport Markdown"):
            path = generate_company_report(company_id)
            st.success(f"Rapport genere : {path}")
            st.code(path)

    with Session(engine) as session:
        assets = session.exec(
            select(Asset).where(Asset.company_id == company_id)
        ).all()
        finding_records = get_company_cve_findings(session, company_id)
        ignored_finding_records = get_company_cve_findings(
            session,
            company_id,
            ignored_only=True,
        )

    st.divider()
    assets_title_col, assets_action_col = st.columns([5, 1])
    with assets_title_col:
        st.subheader("Assets surveilles")

    technology_assets = [
        asset for asset in assets if asset.asset_type.lower() == "technology"
    ]
    editing_assets = st.session_state.get(EDITING_ASSETS_KEY) == company_id
    with assets_action_col:
        if technology_assets and not editing_assets:
            if st.button(
                "Modifier",
                key=f"edit_assets_{company_id}",
                use_container_width=True,
            ):
                clear_company_table_state(company_id, findings=False)
                st.session_state[EDITING_ASSETS_KEY] = company_id
                st.rerun()

    if assets and not editing_assets:
        st.dataframe(
            [{"type": a.asset_type, "value": a.value} for a in assets],
            use_container_width=True,
            hide_index=True,
        )
    elif not assets:
        st.info("Aucun asset pour cette entreprise.")

    selected_asset_ids = []
    if editing_assets:
        asset_editor_revision = st.session_state.get(
            f"asset_editor_revision_{company_id}",
            0,
        )
        edited_assets = st.data_editor(
            [
                {
                    "Sélection": False,
                    "_asset_id": asset.id,
                    "type": asset.asset_type,
                    "value": asset.value,
                }
                for asset in technology_assets
            ],
            use_container_width=True,
            hide_index=True,
            num_rows="fixed",
            disabled=["_asset_id", "type", "value"],
            column_order=["Sélection", "type", "value"],
            column_config={
                "Sélection": st.column_config.CheckboxColumn(
                    "Sélection",
                    default=False,
                ),
                "_asset_id": None,
            },
            key=f"asset_editor_{company_id}_{asset_editor_revision}",
        )
        selected_asset_ids = selected_editor_values(edited_assets, "_asset_id")
        delete_col, cancel_col = st.columns(2)
        with delete_col:
            if st.button(
                "Supprimer la selection",
                disabled=not selected_asset_ids,
                key=f"request_asset_selection_delete_{company_id}",
            ):
                selected_assets_by_id = {asset.id: asset for asset in technology_assets}
                st.session_state[PENDING_ASSET_DELETE_KEY] = {
                    "company_id": company_id,
                    "asset_ids": selected_asset_ids,
                    "technologies": [
                        selected_assets_by_id[asset_id].value
                        for asset_id in selected_asset_ids
                    ],
                }
        with cancel_col:
            if st.button(
                "Annuler",
                key=f"cancel_asset_editing_{company_id}",
            ):
                clear_company_table_state(company_id, findings=False)
                st.rerun()

    pending_assets = st.session_state.get(PENDING_ASSET_DELETE_KEY)
    if pending_assets and pending_assets["company_id"] == company_id:
        st.warning(
            f"Supprimer {len(pending_assets['asset_ids'])} technologie(s) de "
            f"{company_name} ?"
        )
        st.markdown("\n".join(f"- {value}" for value in pending_assets["technologies"]))
        confirm_col, cancel_col = st.columns(2)
        with confirm_col:
            if st.button(
                "Confirmer",
                type="primary",
                key=f"confirm_asset_selection_delete_{company_id}",
            ):
                result = delete_company_technologies(
                    company_id,
                    pending_assets["asset_ids"],
                    db_engine=engine,
                )
                clear_company_table_state(company_id, findings=False)
                st.session_state[COMPANY_MESSAGE_KEY] = (
                    "success",
                    f"{result['deleted_assets']} technologie(s) supprimee(s) - "
                    f"{result['deleted_findings']} finding(s) associe(s) supprime(s).",
                )
                st.rerun()
        with cancel_col:
            if st.button(
                "Annuler",
                key=f"cancel_asset_selection_delete_{company_id}",
            ):
                st.session_state.pop(PENDING_ASSET_DELETE_KEY, None)
                st.rerun()

    st.divider()
    findings_title_col, findings_action_col = st.columns([5, 1])
    with findings_title_col:
        st.subheader("Vulnerabilites detectees")

    editing_findings = st.session_state.get(EDITING_FINDINGS_KEY) == company_id
    with findings_action_col:
        if finding_records and not editing_findings:
            if st.button(
                "Modifier",
                key=f"edit_findings_{company_id}",
                use_container_width=True,
            ):
                clear_company_table_state(company_id, assets=False)
                st.session_state[EDITING_FINDINGS_KEY] = company_id
                st.rerun()

    if finding_records:
        finding_rows = format_company_finding_rows(
            finding_records,
            cve_as_link=True,
        )
        cve_link_config = st.column_config.LinkColumn(
            "CVE",
            display_text=r"https://nvd\.nist\.gov/vuln/detail/(CVE-\d{4}-\d+)",
        )
        if not editing_findings:
            st.dataframe(
                finding_rows,
                use_container_width=True,
                hide_index=True,
                column_config={"CVE": cve_link_config},
            )
        else:
            finding_editor_revision = st.session_state.get(
                f"finding_editor_revision_{company_id}",
                0,
            )
            editor_rows = [
                {
                    "Sélection": False,
                    "_cve_id": record["finding"].cve_id,
                    **row,
                }
                for record, row in zip(finding_records, finding_rows)
            ]
            edited_findings = st.data_editor(
                editor_rows,
                use_container_width=True,
                hide_index=True,
                num_rows="fixed",
                disabled=list(finding_rows[0]),
                column_order=["Sélection", *finding_rows[0]],
                column_config={
                    "Sélection": st.column_config.CheckboxColumn(
                        "Sélection",
                        default=False,
                    ),
                    "_cve_id": None,
                    "CVE": cve_link_config,
                },
                key=f"finding_editor_{company_id}_{finding_editor_revision}",
            )
            selected_cve_ids = selected_editor_values(edited_findings, "_cve_id")
            ignore_col, cancel_col = st.columns(2)
            with ignore_col:
                if st.button(
                    "Ignorer la selection",
                    disabled=not selected_cve_ids,
                    key=f"request_finding_selection_ignore_{company_id}",
                ):
                    st.session_state[PENDING_FINDING_IGNORE_KEY] = {
                        "company_id": company_id,
                        "cve_ids": selected_cve_ids,
                    }
            with cancel_col:
                if st.button(
                    "Annuler",
                    key=f"cancel_finding_editing_{company_id}",
                ):
                    clear_company_table_state(company_id, assets=False)
                    st.rerun()
    else:
        st.info("Aucun finding pour le moment.")

    pending_findings = st.session_state.get(PENDING_FINDING_IGNORE_KEY)
    if pending_findings and pending_findings["company_id"] == company_id:
        st.warning(
            f"Ignorer {len(pending_findings['cve_ids'])} CVE pour {company_name} ?"
        )
        st.markdown("\n".join(f"- {cve_id}" for cve_id in pending_findings["cve_ids"]))
        confirm_col, cancel_col = st.columns(2)
        with confirm_col:
            if st.button(
                "Confirmer",
                type="primary",
                key=f"confirm_finding_selection_ignore_{company_id}",
            ):
                result = ignore_company_cves(
                    company_id,
                    pending_findings["cve_ids"],
                    db_engine=engine,
                )
                clear_company_table_state(company_id, assets=False)
                st.session_state[COMPANY_MESSAGE_KEY] = (
                    "success",
                    f"{result['created']} CVE ajoutee(s) aux exclusions de "
                    f"{company_name}.",
                )
                st.rerun()
        with cancel_col:
            if st.button(
                "Annuler",
                key=f"cancel_finding_selection_ignore_{company_id}",
            ):
                st.session_state.pop(PENDING_FINDING_IGNORE_KEY, None)
                st.rerun()

    with st.expander(f"CVE ignorees ({len(ignored_finding_records)})"):
        if ignored_finding_records:
            ignored_rows = format_company_finding_rows(
                ignored_finding_records,
                cve_as_link=True,
            )
            st.dataframe(
                ignored_rows,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "CVE": st.column_config.LinkColumn(
                        "CVE",
                        display_text=r"https://nvd\.nist\.gov/vuln/detail/(CVE-\d{4}-\d+)",
                    ),
                },
            )
            restore_options = sorted(
                {
                    record["finding"].cve_id
                    for record in ignored_finding_records
                    if record["finding"].cve_id
                }
            )
            selected_restore_cve = st.selectbox(
                "CVE a restaurer",
                restore_options,
                key=f"cve_to_restore_{company_id}",
            )
            if st.button(
                "Restaurer cette CVE",
                key=f"restore_cve_{company_id}",
            ):
                restored = restore_company_cve(
                    company_id,
                    selected_restore_cve,
                    db_engine=engine,
                )
                st.session_state[COMPANY_MESSAGE_KEY] = (
                    "success" if restored else "info",
                    (
                        f"CVE restauree : {selected_restore_cve}"
                        if restored
                        else "Cette CVE n'etait pas ignoree."
                    ),
                )
                st.rerun()
        else:
            st.info("Aucune CVE ignoree pour cette entreprise.")

    st.divider()
    st.subheader("Gestion de l'entreprise")
    if st.button(
        "Supprimer cette entreprise",
        key=f"request_company_delete_{company_id}",
    ):
        st.session_state[PENDING_COMPANY_DELETE_KEY] = {
            "company_id": company_id,
            "company_name": company_name,
        }

    pending_company = st.session_state.get(PENDING_COMPANY_DELETE_KEY)
    if pending_company and pending_company["company_id"] == company_id:
        st.warning(
            f"Supprimer definitivement {pending_company['company_name']} de CyberSignal ? "
            "Cette action supprimera l'entreprise, ses assets, findings, exclusions et "
            "rapports. Le referentiel CVE global ne sera pas modifie."
        )
        confirm_col, cancel_col = st.columns(2)
        with confirm_col:
            if st.button(
                "Confirmer la suppression de l'entreprise",
                type="primary",
                key=f"confirm_company_delete_{company_id}",
            ):
                company_name = pending_company["company_name"]
                delete_company(company_id, db_engine=engine)
                clear_company_table_state(company_id)
                st.session_state.pop(ACTIVE_COMPANY_KEY, None)
                st.session_state.pop(PENDING_COMPANY_DELETE_KEY, None)
                st.session_state[COMPANY_MESSAGE_KEY] = (
                    "success",
                    f"Entreprise supprimee : {company_name}",
                )
                st.rerun()
        with cancel_col:
            if st.button(
                "Annuler",
                key=f"cancel_company_delete_{company_id}",
            ):
                st.session_state.pop(PENDING_COMPANY_DELETE_KEY, None)
                st.rerun()


def render_trends_tab() -> None:
    country_options, source_count = load_trend_source_options()

    if source_count == 0:
        st.warning("Aucune source RSS disponible dans config/sources.csv.")
        return

    controls_col, filters_col, refresh_col = st.columns([2, 2, 1])

    with controls_col:
        start_at, end_at, period_label = get_time_range_from_controls()
        max_terms = st.slider("Nombre de mots", min_value=20, max_value=80, value=50, step=5)

    with filters_col:
        country_filter = st.selectbox("Pays / zone", country_options)
        max_confident = st.select_slider("Fiabilite maximum", options=[1, 2, 3], value=3)
        max_feed_limit = max(1, min(source_count, 100))
        max_feeds = st.slider(
            "Flux charges a l'actualisation",
            min_value=1,
            max_value=max_feed_limit,
            value=min(25, max_feed_limit),
            step=1,
        )
        st.caption("Ce reglage prend effet au prochain clic sur Actualiser.")
        term_query = st.text_input("Recherche mot", placeholder="Ex : Fortinet, CVE, APT")

    with refresh_col:
        st.write("")
        st.write("")
        refresh_requested = st.button("Actualiser", use_container_width=True)

    if refresh_requested:
        load_trend_source_options.clear()
        dataset = refresh_trend_dataset(max_feeds=max_feeds)
    else:
        dataset = get_or_collect_trend_dataset(max_feeds=max_feeds)

    collected_at = dataset.get("collected_at")
    collected_label = (
        collected_at.strftime("%d/%m/%Y %H:%M UTC")
        if collected_at
        else "inconnue"
    )
    st.caption(
        f"Derniere actualisation : {collected_label} - "
        f"{dataset.get('article_count', 0)} articles analyses - "
        f"{dataset.get('term_count', 0)} mots detectes"
    )
    st.caption(f"{get_blocklist_size()} mots actuellement dans la blocklist.")

    blocklist_message = st.session_state.pop(TREND_BLOCKLIST_MESSAGE_KEY, None)

    if blocklist_message:
        level, message = blocklist_message

        if level == "success":
            st.success(message)
        else:
            st.info(message)

    if dataset.get("article_count", 0) == 0:
        st.warning("Aucun article charge. Clique sur Actualiser ou augmente le nombre de flux charges.")
        return

    terms = aggregate_trend_events(
        dataset.get("events", []),
        start_at=start_at,
        end_at=end_at,
        max_terms=max_terms,
        max_confident=max_confident,
        country_filter=country_filter,
        term_query=term_query,
    )

    if not terms:
        st.warning("Aucune tendance disponible sur cette plage temporelle.")
        return

    st.caption(
        "Articles analyses entre "
        f"{start_at.strftime('%Y-%m-%d %H:%M UTC')} et "
        f"{end_at.strftime('%Y-%m-%d %H:%M UTC')} ({period_label})."
    )
    components.html(render_word_cloud_html(terms), height=500, scrolling=False)

    st.subheader("Resume des tendances")
    st.caption("Score de fiabilite moyen : 1 = source la plus fiable, 3 = source moins fiable.")
    st.dataframe(
        [
            {
                "mot detecte": term["term"],
                "nombre d'occurrences": term["occurrence"],
                "moyenne du score de fiabilite (1 fiable - 3 faible)": term["average_confident"],
            }
            for term in terms
        ],
        use_container_width=True,
        hide_index=True,
    )

    selected_term = st.selectbox(
        "Mot a inspecter",
        [""] + [term["term"] for term in terms],
        format_func=lambda value: value or "Selectionne un mot",
    )

    if not selected_term:
        st.info("Selectionne un mot pour voir les articles associes.")
        return

    if st.button("Ajouter a la blocklist", use_container_width=False):
        if add_blocklist_word(selected_term):
            st.session_state[TREND_BLOCKLIST_MESSAGE_KEY] = (
                "success",
                f"Mot ajoute a la blocklist : {selected_term}",
            )
        else:
            st.session_state[TREND_BLOCKLIST_MESSAGE_KEY] = (
                "info",
                "Ce mot est deja dans la blocklist.",
            )

        st.rerun()

    term_details = next(
        (term for term in terms if term["term"] == selected_term),
        None,
    )

    if not term_details or not term_details["articles"]:
        st.info("Aucun article associe disponible pour ce mot.")
        return

    st.subheader(f"Articles associes a {selected_term}")
    st.dataframe(
        [
            {
                "titre": article["title"] or "Article sans titre",
                "source": article["source"] or "Source inconnue",
                "score de fiabilite": article["confident"],
                "date": article["published"] or "Date inconnue",
                "lien": article["url"] or "",
            }
            for article in term_details["articles"]
        ],
        use_container_width=True,
        hide_index=True,
        column_config={
            "lien": st.column_config.LinkColumn(
                "lien",
                display_text="ouvrir l'article",
            ),
        },
    )


st.title("CyberSignal")
st.caption("MVP local de veille d'exposition cyber pour PME/ETI")

with Session(engine) as session:
    companies = session.exec(select(Company)).all()

cve_tab, company_tab, trends_tab = st.tabs(
    ["Recherche CVE", "Suivi entreprise", "Tendances vulnérabilités"]
)

with cve_tab:
    render_cve_search()

with company_tab:
    render_company_tab(companies)

with trends_tab:
    render_trends_tab()
