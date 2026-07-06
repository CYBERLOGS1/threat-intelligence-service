"""
Streamlit web dashboard for the Threat Intel Service.

Run with:
    streamlit run streamlit_app.py

Reads/writes the same SQLite database as ti_service.py, so the CLI and this
dashboard can be used interchangeably (e.g. cron runs `ti_service.py update`
in the background, and you browse the results here).
"""

import pandas as pd
import plotly.express as px
import streamlit as st

import config
from core import checker
from core import feeds as feed_module
from core.database import TIDatabase

st.set_page_config(
    page_title="Threat Intel Dashboard",
    page_icon="🛡️",
    layout="wide",
)


@st.cache_resource
def get_db():
    return TIDatabase(config.DB_PATH)


db = get_db()

if "data_version" not in st.session_state:
    st.session_state.data_version = 0


@st.cache_data(ttl=15)
def load_stats(_version):
    return db.stats()


@st.cache_data(ttl=15)
def load_all(_version, limit=5000):
    rows = db.all_indicators(limit=limit)
    return pd.DataFrame(rows)


@st.cache_data(ttl=15)
def load_history(_version):
    return db.ingestion_history()


def bump_version():
    st.session_state.data_version += 1


# ---------------------------------------------------------------- Sidebar --
with st.sidebar:
    st.title("🛡️ Threat Intel")
    st.caption("Personal IOC pipeline")

    if st.button("🔄 Refresh view", width="stretch"):
        bump_version()
        st.rerun()

    st.divider()
    st.subheader("Update Feeds")
    feed_options = list(config.FEEDS.keys())
    selected_feeds = st.multiselect("Feeds to pull", feed_options, default=feed_options)

    if st.button("⬇️ Pull Now", type="primary", width="stretch"):
        if not selected_feeds:
            st.warning("Select at least one feed.")
        else:
            progress = st.progress(0, text="Starting...")
            for i, name in enumerate(selected_feeds):
                meta = config.FEEDS[name]
                progress.progress(i / len(selected_feeds), text=f"Pulling {name}...")
                records, error = feed_module.fetch_and_parse(name, meta["url"])
                if error:
                    db.record_feed_run(name, 0, "error", error)
                    st.error(f"{name}: {error}")
                else:
                    count = db.bulk_upsert(records)
                    db.record_feed_run(name, count, "ok")
                    st.success(f"{name}: {count} indicators")
            progress.progress(1.0, text="Done")
            bump_version()
            st.rerun()

    st.divider()
    st.subheader("🔍 Quick IOC Check")
    ioc_input = st.text_input("IP / domain / URL / hash", placeholder="185.220.101.5")
    if ioc_input:
        result = checker.verdict(ioc_input, db)
        if result["malicious"]:
            st.error(f"MALICIOUS (confidence {result['max_confidence']})")
            for m in result["matches"]:
                st.caption(f"• {m['source']} — {m.get('threat_type', '')} "
                           f"({m['confidence']})")
        else:
            st.success("Clean — no match found")

    st.divider()
    st.caption("Data refreshes automatically every 15s, or click Refresh view.")

# ------------------------------------------------------------- Main area --
stats = load_stats(st.session_state.data_version)

st.title("Threat Intelligence Dashboard")

col1, col2, col3, col4 = st.columns(4)
by_type_map = {r["ioc_type"]: r["c"] for r in stats["by_type"]}
col1.metric("Total Indicators", stats["total"])
col2.metric("IPs / CIDRs", by_type_map.get("ip", 0) + by_type_map.get("cidr", 0))
col3.metric("URLs / Domains", by_type_map.get("url", 0) + by_type_map.get("domain", 0))
col4.metric("Hashes", by_type_map.get("hash", 0))

st.divider()

c1, c2 = st.columns(2)
with c1:
    st.subheader("By Type")
    if stats["by_type"]:
        df_type = pd.DataFrame(stats["by_type"])
        fig = px.bar(df_type, x="ioc_type", y="c",
                     labels={"ioc_type": "Type", "c": "Count"})
        fig.update_layout(margin=dict(t=10, b=10))
        st.plotly_chart(fig, width="stretch")
    else:
        st.info("No data yet — pull a feed from the sidebar to get started.")

with c2:
    st.subheader("By Source")
    if stats["by_source"]:
        df_source = pd.DataFrame(stats["by_source"])
        fig2 = px.bar(df_source, x="source", y="c",
                      labels={"source": "Source", "c": "Count"})
        fig2.update_layout(margin=dict(t=10, b=10))
        st.plotly_chart(fig2, width="stretch")
    else:
        st.info("No data yet.")

st.divider()

st.subheader("Feed Health")
history = load_history(st.session_state.data_version)
if history:
    df_hist = pd.DataFrame(history)
    st.dataframe(
        df_hist[["feed_name", "run_time", "records_pulled", "status", "message"]],
        width="stretch",
        hide_index=True,
    )
else:
    st.info("No feed runs recorded yet.")

st.divider()

st.subheader("Indicators")
df_all = load_all(st.session_state.data_version)
if df_all.empty:
    st.info("No indicators stored yet. Use the sidebar to pull feeds.")
else:
    fcol1, fcol2, fcol3 = st.columns([1, 1, 2])
    with fcol1:
        type_filter = st.multiselect("Type", sorted(df_all["ioc_type"].unique()))
    with fcol2:
        source_filter = st.multiselect("Source", sorted(df_all["source"].unique()))
    with fcol3:
        search_term = st.text_input("Search value contains...")

    filtered = df_all
    if type_filter:
        filtered = filtered[filtered["ioc_type"].isin(type_filter)]
    if source_filter:
        filtered = filtered[filtered["source"].isin(source_filter)]
    if search_term:
        filtered = filtered[filtered["value"].str.contains(search_term, case=False, na=False)]

    st.caption(f"Showing {len(filtered)} of {len(df_all)} indicators")
    st.dataframe(
        filtered[["value", "ioc_type", "source", "threat_type",
                  "confidence", "last_seen", "tags"]],
        width="stretch",
        hide_index=True,
        height=400,
    )

    csv_bytes = filtered.to_csv(index=False).encode("utf-8")
    st.download_button("Download filtered CSV", csv_bytes, "indicators.csv", "text/csv")
