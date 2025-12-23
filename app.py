import os
import sys
import zipfile
import io
import datetime
import pandas as pd
import streamlit as st
from sqlalchemy import create_engine, text

# Import Rule Factory
sys.path.append(os.getcwd())
from response.rule_factory import generate_yara, generate_snort, generate_suricata
from dotenv import load_dotenv

# Load Env
load_dotenv()

# Configuration
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")

# Page Config
st.set_page_config(
    page_title="Automated Threat Intel Pipeline",
    page_icon="🛡️",
    layout="wide"
)

# Database Connection (SQLAlchemy)
@st.cache_resource
def get_db_engine():
    try:
        # Construct Database URL
        db_url = f"postgresql+psycopg2://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
        engine = create_engine(db_url)
        return engine
    except Exception as e:
        st.error(f"Unable to create database engine: {e}")
        return None

def fetch_data(query_str, params=None):
    engine = get_db_engine()
    if not engine:
        return pd.DataFrame()
    try:
        # Use pandas read_sql for cleaner DF and param handling
        # pandas read_sql using sqlalchemy connection supports params safely
        with engine.connect() as conn:
            # We use text(query_str) for SQLAlchmey 2.0 compatibility
            # params should be a dict
            df = pd.read_sql(text(query_str), conn, params=params)
            return df
    except Exception as e:
        st.error(f"Query failed: {e}")
        return pd.DataFrame()

# --- Sidebar ---
st.sidebar.title("Automated Threat Intel Pipeline🛡️")
st.sidebar.markdown("---")

# Adversary Selector
adv_df = fetch_data("SELECT name FROM adversaries ORDER BY name")
adversary_names = adv_df['name'].tolist() if not adv_df.empty else []
selected_adversary = st.sidebar.selectbox("Select Adversary", ["All"] + adversary_names)

# --- Main Content ---
st.title("Threat Intelligence Dashboard")

# KPIs
col1, col2, col3 = st.columns(3)

# KPI 1
adv_count_df = fetch_data("SELECT count(*) as c FROM adversaries")
total_adv_count = adv_count_df.iloc[0]['c'] if not adv_count_df.empty else 0
col1.metric("Total Adversaries Tracked", total_adv_count)

# KPI 2
ioc_count_df = fetch_data("SELECT count(*) as c FROM infrastructure")
total_inf_count = ioc_count_df.iloc[0]['c'] if not ioc_count_df.empty else 0
col2.metric("Total IOCs", total_inf_count)

# KPI 3
event_count_df = fetch_data("SELECT count(*) as c FROM events")
total_events_count = event_count_df.iloc[0]['c'] if not event_count_df.empty else 0
col3.metric("Total Events/TTP Links", total_events_count)

st.markdown("---")

# Main Table Logic
if selected_adversary == "All":
    st.subheader("All Infrastructure")
    query = """
    SELECT i.value, i.type, i.description, a.name as adversary, e.event_time
    FROM infrastructure i
    JOIN events e ON i.infrastructure_id = e.infrastructure_id
    JOIN adversaries a ON e.adversary_id = a.adversary_id
    ORDER BY e.event_time DESC LIMIT 100
    """
    df = fetch_data(query)
    if not df.empty:
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No linked infrastructure found.")

else:
    st.subheader(f"Campaign: {selected_adversary}")
    
    # Get Adversary Details
    # PARAMETERIZED QUERY: Sage usage of :name
    adv_details = fetch_data("SELECT description FROM adversaries WHERE name = :name", {"name": selected_adversary})
    if not adv_details.empty:
        st.markdown(f"**Description:** {adv_details.iloc[0]['description']}")
    
    # Get Linked Infrastructure
    infra_query = """
    SELECT i.infrastructure_id, i.value, i.type, i.description
    FROM infrastructure i
    JOIN events e ON i.infrastructure_id = e.infrastructure_id
    JOIN adversaries a ON e.adversary_id = a.adversary_id
    WHERE a.name = :name
    """
    inf_df = fetch_data(infra_query, {"name": selected_adversary})
    
    # Get Linked TTPs
    ttp_query = """
    SELECT m.tid, m.technique_name, m.description
    FROM mitre_attack_mappings m
    JOIN events e ON m.tid = e.mitre_tid
    JOIN adversaries a ON e.adversary_id = a.adversary_id
    WHERE a.name = :name
    """
    ttp_df = fetch_data(ttp_query, {"name": selected_adversary})
    
    col_inf, col_ttp = st.columns(2)
    
    with col_inf:
        st.write("### Linked Infrastructure")
        if not inf_df.empty:
            st.dataframe(inf_df, use_container_width=True)
        else:
            st.warning("No known infrastructure for this adversary.")
            
    with col_ttp:
        st.write("### Linked TTPs")
        if not ttp_df.empty:
            st.dataframe(ttp_df, use_container_width=True)
        else:
            st.warning("No mapped TTPs.")
            
    # --- Export Detection Pack ---
    st.markdown("---")
    st.subheader("Response Action")
    
    if st.button("Export Detection Pack 📦"):
        # Gather data for rules
        ips = []
        hashes = []
        if not inf_df.empty:
            ips = inf_df[inf_df['type'].isin(['IPv4', 'domain', 'URL'])]['value'].tolist()
            hashes = inf_df[inf_df['type'] == 'FileHash-SHA256']['value'].tolist()
        
        # Generate Rules
        yara_rules = generate_yara(hashes, selected_adversary)
        snort_rules = generate_snort(ips, selected_adversary)
        suricata_rules = generate_suricata(ips, selected_adversary)
        
        # Zip them
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr(f"{selected_adversary}_yara.yar", yara_rules)
            zf.writestr(f"{selected_adversary}_snort.rules", snort_rules)
            zf.writestr(f"{selected_adversary}_suricata.rules", suricata_rules)
            
        st.download_button(
            label="Download Rules.zip",
            data=zip_buffer.getvalue(),
            file_name=f"{selected_adversary}_rules.zip",
            mime="application/zip"
        )
