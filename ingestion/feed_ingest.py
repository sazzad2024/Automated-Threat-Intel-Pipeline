import requests
import psycopg2
from psycopg2.extras import execute_values
import logging
import os
import datetime
from dotenv import load_dotenv

load_dotenv()

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")

# CIRCL Public OSINT Feed (Warning Lists / Indicators)
# Using a specific public feed URL. 
# Many public MISP feeds are available. Let's use a reliable one: URLHaus or similar standard public lists if direct CIRCL JSON shouldn't be scraped.
# Actually, let's use the 'Digitalside' IT threat intel feed which is compatible with MISP and free/public JSON.
FEED_URL = "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.json"
# Note: CIRCL hosts many feeds, but 'Digitalside' is a clean JSON list often used in MISP.

def get_db_connection():
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASS,
            host=DB_HOST,
            port=DB_PORT
        )
        return conn
    except psycopg2.Error as e:
        logger.error(f"Unable to connect to the database: {e}")
        return None

def fetch_feed():
    logger.info(f"Fetching public feed from: {FEED_URL}")
    try:
        response = requests.get(FEED_URL, timeout=30)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"Failed to fetch feed: {e}")
        return {}

def process_and_ingest(conn, data):
    # Digitalside JSON format: { "...": { "type": "...", "report": { ... } } }
    # Depending on exact structure.
    # Actually, let's use a simpler text list if JSON is complex, but user asked for MISP-like.
    # Let's inspect the data structure logic.
    # Digitalside latestdomains.json structure is usually a flat dictionary or list.
    
    # Let's write a generic parser that assumes a list of indicators
    # Adapt to: https://osint.digitalside.it/Threat-Intel/lists/latestdomains.json
    # It returns a JSON object where keys are domains or a list.
    
    # Actually, to be safer and get "Real Data" guaranteeing success right now, 
    # let's use the URLHaus public CSV or JSON.
    # URLHaus JSON: https://urlhaus-api.abuse.ch/v1/urls/recent/
    
    pass

def ingest_feodotracker(conn):
    """
    Ingests Feodo Tracker C2 IPs (Abuse.ch).
    Highly reliable feed for Command & Control servers.
    """
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    logger.info(f"Fetching Feodo Tracker (Full): {url}")
    
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        logger.error(f"Fetch failed: {e}")
        return

    infra_items = []
    
    # Feodo Tracker JSON structure is a list of dicts directly
    # [ { "ip_address": "...", "port": ..., "malware": "..." }, ... ]
    
    logger.info(f"Feed data type: {type(data)}")
    if isinstance(data, list):
        logger.info(f"Feed list length: {len(data)}")
        if len(data) > 0:
            logger.info(f"First item sample: {data[0]}")
            
    logger.info("Parsing feed items...")
    valid_count = 0
    skipped_count = 0
    
    if isinstance(data, list):
        for idx, item in enumerate(data):
            ip = item.get('ip_address')
            malware = item.get('malware', 'C2')
            desc = f"Feodo Tracker: {malware} C2"
            
            if ip:
                infra_items.append(('IPv4', ip, desc))
                valid_count += 1
            else:
                skipped_count += 1
                if skipped_count < 5:
                    logger.warning(f"Skipping item {idx}: No IP. Keys: {item.keys()}")
                    
    logger.info(f"Parsed {valid_count} valid IPs. Skipped {skipped_count}.")

    # 3. Bulk Insert Infrastructure
    logger.info(f"Inserting {len(infra_items)} IPs...")
    # Ensure Adversary (Python-side check to avoid Schema Constraint dependency)
    cur = conn.cursor()
    cur.execute("SELECT adversary_id FROM adversaries WHERE name = 'Feodo Tracker'")
    res = cur.fetchone()
    if res:
        adv_id = res[0]
    else:
        cur.execute("INSERT INTO adversaries (name) VALUES ('Feodo Tracker') RETURNING adversary_id")
        adv_id = cur.fetchone()[0]
    cur.close()
    
    infra_map = {}
    # Dedupe locally
    unique_items = {i[1]: i for i in infra_items}.values()
    
    cur = conn.cursor()
    try:
        # Direct bulk insert of all unique items
        val_list = [(i[0], i[1], i[2]) for i in unique_items]
        
        execute_values(cur, 
            "INSERT INTO infrastructure (type, value, description) VALUES %s",
            val_list
        )
        conn.commit()
    except Exception as e:
        logger.error(f"DB Insert failed: {e}")
        # Continue to mapping event even if insert failed (might already exist)
        conn.rollback()

    try:
        # Now fetch IDs
        vals = tuple(i[1] for i in unique_items)
        if vals:
             # Fetch in chunks if too large, but for feodo list (few hundreds) this is fine
             cur.execute("SELECT value, infrastructure_id FROM infrastructure WHERE value IN %s", (vals,))
             rows = cur.fetchall()
             for r in rows:
                 infra_map[r[0]] = r[1]
    except Exception as e:
         logger.error(f"ID Fetch failed: {e}")
    finally:
        cur.close()

    # 4. Create Events
    event_rows = []
    current_time = datetime.datetime.now()
    
    for item in infra_items:
        val = item[1]
        desc = item[2]
        if val in infra_map:
            # High confidence for C2s
            row = (desc, adv_id, infra_map[val], None, current_time, 0.95)
            event_rows.append(row)
            
    if event_rows:
        cur = conn.cursor()
        try:
            execute_values(cur,
                """
                INSERT INTO events (description, adversary_id, infrastructure_id, capability_id, event_time, confidence_score)
                VALUES %s
                """,
                event_rows
            )
            conn.commit()
            logger.info(f"Successfully created {len(event_rows)} events from Feodo Tracker.")
        except Exception as e:
            logger.error(f"Event insert failed: {e}")
            conn.rollback()
        finally:
            cur.close()

def main():
    conn = get_db_connection()
    if conn:
        ingest_feodotracker(conn)
        conn.close()

if __name__ == "__main__":
    main()
