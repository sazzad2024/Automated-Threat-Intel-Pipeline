import os
import sys
import asyncio
import logging
import datetime
import aiohttp
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
OTX_API_KEY = os.getenv("OTX_API_KEY")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
BATCH_SIZE = 5000  # Number of rows to insert at once

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
        sys.exit(1)

async def fetch_pulses_async():
    """Fetches pulses asynchronously using aiohttp."""
    if not OTX_API_KEY:
        logger.error("OTX_API_KEY environment variable not set.")
        return []
    
    
    # Reverting to subscribed endpoint as it includes indicators
    # To force data, we rely on the fact that if we deleted the state file, it fetches from start.
    # OR we set modified_since to far past.
    # Actually, let's just use subscribed with no extra filters, relying on default behavior.
    
    url = f"{OTX_BASE_URL}/pulses/subscribed?limit=50"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers=headers, timeout=30) as response:
                response.raise_for_status()
                data = await response.json()
                results = data.get("results", [])
                if results:
                    logger.info(f"First pulse keys: {results[0].keys()}")
                    # Check if 'indicators' key exists or needs fetching
                    if 'indicators' not in results[0]:
                        logger.warning("Pulse has no 'indicators' key! Search endpoint might not return full details.")
                return results
        except Exception as e:
            logger.error(f"Async fetch failed: {e}")
            return []

def get_or_create_adversaries(conn, adversary_names):
    """
    Bulk resolves adversary names to IDs.
    Returns a dict {name: id}.
    """
    if not adversary_names:
        return {}
        
    unique_names = list(set(adversary_names))
    mapping = {}
    
    cur = conn.cursor()
    # 1. Fetch Existing
    try:
        cur.execute("SELECT name FROM adversaries WHERE name IN %s", (tuple(unique_names),))
        existing_names = set(row[0] for row in cur.fetchall())
        
        # 2. Filter New
        new_names = [name for name in unique_names if name not in existing_names]
        
        # 3. Insert New (without ON CONFLICT)
        if new_names:
            execute_values(cur, 
                "INSERT INTO adversaries (name) VALUES %s",
                [(name,) for name in new_names]
            )
            conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Error creating adversaries: {e}")
        
    # 2. Fetch all IDs
    try:
        cur.execute("SELECT name, adversary_id FROM adversaries WHERE name IN %s", (tuple(unique_names),))
        rows = cur.fetchall()
        for r in rows:
            mapping[r[0]] = r[1]
    finally:
        cur.close()
        
    return mapping

def bulk_insert_infrastructure(conn, items):
    """
    Bulk inserts infrastructure items.
    Items: list of tuples (type, value, description)
    Returns dict {value: id} 
    """
    if not items:
        return {}
    
    # Simple dedupe by value
    unique_items = {item[1]: item for item in items}.values()
    
    cur = conn.cursor()
    mapping = {}
    
    # We need IDs back. infrastructure table doesn't have a unique constraint on 'value' in schema.sql 
    # (it should, but we work with what we have). We'll assume strict append for now or try to match.
    # To be robust/scalable:
    # INSERT ... RETURNING id.
    
    values_list = [(i[0], i[1], i[2]) for i in unique_items]
    
    try:
        execute_values(cur, 
            "INSERT INTO infrastructure (type, value, description) VALUES %s",
            values_list
        )
        conn.commit()
        
        # Now fetch IDs (assumes values are unique enough or we take latest)
        vals = tuple(i[1] for i in unique_items)
        cur.execute("SELECT value, infrastructure_id FROM infrastructure WHERE value IN %s", (vals,))
        for r in cur.fetchall():
            mapping[r[0]] = r[1]
            
    except Exception as e:
        conn.rollback()
        logger.error(f"Bulk insert infra failed: {e}")
    finally:
        cur.close()
        
    return mapping

def bulk_save_events(conn, event_rows):
    """
    Bulk saves events.
    event_rows: list of (desc, adv_id, infra_id, cap_id, time, score)
    """
    if not event_rows:
        return

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
    except Exception as e:
        conn.rollback()
        logger.error(f"Bulk save events failed: {e}")
    finally:
        cur.close()

async def pipeline():
    logger.info("Starting Async/Batch Ingestion Pipeline...")
    conn = get_db_connection()
    
    # 1. Fetch (Async)
    pulses = await fetch_pulses_async()
    logger.info(f"Fetched {len(pulses)} pulses. Processing...")
    
    # 2. Prepare Data Structures
    all_adversaries = set()
    infra_buffer = []  # (type, value, desc)
    cap_buffer = []    # (name, type, desc) - Skipping caps for brevity/demo unless requested
    
    # Intermediate storage to link pulse -> indicators
    pulse_map = [] # (pulse_name, author, indicators_list)
    
    for pulse in pulses:
        author = pulse.get("author_name", "Unknown")
        all_adversaries.add(author)
        
        p_infra = []
        for ind in pulse.get("indicators", []):
            itype = ind.get("type")
            ivalue = ind.get("indicator")
            idesc = ind.get("description", "") or pulse.get("name")
            
            if itype in ["IPv4", "IPv6", "domain", "hostname", "URL", "url"]:
                item = (itype, ivalue, idesc)
                infra_buffer.append(item)
                p_infra.append(item)
        
        pulse_map.append({
            "author": author,
            "name": pulse.get("name"),
            "infra": p_infra
        })

    # 3. Bulk Insert Adversaries & Get IDs
    logger.info("Bulk processing Adversaries...")
    adv_id_map = get_or_create_adversaries(conn, list(all_adversaries))
    
    # 4. Bulk Insert Infrastructure & Get IDs
    logger.info(f"Bulk inserting {len(infra_buffer)} infrastructure items...")
    # Process in chunks of BATCH_SIZE
    total_infra = len(infra_buffer)
    infra_id_map = {}
    
    for i in range(0, total_infra, BATCH_SIZE):
        batch = infra_buffer[i : i + BATCH_SIZE]
        batch_map = bulk_insert_infrastructure(conn, batch)
        infra_id_map.update(batch_map)
        logger.info(f"Inserted batch {i}-{i+len(batch)}")

    # 5. Build & Bulk Insert Events (Linking)
    logger.info("Building Event links...")
    event_rows = []
    
    for p in pulse_map:
        adv_id = adv_id_map.get(p["author"])
        if not adv_id: continue
        
        for infra_item in p["infra"]:
            val = infra_item[1]
            infra_id = infra_id_map.get(val)
            
            if infra_id:
                # (desc, adv_id, infra_id, cap_id, time, score)
                row = (
                    f"Indicator from Pulse: {p['name']}",
                    adv_id,
                    infra_id,
                    None, # cap_id
                    datetime.datetime.now(),
                    0.8
                )
                event_rows.append(row)
    
    logger.info(f"Bulk inserting {len(event_rows)} events...")
    for i in range(0, len(event_rows), BATCH_SIZE):
        batch = event_rows[i : i + BATCH_SIZE]
        bulk_save_events(conn, batch)
        logger.info(f"Linked batch {i}-{i+len(batch)}")

    conn.close()
    logger.info("Pipeline Complete.")

def main():
    asyncio.run(pipeline())

if __name__ == "__main__":
    main()
