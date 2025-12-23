import os
import sys
import logging
import requests
import psycopg2
from mitreattack.stix20 import MitreAttackData

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")

# Getting latest STIX data
MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

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

def download_stix_data():
    logger.info("Downloading MITRE ATT&CK STIX data...")
    try:
        response = requests.get(MITRE_STIX_URL)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"Failed to download STIX data: {e}")
        sys.exit(1)

def ingest_mitre_data():
    conn = get_db_connection()
    cur = conn.cursor()
    
    # 1. Download Data
    stix_json = download_stix_data()
    
    # 2. Initialize MitreAttackData helper
    temp_file = "enterprise-attack.json"
    with open(temp_file, "w", encoding='utf-8') as f:
        import json
        json.dump(stix_json, f)
        
    mitre_attack_data = MitreAttackData(temp_file)
    
    # 3. Process Techniques (Attack Patterns)
    logger.info("Processing Techniques...")
    techniques = mitre_attack_data.get_techniques(remove_revoked_deprecated=True)
    
    tech_count = 0
    for t in techniques:
        # standard STIX extraction
        external_references = t.get('external_references', [])
        mitre_id = next((ref['external_id'] for ref in external_references if ref.get('source_name') == 'mitre-attack'), None)
        
        if not mitre_id:
            continue
            
        name = t.get('name')
        description = t.get('description', '')
        
        # Upsert into mitre_attack_mappings
        try:
            cur.execute(
                """
                INSERT INTO mitre_attack_mappings (tid, technique_name, description)
                VALUES (%s, %s, %s)
                ON CONFLICT (tid) DO UPDATE 
                SET technique_name = EXCLUDED.technique_name, 
                    description = EXCLUDED.description
                """,
                (mitre_id, name, description)
            )
            tech_count += 1
        except Exception as e:
            logger.error(f"Error inserting technique {mitre_id}: {e}")
            conn.rollback()

    logger.info(f"Upserted {tech_count} techniques.")

    # 4. Process Adversaries (Intrusion Sets) and Relationships
    logger.info("Processing Adversaries and Relationships...")
    groups = mitre_attack_data.get_groups(remove_revoked_deprecated=True)
    
    group_count = 0
    rel_count = 0
    
    for g in groups:
        name = g.get('name')
        description = g.get('description', '')
        aliases = g.get('aliases', [])
        
        # Insert Adversary (ensure cleaned up from transaction issues)
        cur.execute(
            """
            INSERT INTO adversaries (name, description, aliases)
            VALUES (%s, %s, %s)
            ON CONFLICT DO NOTHING
            RETURNING adversary_id
            """,
            (name, description, aliases)
        )
        
        # Since we can't easily ON CONFLICT RETURNING if nothing inserted (in older Postgres, though 15 is fine usually but requires unique constraint on name which we lack)
        # We'll just fetch ID.
        result = cur.fetchone()
        if result:
            adv_id = result[0]
        else:
             # If insert didn't happen (because of conflict check? no, we removed ON CONFLICT in original script but here strictness matters)
             # Wait, my previous script used check-then-insert.
             cur.execute("SELECT adversary_id FROM adversaries WHERE name = %s", (name,))
             res = cur.fetchone()
             if res:
                 adv_id = res[0]
             else:
                 # Should insert if not found
                 cur.execute(
                    """
                    INSERT INTO adversaries (name, description, aliases)
                    VALUES (%s, %s, %s)
                    RETURNING adversary_id
                    """,
                    (name, description, aliases)
                )
                 adv_id = cur.fetchone()[0]
        
        group_count += 1
        
        # Get Techniques used by this Group
        group_stix_id = g.get('id')
        techniques_used = mitre_attack_data.get_techniques_used_by_group(group_stix_id)
        
        for t in techniques_used:
            object_used = t['object']
            
            # We need the TID of the technique
            refs = object_used.get('external_references', [])
            tid = next((ref['external_id'] for ref in refs if ref.get('source_name') == 'mitre-attack'), None)
            
            if tid:
                 # Check if TID exists in mappings first to avoid FK violation
                 cur.execute("SELECT 1 FROM mitre_attack_mappings WHERE tid = %s", (tid,))
                 if not cur.fetchone():
                     # logger.warning(f"Skipping relationship: TID {tid} not linked.")
                     continue
                 
                 # Check if relationship exists
                 cur.execute(
                     """
                     SELECT 1 FROM events 
                     WHERE adversary_id = %s AND mitre_tid = %s
                     """,
                     (adv_id, tid)
                 )
                 if not cur.fetchone():
                     cur.execute(
                        """
                        INSERT INTO events (adversary_id, mitre_tid, description, confidence_score)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (adv_id, tid, f"Knowledge Base: {name} uses {tid}", 1.0)
                     )
                     rel_count += 1

    conn.commit()
    logger.info(f"Processed {group_count} adversaries and {rel_count} relationships.")
    
    # Cleanup
    cur.close()
    conn.close()
    if os.path.exists(temp_file):
        os.remove(temp_file)

if __name__ == "__main__":
    ingest_mitre_data()
