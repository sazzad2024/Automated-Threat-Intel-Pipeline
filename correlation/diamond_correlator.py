import psycopg2
from psycopg2.extras import RealDictCursor
import os
import logging
import sys

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("DiamondCorrelator")

class DiamondCorrelator:
    def __init__(self):
        self.db_name = os.getenv("DB_NAME")
        self.db_user = os.getenv("DB_USER")
        self.db_pass = os.getenv("DB_PASS")
        self.db_host = os.getenv("DB_HOST")
        self.db_port = os.getenv("DB_PORT")
        self.conn = None
        self._connect()

    def _connect(self):
        try:
            self.conn = psycopg2.connect(
                dbname=self.db_name,
                user=self.db_user,
                password=self.db_pass,
                host=self.db_host,
                port=self.db_port
            )
            logger.info("Database connection established successfully.")
        except psycopg2.Error as e:
            logger.error(f"Failed to connect to database: {e}")
            raise

    def correlate_indicator(self, value, mitre_ttps=None):
        """
        Correlates a given indicator (value) against the Diamond Model database.
        
        Args:
            value (str): The indicator value (e.g., specific IP, domain).
            mitre_ttps (list): Optional list of MITRE Technique IDs observed (e.g. ['T1003']).

        Returns:
            dict: A correlation result dictionary.
        """
        logger.info(f"Processing correlation request for indicator: {value}")
        
        if not self.conn or self.conn.closed:
            logger.warning("Database connection was closed. Reconnecting...")
            self._connect()

        # 1. Existing Indicator Check (Exact Match)
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        try:
            cursor.execute("SELECT infrastructure_id, type, description FROM infrastructure WHERE value = %s", (value,))
            result = cursor.fetchone()
            
            if result:
                logger.info(f"Existing indicator found: {value} (ID: {result['infrastructure_id']})")
                
                # Pivot to Adversary via Events
                cursor.execute("""
                    SELECT a.name as adversary, e.confidence_score
                    FROM events e
                    JOIN adversaries a ON e.adversary_id = a.adversary_id
                    WHERE e.infrastructure_id = %s
                """, (result['infrastructure_id'],))
                
                matches = cursor.fetchall()
                logger.info(f"Found {len(matches)} attribution links for indicator {value}.")
                
                return {
                    "status": "known",
                    "confidence": 1.0,
                    "matches": [
                        {"type": "direct_link", "adversary": m['adversary'], "score": m['confidence_score']}
                        for m in matches
                    ]
                }
        except Exception as e:
            logger.error(f"Error querying existing indicator: {e}")
            self.conn.rollback() # Ensure transaction is clean
            cursor.close()
            return {"error": str(e)}

        # 2. Heuristic Analysis (New Indicator)
        logger.info(f"Indicator {value} not known. analyzing heuristics...")
        
        if mitre_ttps:
            logger.info(f"Analyzing {len(mitre_ttps)} observed TTPs: {mitre_ttps}")
            # Find adversaries that use these TTPs using the events/mitre tables
            
            # Simple scoring: Count how many observed TTPs match an adversary's known TTPs
            # Note: This is an intersection count.
            
            placeholders = str(tuple(mitre_ttps)).replace(",)", ")") # Tuple fmt hack '("A",)' or '("A","B")'
            
            query = f"""
                SELECT a.name, count(e.mitre_tid) as match_count
                FROM events e
                JOIN adversaries a ON e.adversary_id = a.adversary_id
                WHERE e.mitre_tid IN {placeholders}
                GROUP BY a.name
                ORDER BY match_count DESC
            """
            
            try:
                cursor.execute(query)
                candidates = cursor.fetchall()
                
                heuristic_matches = []
                total_observed = len(mitre_ttps)
                
                for cand in candidates:
                    # Score = (Matched TTPs / Total Observed TTPs)
                    score = round(cand['match_count'] / total_observed, 2)
                    heuristic_matches.append({
                        "adversary": cand['name'],
                        "matched_ttps": cand['match_count'],
                        "score": score
                    })
                
                logger.info(f"Heuristic analysis returned {len(heuristic_matches)} potential candidates.")
                
                # sort by score
                heuristic_matches.sort(key=lambda x: x['score'], reverse=True)

                return {
                    "status": "heuristic_match",
                    "confidence": heuristic_matches[0]['score'] if heuristic_matches else 0.0,
                    "matches": heuristic_matches
                }
            except Exception as e:
                logger.error(f"Error executing heuristic query: {e}")
                self.conn.rollback()
        
        logger.info("No existing match and no TTPs provided for heuristics.")
        cursor.close()
        return {"status": "unknown", "confidence": 0.0}

    def close(self):
        if self.conn:
            self.conn.close()
            logger.info("DiamondCorrelator closed.")
