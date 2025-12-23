# Automated Threat Intel Pipeline (TIP)

A scalable, automated Threat Intelligence Platform designed to ingest, correlate, and act on threat data in real-time. This system aggregates 63,000+ IOCs, maps them to MITRE ATT&CK TTPs, and generates actionable defense rules (Suricata/Snort).

![Dashboard Screenshot](https://via.placeholder.com/800x400?text=Dashboard+Screenshot+Here)  
*(Replace this with a real screenshot of your Streamlit Dashboard)*

## 🚀 Key Features

*   **Multi-Source Ingestion**:
    *   **AlienVault OTX**: High-volume community threat data (IPs, Domains).
    *   **Feodo Tracker**: High-fidelity C2 botnet detection.
    *   **MISP**: Organization-specific event attributes.
*   **Adversary Profiling**: Uses the **Diamond Model** to correlate raw infrastructure (IPs) with Adversaries (e.g., APT28) and their Techniques.
*   **Automated Enrichment**: Maps threats to **MITRE ATT&CK Enterprise Matrix** context.
*   **Defense Generation**: One-click export of **Suricata**, **Snort**, and **YARA** rules.
*   **Analyst Dashboard**: Built with **Streamlit** for rapid searching and visualization.

## 🛠️ Tech Stack

*   **Backend**: Python 3.9+, AsyncIO (aiohttp)
*   **Database**: PostgreSQL 15 (Dockerized)
*   **Frontend**: Streamlit
*   **Security**: Parameterized SQL queries, Environment-based config

## 📦 Installation

### Prerequisites
*   Docker & Docker Compose
*   Python 3.9+
*   Git

### Steps

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/YOUR_USERNAME/Automated-Threat-Intel-Pipeline.git
    cd Automated-Threat-Intel-Pipeline
    ```

2.  **Environment Setup**
    Create a `.env` file for your API keys (see `.env.example` if available, or just use variables below):
    ```ini
    OTX_API_KEY=your_key_here
    DB_NAME=threat_meta
    DB_USER=postgres
    DB_PASS=postgres
    ```

3.  **Start Infrastructure**
    ```bash
    docker-compose up -d
    ```

4.  **Install Dependencies**
    ```bash
    python -m venv venv
    .\venv\Scripts\activate   # Windows
    pip install -r requirements.txt
    ```

## ⚡ Usage

### 1. Ingest Data
Run the ingestion pipelines to populate the database:
```bash
# Volume Data
python ingestion/otx_ingest.py

# Context Data
python ingestion/mitre_ingest.py

# High-Fidelity Data
python ingestion/feed_ingest.py
```

### 2. Launch Dashboard
Start the analysis UI:
```bash
streamlit run app.py
```
Access the dashboard at `http://localhost:8501`.

## 🛡️ Architecture (Star Schema)

The database uses a central `events` table to link entities:
*   `infrastructure` (IP/Domain)
*   `adversaries` (Who)
*   `mitre_attack_mappings` (TTPs)

This enables complex queries like *"Find all IPs used by adversaries who employ Credential Dumping"*.

## 📄 License
MIT License.
