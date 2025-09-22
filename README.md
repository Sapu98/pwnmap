# 🗺️ Pwnmap

Pwnmap is a **Pwnagotchi plugin** and a **self-hosted map** to visualize captured Wi-Fi networks.

---

## Preview

![Pwnmap preview](raw.png)

---

## Installation

### 1) Install system packages
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
```

### 2) Clone the repository
```bash
cd /mnt/ssd
git clone https://github.com/<your-user>/pwnmap.git
cd pwnmap
```

### 3) Configure environment
Create or edit the `.env` file in the project root and add your secrets. **Do not commit this file.**

Example `.env` (values censored):
```env
WPASEC_API_KEY=<REDACTED_WPASEC_KEY>
DATABASE_URL=sqlite:////mnt/ssd/pwnmap/data/pwnmap.db
# Add any other variables your app requires
```

For systemd production use, create `/etc/pwnamap.env` (root-owned, chmod 600) with the same variables.

### 4) Create and activate virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 5) Install dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
# if there's no requirements file:
pip install "uvicorn[standard]" fastapi
```

### 6) Run the backend (test)
```bash
python -m uvicorn backend.app:app --host 0.0.0.0 --port 1337
```

Open in browser: `http://127.0.0.1:1337` (replace with your machine IP).

---

## 🔌 Pwnagotchi plugin installation

1. Copy `pwnamap_uploader.py` from the repo into your Pwnagotchi custom plugins directory (example: `/usr/local/share/pwnagotchi/custom-plugins/`).

2. Add to `config.toml` on the Pwnagotchi device:
```toml
main.plugins.pwnamap_uploader.enabled = true
main.plugins.pwnamap_uploader.server_url = "https://<your-server-domain-or-ip>/api/upload"
main.plugins.pwnamap_uploader.api_token = "<REDACTED_API_TOKEN>"
main.plugins.pwnamap_uploader.handshakes_dir = "/home/pi/handshakes/"
main.plugins.pwnamap_uploader.interval_sec = 300
main.plugins.pwnamap_uploader.faces = true
```

3. Restart Pwnagotchi:
```bash
sudo service pwnagotchi restart
```

---
