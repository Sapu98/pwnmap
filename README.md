# 🗺️ Pwnmap

Pwnmap is a Pwnagotchi plugin and a self-hosted map to visualize captured networks.  

---

## Preview

![Pwnmap preview](raw.png)

##Pwnmap Installation

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git

git clone https://github.com/Sapu98/pwnmap
cd Pwnamap

# edit the .env file with your TOKENS from wpa-sec and other preferences

# create and activate venv
python3 -m venv .venv
source .venv/bin/activate

# install deps
pip install --upgrade pip
pip install -r requirements.txt
pip install "uvicorn[standard]" fastapi

python -m uvicorn backend.app:app --host 0.0.0.0 --port 1337

visit http://127.0.0.1:1337 # replace 127.0.0.1 with whatever ip your machien is using

#Optional but stronly suggested: use a reverse proxy such as Nginx to access your map and protect the server with apache2 password.

##Plugin installation
copy the plugin pwnamap_uploader.py from the repo folder to your pwnagotchi

add the following lines to yout config.toml:

main.plugins.pwnamap_uploader.enabled = true
main.plugins.pwnamap_uploader.server_url = "https://(your ip)/api/upload"
main.plugins.pwnamap_uploader.api_token = "SAME TOKEN AS IN THE .ENV"
main.plugins.pwnamap_uploader.handshakes_dir = "/home/pi/handshakes/"
main.plugins.pwnamap_uploader.interval_sec = 300
main.plugins.pwnamap_uploader.faces = true

sudo service pwnagotchi restart
