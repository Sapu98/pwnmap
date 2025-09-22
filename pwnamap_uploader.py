# plugin/pwnamap_uploader.py
# Pwnagotchi plugin: uploads .pcap + .gps.json (ENTRAMBI i file) al backend
# Versione "low-power essentials" con:
# - Sleep stop-aware (Event.wait)
# - requests.Session() con keep-alive
# - Backoff lungo con jitter
# - File stability check
# - Check rete agnostico interfaccia (funziona con Wi-Fi, BT tethering, USB)
# - UI face/status solo su cambi di stato
#
# NOTE:
#  - Config consigliata per test in .toml:
#      interval_sec = 120
#    poi riportare a 600–900 per risparmio su Zero W.
#
#  - Richiede: requests, pwnagotchi.plugins

import os
import time
import glob
import logging
import threading
import socket
import random
from typing import Set, Tuple, Optional, Dict, Any

import requests
from pwnagotchi import plugins

DEFAULT_LIST_PATH = "/home/pi/.pwnamap_uploaded.list"
DEFAULT_HANDSHAKES_DIR = "/home/pi/handshakes"


def read_uploaded_list(path: str) -> Set[str]:
    paths: Set[str] = set()
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                ln = ln.strip()
                if ln:
                    paths.add(ln)
    return paths


def append_uploaded_list(path: str, filename: str):
    with open(path, "a", encoding="utf-8") as f:
        f.write(filename + "\n")


def find_complete_pairs(handshakes_dir: str) -> Set[Tuple[str, str]]:
    """
    Ritorna insieme di (pcap_path, gps_json_path) SOLO se entrambi esistono.
    Considera .pcap e <base>.gps.json.
    """
    pairs: Set[Tuple[str, str]] = set()
    for pcap in glob.glob(os.path.join(handshakes_dir, "*.pcap")):
        base = os.path.splitext(os.path.basename(pcap))[0]
        gps = os.path.join(handshakes_dir, base + ".gps.json")
        if os.path.isfile(gps):
            pairs.add((pcap, gps))
    return pairs


def _parse_bool(v: Any, default: bool = True) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return default
    if isinstance(v, int):
        return bool(v)
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "y", "on"):
        return True
    if s in ("0", "false", "no", "n", "off"):
        return False
    return default


def _url_host(url: str) -> Optional[str]:
    try:
        if "://" in url:
            host_port = url.split("://", 1)[1].split("/", 1)[0]
        else:
            host_port = url.split("/", 1)[0]
        return host_port.split(":")[0]
    except Exception:
        return None


def _file_is_stable(path: str, min_age_s: float = 5.0, recheck_delay_s: float = 1.0) -> bool:
    """
    Considera "stabile" se:
      - mtime è più vecchio di min_age_s, oppure
      - size e mtime non cambiano tra due letture distanziate di recheck_delay_s.
    """
    try:
        st1 = os.stat(path)
    except FileNotFoundError:
        return False
    now = time.time()
    if now - st1.st_mtime >= min_age_s:
        return True
    time.sleep(recheck_delay_s)
    try:
        st2 = os.stat(path)
    except FileNotFoundError:
        return False
    return (st1.st_size == st2.st_size) and (st1.st_mtime == st2.st_mtime)


# --- Check rete agnostico interfaccia (Wi-Fi, bnep0, USB, ecc.) ---
def _net_ok(url: str, timeout: float = 2.0) -> bool:
    host = _url_host(url)
    if not host:
        return True
    port = 443 if url.lower().startswith("https://") else 80
    try:
        # Risolve DNS e apre TCP; se va, la rete è OK per l'upload.
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class PwnamapUploader(plugins.Plugin):
    __author__ = 'sapu'
    __version__ = '0.5.1-essentials'
    __license__ = 'GPL3'
    __description__ = 'Uploads .pcap + .gps.json (entrambi) al backend Pwnamap (low-power essentials)'

    def __init__(self):
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._uploaded: Set[str] = set()
        self._lock = threading.Lock()
        self.options: Dict[str, Any] = {}
        self._session: Optional[requests.Session] = None
        self._ui_uploading = False  # evita flip UI ridondanti

    def on_loaded(self):
        logging.info("[pwnamap_uploader] plugin loaded")
        ul = self.options.get("uploaded_list_path", DEFAULT_LIST_PATH)
        self._uploaded = read_uploaded_list(ul)

    def on_ready(self, agent):
        # Avvio thread + scansione immediata
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._worker, args=(agent,), daemon=True)
        self._thread.start()

    def _set_ui_state(self, agent, uploading: bool):
        if uploading == self._ui_uploading:
            return  # evita chiamate ripetute
        self._ui_uploading = uploading
        try:
            if uploading:
                try:
                    agent.set_status("Pwnamap: uploading…")
                except Exception:
                    pass
                try:
                    if hasattr(agent, "view") and hasattr(agent.view, "set"):
                        agent.view.set("face", "(^_^)⌛")
                except Exception:
                    pass
            else:
                try:
                    agent.set_status("")
                except Exception:
                    pass
                try:
                    if hasattr(agent, "view") and hasattr(agent.view, "set"):
                        agent.view.set("face", "(^_^)")
                except Exception:
                    pass
        except Exception:
            pass

    def _worker(self, agent):
        handshakes_dir = self.options.get("handshakes_dir", DEFAULT_HANDSHAKES_DIR)
        # Intervallo alto di default per Zero W; abbassare durante i test
        interval = int(self.options.get("interval_sec", 120))  # 15 min default

        server_url = self.options.get("server_url")
        api_token = self.options.get("api_token")
        verify_ssl = _parse_bool(self.options.get("verify_ssl", True))
        ul = self.options.get("uploaded_list_path", DEFAULT_LIST_PATH)

        if not server_url or not api_token:
            logging.error("[pwnamap_uploader] Missing server_url or api_token in .toml")
            return

        headers = {
            "Authorization": f"Bearer {api_token}",
            "User-Agent": "pwnamap-uploader/0.5.1-essentials (+pwnagotchi)"
        }

        # Session HTTP riutilizzabile
        self._session = requests.Session()

        # Backoff con jitter
        backoff = 2
        max_backoff = int(self.options.get("max_backoff_sec", 1800))  # fino a 30 min

        def stop_aware_wait(seconds: float):
            # dorme ma si sveglia prontamente se arriva stop
            self._stop.wait(seconds)

        def upload_pair(pcap_path: str, gps_path: str) -> bool:
            nonlocal backoff
            base = os.path.basename(pcap_path)

            # Connettività: prova TCP al server (copre Wi-Fi, BT tethering, ecc.)
            if not _net_ok(server_url):
                logging.debug("[pwnamap_uploader] network not reachable for %s, skip.", server_url)
                return False

            # File stability check
            if not _file_is_stable(pcap_path) or not _file_is_stable(gps_path):
                logging.debug("[pwnamap_uploader] files not stable yet, will retry.")
                return False

            # Prepara multipart con ENTRAMBI i file
            files = {}
            try:
                files["pcap"] = (os.path.basename(pcap_path), open(pcap_path, "rb"))
                if os.path.getsize(pcap_path) <= 0:
                    raise IOError("pcap empty")
            except Exception as e:
                logging.warning("[pwnamap_uploader] Unable to open pcap %s: %s", pcap_path, e)
                return False
            try:
                files["gps"] = (os.path.basename(gps_path), open(gps_path, "rb"), "application/json")
                if os.path.getsize(gps_path) <= 0:
                    raise IOError("gps json empty")
            except Exception as e:
                logging.warning("[pwnamap_uploader] Unable to open gps %s: %s", gps_path, e)
                try:
                    files["pcap"][1].close()
                except Exception:
                    pass
                return False

            self._set_ui_state(agent, uploading=True)
            try:
                resp = self._session.post(
                    server_url,
                    files=files,      # pcap + gps
                    data={},          # inviamo il file intero
                    headers=headers,
                    timeout=60,
                    verify=verify_ssl,
                )
                if 200 <= resp.status_code < 300:
                    append_uploaded_list(ul, base)
                    self._uploaded.add(base)
                    backoff = 2
                    logging.info("[pwnamap_uploader] Uploaded %s (+gps).", base)
                    return True
                else:
                    logging.warning("[pwnamap_uploader] Upload failed HTTP %s", resp.status_code)
                    jitter = random.uniform(0.8, 1.2)
                    stop_aware_wait(min(max_backoff, backoff) * jitter)
                    backoff = min(max_backoff, max(4, backoff * 2))
                    return False
            except requests.RequestException as e:
                logging.warning("[pwnamap_uploader] Upload error: %s", e)
                jitter = random.uniform(0.8, 1.2)
                stop_aware_wait(min(max_backoff, backoff) * jitter)
                backoff = min(max_backoff, max(4, backoff * 2))
                return False
            finally:
                try:
                    for v in files.values():
                        if isinstance(v, tuple) and len(v) >= 2 and hasattr(v[1], "close"):
                            v[1].close()
                except Exception:
                    pass
            # end upload_pair

        # Jitter di startup (0–30s) per evitare stampede
        self._stop.wait(random.uniform(0, 30))

        # Loop principale: scansione + cicli con sleep stop-aware
        while not self._stop.is_set():
            had_work = False
            pairs = find_complete_pairs(handshakes_dir)  # no sorted()

            for pcap_path, gps_path in pairs:
                if self._stop.is_set():
                    break
                base = os.path.basename(pcap_path)
                if base in self._uploaded:
                    continue
                # Fino a 5 tentativi in questa passata
                attempts = 0
                while attempts < 5 and base not in self._uploaded and not self._stop.is_set():
                    self._set_ui_state(agent, uploading=True)
                    ok = upload_pair(pcap_path, gps_path)
                    attempts += 1
                    if ok:
                        had_work = True
                        break

            # UI a riposo se non c'è lavoro
            if not had_work:
                self._set_ui_state(agent, uploading=False)

            # Sleep principale: breve se abbiamo lavorato, lungo se idle
            if had_work:
                self._stop.wait(10)  # raffreddamento
            else:
                self._stop.wait(max(5, interval))

        # cleanup
        self._set_ui_state(agent, uploading=False)

    def on_unload(self, ui):
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        try:
            if self._session:
                self._session.close()
        except Exception:
            pass
