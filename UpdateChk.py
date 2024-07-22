import os
import requests
import configparser

def check_and_update_geolite2_db(config_file='config.cfg', geoip_db_path='GeoLite2-City.mmdb', download_url='https://github.com/P3TERX/GeoLite.mmdb/releases/download/2024.07.22/GeoLite2-City.mmdb'):
    config = configparser.ConfigParser()
    
    # Prüfen, ob config.cfg existiert und laden
    if os.path.exists(config_file):
        config.read(config_file)
    
    # Prüfen, ob die GeoLite2-Datenbank vorhanden ist
    if not os.path.exists(geoip_db_path):
        # Datenbank herunterladen
        download_geolite2_db(download_url, geoip_db_path)
        # Version in der config.cfg eintragen
        update_config_with_version(config, config_file, geoip_db_path)
    else:
        # Überprüfen, ob die Version in der config.cfg eingetragen ist
        if 'GeoLite2' not in config or 'version' not in config['GeoLite2']:
            print("GeoLite2 Datenbank vorhanden, aber keine Version in der config.cfg eingetragen.")
        else:
            print(f"GeoLite2 Datenbank Version: {config['GeoLite2']['version']}")

def download_geolite2_db(download_url, geoip_db_path):
    try:
        response = requests.get(download_url, stream=True)
        response.raise_for_status()
        with open(geoip_db_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"GeoLite2 Datenbank heruntergeladen und gespeichert unter: {geoip_db_path}")
    except requests.RequestException as e:
        print(f"Fehler beim Herunterladen der GeoLite2 Datenbank: {e}")
        raise

def update_config_with_version(config, config_file, geoip_db_path):
    # Beispielversion eintragen, normalerweise würde man die Version dynamisch aus dem Download ermitteln
    version = "2024.07.22"
    
    if 'GeoLite2' not in config:
        config['GeoLite2'] = {}
    
    config['GeoLite2']['version'] = version
    
    with open(config_file, 'w') as configfile:
        config.write(configfile)
    print(f"Version {version} der GeoLite2 Datenbank in der config.cfg eingetragen.")
