import os
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
from flask import Flask, request, send_file, abort, make_response
import geoip2.database
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import requests
import ssl
from werkzeug.serving import make_server
import configparser
import base64
import hashlib
from cryptography.fernet import Fernet

app = Flask(__name__)

geoip_db_path = 'GeoLite2-City.mmdb'
geoip_reader = geoip2.database.Reader(geoip_db_path)

image_path = 'start_image.jpg'
show_image = False
custom_image_url = ''

server_thread = None
running = False
http_server = None

config_file = 'config.cfg'

def anonymize_path(path):
    encoded_bytes = base64.urlsafe_b64encode(path.encode('utf-8'))
    return str(encoded_bytes, 'utf-8')

def de_anonymize_path(encoded_path):
    decoded_bytes = base64.urlsafe_b64decode(encoded_path)
    return str(decoded_bytes, 'utf-8')

def generate_key_from_password(password):
    # SHA-256 hash of the password
    password_hash = hashlib.sha256(password.encode()).digest()
    # Base64 encode the hash to get a 32-byte key
    key = base64.urlsafe_b64encode(password_hash)
    return key

def encrypt_config(password):
    key = generate_key_from_password(password)
    cipher = Fernet(key)
    with open(config_file, 'rb') as file:
        file_data = file.read()
    encrypted_data = cipher.encrypt(file_data)
    with open(config_file, 'wb') as file:
        file.write(encrypted_data)

def decrypt_config(password):
    key = generate_key_from_password(password)
    cipher = Fernet(key)
    with open(config_file, 'rb') as file:
        encrypted_data = file.read()
    try:
        decrypted_data = cipher.decrypt(encrypted_data)
        with open(config_file, 'wb') as file:
            file.write(decrypted_data)
        return True
    except Exception as e:
        print(f"Failed to decrypt config: {e}")
        return False

def load_config(password=None):
    if os.path.exists(config_file) and is_encrypted(config_file):
        if password:
            if not decrypt_config(password):
                messagebox.showerror("Error", "Incorrect password or failed to decrypt config.")
                return
        else:
            open_load_config_dialog()
            return  # Wait for the dialog to handle the decryption
    config = configparser.ConfigParser()
    if os.path.exists(config_file):
        config.read(config_file)
        if 'DynDNS' in config:
            user_entry.delete(0, tk.END)
            password_entry.delete(0, tk.END)
            domain_entry.delete(0, tk.END)
            api_key_entry.delete(0, tk.END)
            port_entry.delete(0, tk.END)
            user_entry.insert(0, config['DynDNS'].get('user', ''))
            password_entry.insert(0, config['DynDNS'].get('password', ''))
            domain_entry.insert(0, config['DynDNS'].get('domain', ''))
            api_key_entry.insert(0, config['DynDNS'].get('api_key', ''))
            port_entry.insert(0, config['DynDNS'].get('port', '80'))
            image_var.set(config['DynDNS'].getboolean('show_image', False))
            http_var.set(config['DynDNS'].getboolean('use_http', False))
            publish_folder_var.set(config['DynDNS'].getboolean('publish_folder', False))
            mask_var.set(config['DynDNS'].get('mask', 'Apache/2.4.41 (Ubuntu)'))
            url_entry.delete(0, tk.END)
            url_entry.insert(0, config['DynDNS'].get('url', ''))
        print(f"Config loaded: {config['DynDNS']}")
    else:
        port_entry.insert(0, '80')
        print("No config file found.")


def is_encrypted(file_path):
    try:
        with open(file_path, 'rb') as file:
            file_header = file.read(10)  # Read the first 10 bytes
            if file_header.startswith(b'gAAAAA'):
                return True
    except Exception as e:
        print(f"Error checking if file is encrypted: {e}")
    return False



def save_config(encrypted=False, password=None):
    config = configparser.ConfigParser()
    config['DynDNS'] = {
        'user': user_entry.get(),
        'password': password_entry.get(),
        'domain': domain_entry.get(),
        'api_key': api_key_entry.get(),
        'port': port_entry.get(),
        'show_image': image_var.get(),
        'use_http': http_var.get(),
        'publish_folder': publish_folder_var.get(),
        'mask': mask_var.get(),
        'url': url_entry.get()
    }
    with open(config_file, 'w') as configfile:
        config.write(configfile)
    if encrypted and password:
        encrypt_config(password)
    print("Config saved.")

def open_save_config_dialog():
    dialog = tk.Toplevel()
    dialog.title("Save Config")

    ttk.Label(dialog, text="Enter password to encrypt config (optional):").pack(pady=10)
    password_entry = ttk.Entry(dialog, show='*')
    password_entry.pack(pady=5)

    def save_unencrypted():
        save_config(encrypted=False)
        dialog.destroy()

    def save_encrypted():
        password = password_entry.get()
        if password:
            save_config(encrypted=True, password=password)
        else:
            messagebox.showwarning("Warning", "Password is empty, saving unencrypted.")
            save_unencrypted()
        dialog.destroy()

    ttk.Button(dialog, text="Just Save", command=save_unencrypted).pack(side=tk.LEFT, padx=10, pady=10)
    ttk.Button(dialog, text="Save Encrypted", command=save_encrypted).pack(side=tk.RIGHT, padx=10, pady=10)

def open_load_config_dialog():
    dialog = tk.Toplevel()
    dialog.title("Load Config")

    ttk.Label(dialog, text="Enter password to decrypt config:").pack(pady=10)
    password_entry = ttk.Entry(dialog, show='*')
    password_entry.pack(pady=5)

    def load_encrypted():
        password = password_entry.get()
        if password:
            if decrypt_config(password):
                load_config()  # Load the config after decrypting
            else:
                messagebox.showwarning("Warning", "Failed to decrypt config. Incorrect password?")
        else:
            messagebox.showwarning("Warning", "Password is empty.")
        dialog.destroy()

    ttk.Button(dialog, text="Load", command=load_encrypted).pack(pady=10)


def create_ssl_cert_and_key():
    ssl_cert_path = 'cert.pem'
    ssl_key_path = 'key.pem'

    if not os.path.isfile(ssl_cert_path) or not os.path.isfile(ssl_key_path):
        print("Zertifikate nicht gefunden. Erstelle neue Zertifikate...")

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).sign(key, hashes.SHA256(), default_backend())

        with open(ssl_key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(ssl_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    return ssl_cert_path, ssl_key_path

@app.route('/')
@app.route('/<path:subpath>')
def index(subpath=None):
    global show_image, custom_image_url, image_path, publish_folder_var
    ip_address = request.remote_addr
    try:
        response = geoip_reader.city(ip_address)
        city = response.city.name if response.city.name else 'Unknown City'
        country = response.country.name if response.country.name else 'Unknown Country'
        location_str = f"{city}, {country}"
    except geoip2.errors.AddressNotFoundError:
        location_str = "Unknown Location"

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"Timestamp: {timestamp}, IP: {ip_address}, Location: {location_str}"
    with open("access.log", "a") as log_file:
        log_file.write(log_entry + "\n")

    log_access(ip_address, request.headers.get('User-Agent'), location_str)

    if subpath:
        # De-Anonymisieren des Pfades
        decoded_path = de_anonymize_path(subpath)
        if publish_folder_var.get() and os.path.isdir(decoded_path):
            files = os.listdir(decoded_path)
            file_list = ""
            for file in files:
                file_url = f"/files/{anonymize_path(os.path.join(decoded_path, file))}"
                if file.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                    file_list += f'<div class="grid-item"><img src="{file_url}" alt="{file}" style="max-width:100%; max-height:100%;"/></div>'
                elif file.lower().endswith(('.mp4', '.webm', '.ogg')):
                    file_list += f'<div class="grid-item"><video width="100%" height="auto" controls><source src="{file_url}" type="video/mp4">Your browser does not support the video tag.</video></div>'
                else:
                    file_list += f'<div class="grid-item"><a href="{file_url}" download>{file}</a></div>'

            html_content = f"""
            <html>
            <head>
                <style>
                    .grid-container {{
                        display: grid;
                        grid-template-columns: repeat(6, 1fr);
                        gap: 10px;
                        padding: 10px;
                    }}
                    .grid-item {{
                        text-align: center;
                        border: 1px solid #ddd;
                        padding: 10px;
                        box-sizing: border-box;
                    }}
                    img {{
                        width: 100%;
                        height: auto;
                    }}
                    video {{
                        width: 100%;
                        height: auto;
                    }}
                </style>
            </head>
            <body>
                <div class="grid-container">{file_list}</div>
            </body>
            </html>
            """
            return html_content
        elif os.path.isfile(decoded_path):
            return send_file(decoded_path)
        else:
            abort(404)
    elif show_image and os.path.isfile(image_path):
        return send_file(image_path, mimetype='image/jpeg')
    else:
        return "Hello, World!"

@app.route('/files/<path:encoded_filename>')
def serve_file(encoded_filename):
    decoded_filename = de_anonymize_path(encoded_filename)
    return send_file(decoded_filename)

@app.after_request
def apply_server_header(response):
    selected_server = mask_var.get()
    response.headers["Server"] = selected_server
    return response

def start_flask():
    global http_server
    port = port_entry.get()
    if port:
        port = int(port)
    else:
        port = None
    if http_var.get():
        if port:
            http_server = make_server('0.0.0.0', port, app)
        else:
            http_server = make_server('0.0.0.0', 80, app)
        http_server.serve_forever()
    else:
        ssl_cert_path, ssl_key_path = create_ssl_cert_and_key()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(ssl_cert_path, ssl_key_path)
        if port:
            http_server = make_server('0.0.0.0', port, app, ssl_context=context)
        else:
            http_server = make_server('0.0.0.0', 443, app, ssl_context=context)
        http_server.serve_forever()

def toggle_server():
    global running
    if running:
        stop_server()
    else:
        start_server()

def start_server():
    global server_thread, running
    if not running:
        server_thread = threading.Thread(target=start_flask)
        server_thread.start()
        running = True
        update_button_state()

def stop_server():
    global http_server, running
    if running:
        if http_server:
            http_server.shutdown()
        running = False
        update_button_state()

def update_button_state():
    if running:
        toggle_button.config(text="Server started.... press to stop it", bg="green", fg="white", font=('Helvetica', 12, 'bold'))
    else:
        toggle_button.config(text="Server stopped.... press to start it", bg="red", fg="white", font=('Helvetica', 12, 'bold'))

def log_access(ip, client, location):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_text = f"{now} - IP: {ip}, Client: {client}, Location: {location}\n"
    log_window.insert(tk.END, log_text)
    log_window.see(tk.END)

def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        if response.status_code == 200:
            return response.json()['ip']
    except Exception as e:
        print(f"Failed to get public IP: {e}")
    return None

def get_domain_id(api_key, domain):
    headers = {
        'accept': 'application/json',
        'API-Key': api_key
    }
    response = requests.get('https://api.dynu.com/v2/dns', headers=headers)
    if response.status_code == 200:
        domains = response.json().get('domains', [])
        for d in domains:
            if d.get('name') == domain:
                return d.get('id')
    return None

def update_dyndns():
    api_key = api_key_entry.get()
    domain = domain_entry.get()
    domain_id = get_domain_id(api_key, domain)
    public_ip = get_public_ip()

    if not domain_id:
        messagebox.showerror("Error", "Domain ID not found.")
        return

    if not public_ip:
        messagebox.showerror("Error", "Public IP not found.")
        return

    try:
        headers = {
            'accept': 'application/json',
            'API-Key': api_key
        }
        data = {
            "name": domain,
            "ipv4Address": public_ip
        }
        response = requests.post(
            f'https://api.dynu.com/v2/dns/{domain_id}',
            headers=headers,
            json=data
        )
        if response.status_code == 200:
            update_url()
            messagebox.showinfo("Success", f"DynDNS domain {domain} updated to IP {public_ip}")
        else:
            messagebox.showerror("Error", f"Failed to update DynDNS: {response.json()}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to update DynDNS: {e}")

def create_dyndns():
    api_key = api_key_entry.get()
    domain = domain_entry.get()
    public_ip = get_public_ip()

    if not public_ip:
        messagebox.showerror("Error", "Public IP not found.")
        return

    try:
        headers = {
            'accept': 'application/json',
            'API-Key': api_key
        }
        data = {
            "name": domain,
            "ipv4Address": public_ip
        }
        response = requests.post(
            f'https://api.dynu.com/v2/dns',
            headers=headers,
            json=data
        )
        if response.status_code == 200:
            update_url()
            messagebox.showinfo("Success", f"DynDNS domain {domain} created")
        else:
            messagebox.showerror("Error", f"Failed to create DynDNS: {response.json()}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to create DynDNS: {e}")

def remove_dyndns():
    api_key = api_key_entry.get()
    domain = domain_entry.get()
    domain_id = get_domain_id(api_key, domain)

    if not domain_id:
        messagebox.showerror("Error", "Domain ID not found.")
        return

    try:
        headers = {
            'accept': 'application/json',
            'API-Key': api_key
        }
        response = requests.delete(
            f'https://api.dynu.com/v2/dns/{domain_id}',
            headers=headers
        )
        if response.status_code == 200:
            url_entry.delete(0, tk.END)
            messagebox.showinfo("Success", f"DynDNS domain {domain} removed")
        else:
            messagebox.showerror("Error", f"Failed to remove DynDNS: {response.json()}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to remove DynDNS: {e}")

def update_url():
    global custom_image_url
    protocol = "http" if http_var.get() else "https"
    domain = domain_entry.get()
    url = f"{protocol}://{domain}"
    if image_path:
        # Replace backslashes with forward slashes for URL compatibility
        path_for_url = anonymize_path(image_path)
        url = f"{url}/{path_for_url}"
    current_url = url_entry.get()
    if current_url != url:
        url_entry.delete(0, tk.END)
        url_entry.insert(0, url)
    custom_image_url = url

def browse_image():
    global image_path
    if publish_folder_var.get():
        folder_path = filedialog.askdirectory(initialdir=os.getcwd(), title="Select a folder")
        if folder_path:
            image_path = folder_path
    else:
        file_path = filedialog.askopenfilename(initialdir=os.getcwd(), title="Select an image",
                                               filetypes=(("jpeg files", "*.jpg"), ("all files", "*.*")))
        if file_path:
            image_path = file_path
    update_url()

def on_image_checkbox_toggle():
    global show_image
    show_image = image_var.get()
    update_url()

def on_http_checkbox_toggle():
    update_url()

def on_publish_folder_checkbox_toggle():
    if publish_folder_var.get():
        browse_button.config(text="Browse Folder")
    else:
        browse_button.config(text="Browse Image")
    update_url()

# Hauptanwendung
app_gui = tk.Tk()
app_gui.title("HTTPs-Quicky")

# Hauptframe
frame = ttk.Frame(app_gui)
frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

# URL- und Port-Eingabefelder
url_frame = ttk.Frame(frame)
url_frame.pack(fill=tk.X)

url_label = ttk.Label(url_frame, text="URL des HTTPS-Servers:")
url_label.pack(side=tk.LEFT)
url_entry = ttk.Entry(url_frame)
url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

browse_button = ttk.Button(url_frame, text="Browse Image", command=browse_image)
browse_button.pack(side=tk.LEFT)

port_label = ttk.Label(url_frame, text="Port:")
port_label.pack(side=tk.LEFT)
port_entry = ttk.Entry(url_frame)
port_entry.pack(side=tk.LEFT)

# Toggle-Button für Starten/Stoppen des Servers
button_frame = ttk.Frame(frame)
button_frame.pack(fill=tk.X)
toggle_button = tk.Button(button_frame, text="Server stopped.... press to start it", command=toggle_server, bg="red", fg="white", font=('Helvetica', 12, 'bold'))
toggle_button.pack(fill=tk.X, expand=True)

# Log-Fenster
log_window = scrolledtext.ScrolledText(frame, height=10)
log_window.pack(fill=tk.BOTH, expand=True)

# Bild- und HTTP-Checkbox und Publish Folder Checkbox
checkbox_frame = ttk.Frame(frame)
checkbox_frame.pack(fill=tk.X)

image_var = tk.BooleanVar()
image_checkbox = ttk.Checkbutton(checkbox_frame, text="Bild", variable=image_var, command=on_image_checkbox_toggle)
image_checkbox.pack(side=tk.LEFT)

http_var = tk.BooleanVar()
http_checkbox = ttk.Checkbutton(checkbox_frame, text="http", variable=http_var, command=on_http_checkbox_toggle)
http_checkbox.pack(side=tk.LEFT)

publish_folder_var = tk.BooleanVar()
publish_folder_checkbox = ttk.Checkbutton(checkbox_frame, text="Publish Folder", variable=publish_folder_var, command=on_publish_folder_checkbox_toggle)
publish_folder_checkbox.pack(side=tk.LEFT)

mask_label = ttk.Label(checkbox_frame, text="Mask:")
mask_label.pack(side=tk.LEFT)

mask_var = tk.StringVar(value="Apache/2.4.41 (Ubuntu)")
mask_options = [
    "Apache/2.4.41 (Ubuntu)",
    "nginx/1.18.0 (Ubuntu)",
    "Microsoft-IIS/10.0",
    "LiteSpeed",
    "Caddy"
]
mask_menu = ttk.OptionMenu(checkbox_frame, mask_var, mask_options[0], *mask_options)
mask_menu.pack(side=tk.LEFT)

# Tab-Controller
tab_control = ttk.Notebook(frame)
dyn_dns_tab = ttk.Frame(tab_control)
tab_control.add(dyn_dns_tab, text="DynDNS")
tab_control.pack(fill=tk.BOTH, expand=True)

# DynDNS-Eingabefelder
user_label = ttk.Label(dyn_dns_tab, text="User:")
user_label.pack(fill=tk.X)
user_entry = ttk.Entry(dyn_dns_tab)
user_entry.pack(fill=tk.X)

password_label = ttk.Label(dyn_dns_tab, text="Password:")
password_label.pack(fill=tk.X)
password_entry = ttk.Entry(dyn_dns_tab, show="*")
password_entry.pack(fill=tk.X)

domain_label = ttk.Label(dyn_dns_tab, text="Domain:")
domain_label.pack(fill=tk.X)
domain_entry = ttk.Entry(dyn_dns_tab)
domain_entry.pack(fill=tk.X)

api_key_label = ttk.Label(dyn_dns_tab, text="API Key:")
api_key_label.pack(fill=tk.X)
api_key_entry = ttk.Entry(dyn_dns_tab)
api_key_entry.pack(fill=tk.X)

# Save Config Button
save_button = ttk.Button(dyn_dns_tab, text="Save Config", command=open_save_config_dialog)
save_button.pack(fill=tk.X)

# DynDNS-Update-Button
update_button = ttk.Button(dyn_dns_tab, text="Update Dyndns Domain", command=update_dyndns)
update_button.pack(fill=tk.X)

# DynDNS-Create-Button
create_button = ttk.Button(dyn_dns_tab, text="Create Dyndns Domain", command=create_dyndns)
create_button.pack(fill=tk.X)

# DynDNS-Remove-Button
remove_button = ttk.Button(dyn_dns_tab, text="Remove Dyndns Domain", command=remove_dyndns)
remove_button.pack(fill=tk.X)

# Initialisierung
create_ssl_cert_and_key()
load_config()
update_button_state()
running = False

# Hauptanwendung starten
app_gui.mainloop()
