import random
import socket
import requests
from colorama import Fore, Style, init
from base64 import b64encode, b64decode
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import sys
import subprocess
def ensure_dependencies():
    required = [
        "colorama",
        "requests",
        "cryptography"
    ]
    for pkg in required:
        try:
            __import__(pkg)
        except ImportError:
            print(f"[INFO] Installing missing dependency: {pkg}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

def print_banner():
    banner = r"""
  _____        _____                ____                 __  __ 
 |_   _|      / ____|              |  _ \               |  \/  |
   | |       | |                   | |_) |              | \  / |
   | |       | |                   |  _ <               | |\/| |
  _| |_      | |____               | |_) |              | |  | |
 |_____|NTRA  \_____| ONTINENTAL   |____/ ALLISHTIC     |_|  |_|ISSILE
         (c) 2025 BELACOM TECHNOLOGIES LIMITED
         RUINING YOUR DAY                        
    """
    print(banner)

# Initialize colorama
init(autoreset=True)

def info(msg):
    print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} {msg}")

def warning(msg):
    print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {msg}")

def error(msg):
    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {msg}")

# ---------------- PORT SCANNER ----------------
def scan_port(target, port, list):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        result = s.connect_ex((target, port))
        if result == 0:
            print(f"{Fore.GREEN}[OPEN]{Style.RESET_ALL} Port {port} is open on {target}")
            list.append(port)
        else:
            print(f"{Fore.RED}[CLOSED]{Style.RESET_ALL} Port {port} is closed on {target}")

def scan_ports():
    target = input(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Enter target host (default: scanme.nmap.org): ") or "scanme.nmap.org"
    ports_input = input(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Enter ports to scan (comma separated or range e.g., 22,80,443 or 1-1000, default: 1-65535): ")

    # Determine shit

    open_ports = []

    # Determine ports
    if "-" in ports_input:
        start, end = map(int, ports_input.split("-"))
        ports = range(start, end + 1)
    elif ports_input.strip() == "":
        ports = range(1, 65536)  # Default to all ports
    else:
        ports = [int(p.strip()) for p in ports_input.split(",")]

    print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Scanning {len(ports)} ports on {target} using threads...")

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, target, port, open_ports) for port in ports]
        for _ in as_completed(futures):
            pass  # Just wait for all to complete

    print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Scan complete. Open ports: {open_ports}")

# ---------------- DNS RESOLVER ----------------
def resolve_dns():
    host = input(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Enter domain to resolve: ")
    try:
        ip = socket.gethostbyname(host)
        info(f"{host} resolves to {ip}")
    except Exception as e:
        error(f"Failed to resolve: {e}")

# ---------------- PUBLIC IP ----------------
def get_public_ip():
    try:
        ip = requests.get('https://api.ipify.org').text
        info(f"Your public IP is: {ip}")
    except Exception as e:
        error(f"Failed to get public IP: {e}")

# ---------------- SECURE MESSAGING ----------------
def generate_keypair():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return b64encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
    ).decode()

def deserialize_public_key(pub_bytes):
    return ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP384R1(),
        b64decode(pub_bytes)
    )

def derive_shared_key(private_key, peer_public_key):
    shared = private_key.exchange(ec.ECDH(), peer_public_key)
    return sha256(shared).digest()

def encrypt_message(key, plaintext):
    aesgcm = AESGCM(key)
    nonce = AESGCM.generate_key(bit_length=256)[:12]
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return b64encode(nonce + ct).decode()

def decrypt_message(key, ciphertext):
    try:
        data = b64decode(ciphertext)
        nonce, ct = data[:12], data[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct, None).decode()
    except Exception as e:
        error(f"Failed to decrypt: {e}")
        return None

def messaging():
    info("Generating ECDH keypair...")
    priv, pub = generate_keypair()
    info(f"Your public key (share this): {serialize_public_key(pub)}")
    peer_pub_str = input(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Enter peer's public key: ")
    try:
        peer_pub = deserialize_public_key(peer_pub_str)
    except Exception as e:
        error(f"Invalid public key: {e}")
        return
    shared_key = derive_shared_key(priv, peer_pub)
    info("Shared key established. You can now send encrypted messages.")
    while True:
        action = input(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} (E)ncrypt / (D)ecrypt / (Q)uit: ").strip().lower()
        if action == "e":
            msg = input(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Enter message to encrypt: ")
            enc = encrypt_message(shared_key, msg)
            info(f"Encrypted: {enc}")
        elif action == "d":
            enc = input(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Enter message to decrypt: ")
            dec = decrypt_message(shared_key, enc)
            if dec is not None:
                info(f"Decrypted: {dec}")
        elif action == "q":
            break
        else:
            warning("Invalid option.")

# ---------------- NCAT ----------------

def ncat():
    hostOrClient = input("[INFO] Are you a (H)ost or (C)lient? ").strip().lower()
    if hostOrClient not in ('h', 'c'):
        error("Invalid choice. Please enter 'H' for Host or 'C' for Client.")
        return
    if hostOrClient == 'c':
        host = input("[INFO] Enter target IP or hostname: ").strip()
        port_input = input("[INFO] Enter target port: ").strip()

        try:
            port = int(port_input)
        except ValueError:
            error("Invalid port number.")
            return

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            info(f"Connected to {host}:{port}")

            def receive():
                while True:
                    try:
                        data = s.recv(4096)
                        if not data:
                            warning("Connection closed by remote host.")
                            break
                        print(data.decode(errors='ignore'), end='')
                    except Exception as e:
                        error(f"Receive error: {e}")
                        break

            threading.Thread(target=receive, daemon=True).start()

            while True:
                try:
                    msg = input()
                    if msg.lower() in ("exit", "quit"):
                        info("Closing connection.")
                        break
                    s.sendall(msg.encode() + b'\n')
                except Exception as e:
                    error(f"Send error: {e}")
                    break

            s.close()

        except Exception as e:
            error(f"Connection failed: {e}")
    else:
        port_input = input("[INFO] Enter port to listen on: ").strip()

        try:
            port = int(port_input)
        except ValueError:
            error("Invalid port number.")
            return

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('', port))
            s.listen(1)
            info(f"Listening on port {port}...")

            conn, addr = s.accept()
            info(f"Connection established with {addr}")

            def receive():
                while True:
                    try:
                        data = conn.recv(4096)
                        if not data:
                            warning("Connection closed by remote host.")
                            break
                        print(data.decode(errors='ignore'), end='')
                    except Exception as e:
                        error(f"Receive error: {e}")
                        break

            threading.Thread(target=receive, daemon=True).start()

            while True:
                try:
                    msg = input()
                    if msg.lower() in ("exit", "quit"):
                        info("Closing connection.")
                        break
                    conn.sendall(msg.encode() + b'\n')
                except Exception as e:
                    error(f"Send error: {e}")
                    break

            conn.close()
            s.close()

        except Exception as e:
            error(f"Failed to set up server: {e}")


# ---------------- MAIN MENU ----------------
def main_menu():
    print_banner()
    while True:
        print("\n[INFO] Choose an action:")
        print("  1. Scan ports")
        print("  2. Resolve DNS")
        print("  3. Get public IP")
        print("  4. Secure Messaging (AES-256-GCM + ECDH)")
        print("  5. Connect to a remote host")
        print("  6. Exit")
        choice = input(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Enter your choice: ").strip()
        if choice == "1":
            scan_ports()
        elif choice == "2":
            resolve_dns()
        elif choice == "3":
            get_public_ip()
        elif choice == "4":
            messaging()
        elif choice == "5":
            ncat()
            break
        elif choice == "6":
            info("Goodbye!")
            break
        else:
            warning("Invalid choice. Try again.")

if __name__ == "__main__":
    try:
        ensure_dependencies()
        main_menu()
    except KeyboardInterrupt:
        print("\n" + Fore.RED + "Exiting due to keyboard interrupt." + Style.RESET_ALL)
        exit(0)
    
