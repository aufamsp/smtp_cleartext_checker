import argparse
import socket
import ssl
import json
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# Banner
BANNER = """
############################################
#   SMTP Cleartext Login Permitted Tester  #
#            Developed by Afif             #
############################################
"""

DEFAULT_PORTS = [25, 587, 465]
 
 
def recv_smtp(sock):
    """Baca response SMTP sampai baris terakhir (format 'XXX ' bukan 'XXX-')"""
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        lines = data.decode(errors="ignore").strip().splitlines()
        if lines and len(lines[-1]) >= 4 and lines[-1][3] == " ":
            break
    return data.decode(errors="ignore")
 
 
def check_smtp_cleartext_login(host, port, timeout=5):
    """Tests if the SMTP server allows cleartext login"""
    result = {
        "host": host,
        "port": port,
        "status": "Failed",
        "banner": None,
        "cleartext_login_permitted": False
    }
 
    try:
        sock = socket.create_connection((host, port), timeout)
        # Port 465 pakai implicit TLS, jadi socket harus dibungkus SSL dulu
        if port == 465:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
 
        with sock:
            sock.settimeout(timeout)
            recv_smtp(sock)  # Read initial SMTP banner
            sock.sendall(b"EHLO test\r\n")
            response = recv_smtp(sock)
            result["banner"] = response.strip()
 
            if port == 465:
                # Implicit TLS: AUTH PLAIN/LOGIN di sini sudah terenkripsi, bukan cleartext
                result["status"] = "Secure (implicit TLS)" if "250" in response else "Unknown"
            elif "250" in response and "AUTH" in response:
                if "PLAIN" in response or "LOGIN" in response:
                    result["cleartext_login_permitted"] = True
                    result["status"] = "Vulnerable"
                else:
                    result["status"] = "Secure"
            else:
                result["status"] = "Unknown"
 
    except Exception as e:
        result["status"] = f"Error: {str(e)}"
 
    return result
 
 
def save_results(results, output_file, output_format):
    """Saves results in the specified format"""
    if output_format == "json":
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4)
    elif output_format == "csv":
        keys = results[0].keys()
        with open(output_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(results)
    elif output_format == "xlsx":
        import pandas as pd
        df = pd.DataFrame(results)
        df.to_excel(output_file, index=False)
    elif output_format == "txt":
        with open(output_file, "w") as f:
            for res in results:
                f.write(json.dumps(res) + "\n")
 
 
def parse_bulk_target(line, ports):
    """
    'host:port' -> [(host, port)]
    'host'      -> [(host, 25), (host, 587), (host, 465)]
    """
    line = line.strip()
 
    # Buang skema URL seperti ftp://, http://, smtp://
    if "://" in line:
        line = line.split("://", 1)[1]
 
    # Buang path, query, dan user@ jika ada
    line = line.split("/", 1)[0].split("?", 1)[0]
    if "@" in line:
        line = line.rsplit("@", 1)[1]
 
    if not line:
        raise ValueError("host kosong")
 
    if ":" in line:
        host, port = line.rsplit(":", 1)
        return [(host.strip(), int(port.strip()))]
    return [(line, p) for p in ports]
 
 
def main():
    print(BANNER)
 
    parser = argparse.ArgumentParser(description="SMTP Cleartext Login Permitted Tester")
    parser.add_argument("target", help="Single host or file containing list of hosts (bulk mode)")
    parser.add_argument("--port", type=int, help="SMTP port (single mode). Jika kosong, cek 25, 587, 465")
    parser.add_argument("--bulk", action="store_true", help="Enable bulk mode (requires file input)")
    parser.add_argument("--output", help="File to save results (format: csv, xlsx, txt, json)")
    parser.add_argument("--threads", type=int, default=20, help="Jumlah thread paralel (default: 20)")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout per koneksi dalam detik (default: 5)")
 
    args = parser.parse_args()
 
    targets = []
 
    if args.bulk:
        try:
            with open(args.target, "r") as file:
                for num, line in enumerate(file, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        targets.extend(parse_bulk_target(line, DEFAULT_PORTS))
                    except ValueError as e:
                        print(f"[skip] baris {num}: '{line}' ({e})")
        except Exception as e:
            print(f"Error reading file: {e}")
            return
    else:
        if args.port:
            targets.append((args.target, args.port))
        else:
            targets.extend((args.target, p) for p in DEFAULT_PORTS)
 
    # Hapus duplikat, urutan tetap
    targets = list(dict.fromkeys(targets))
 
    print(f"\nScanning {len(targets)} target(s) with {args.threads} threads...\n")
 
    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(check_smtp_cleartext_login, h, p, args.timeout) for h, p in targets]
        for future in tqdm(as_completed(futures), total=len(futures), desc="Checking SMTP", unit="target"):
            results.append(future.result())
 
    # Urutkan hasil sesuai host lalu port
    results.sort(key=lambda r: (r["host"], r["port"]))
 
    if not args.output:
        print(json.dumps(results, indent=4))
    else:
        output_format = args.output.split(".")[-1]
        if output_format not in ["csv", "xlsx", "txt", "json"]:
            print("Unsupported output format! Use csv, xlsx, txt, or json.")
            return
        save_results(results, args.output, output_format)
        print(f"\nResults saved to {args.output}")
 
 
if __name__ == "__main__":
    main()
 