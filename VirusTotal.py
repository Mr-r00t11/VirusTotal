from colorama import Fore
import argparse
import requests
import sys
import base64
import json
import os

# Definir la clave de API de VirusTotal (debes poner tu clave aquí)
API_KEY = 'API_KEY'

# URL base de la API de VirusTotal
BASE_URL = 'https://www.virustotal.com/api/v3/'

def codificar_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def obtener_info_virustotal(tipo, valor):
    if tipo == 'ip':
        url = f'{BASE_URL}ip_addresses/{valor}'
    elif tipo == 'url':
        valor_codificado = codificar_url(valor)
        url = f'{BASE_URL}urls/{valor_codificado}'
    elif tipo == 'domain':
        url = f'{BASE_URL}domains/{valor}'
    elif tipo == 'hash':
        url = f'{BASE_URL}files/{valor}'
    else:
        raise ValueError('Tipo de consulta no válido.')

    headers = {'x-apikey': API_KEY}
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else None

def subir_y_analizar_archivo(filepath):
    if not os.path.isfile(filepath):
        print(f"{Fore.RED}[!] Archivo no encontrado: {filepath}{Fore.RESET}")
        return None

    headers = {'x-apikey': API_KEY}
    files = {'file': (os.path.basename(filepath), open(filepath, 'rb'))}
    response = requests.post(f'{BASE_URL}files', headers=headers, files=files)

    if response.status_code == 200:
        data = response.json()
        analysis_id = data.get("data", {}).get("id", "")
        print(f"{Fore.YELLOW}[*] Archivo enviado con éxito. Esperando resultados...{Fore.RESET}")
        
        # Consultar análisis por ID
        result_url = f'{BASE_URL}analyses/{analysis_id}'
        while True:
            analysis_response = requests.get(result_url, headers=headers)
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                status = analysis_data.get("data", {}).get("attributes", {}).get("status", "")
                if status == "completed":
                    file_id = analysis_data.get("meta", {}).get("file_info", {}).get("sha256", "")
                    return obtener_info_virustotal('hash', file_id)
            else:
                print(f"{Fore.RED}[!] Error al consultar análisis: {analysis_response.status_code}{Fore.RESET}")
                break
    else:
        print(f"{Fore.RED}[!] Fallo al subir archivo: {response.text}{Fore.RESET}")
    return None

def imprimir_estadisticas(info, tipo, valor):
    stats = info.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless = stats.get("harmless", 0)
    timeout = stats.get("timeout", 0)

    categories = info.get("data", {}).get("attributes", {}).get("categories", {})

    ROJO = "\033[91m"
    AMARILLO = "\033[93m"
    VERDE = "\033[92m"
    AZUL = "\033[34m"
    GRIS = "\033[90m"
    CIAN = "\033[96m"
    RESET = "\033[0m"

    print(f"\n{VERDE}=== Resultados de la consulta a VirusTotal ==={RESET}\n")
    print(f"{AMARILLO}Tipo de Consulta:{RESET} {tipo}")
    print(f"{AMARILLO}Valor Consultado:{RESET} {valor}")
    print(f"\n{Fore.GREEN}=== Estadísticas de Análisis ==={Fore.RESET}")
    
    print(f"{ROJO}Malicioso:{RESET} {malicious}")
    print(f"{AMARILLO}Sospechoso:{RESET} {suspicious}")
    print(f"{AZUL}Indetectado:{RESET} {undetected}")
    print(f"{VERDE}Inofensivo:{RESET} {harmless}")
    print(f"{GRIS}Timeout:{RESET} {timeout}")
    
    if categories:
        print(f"\n{VERDE}=== Categorías detectadas ==={RESET}")
        for categoria, descripcion in categories.items():
            print(f"{CIAN}- {categoria}: {descripcion}{RESET}")

    last_analysis_results = info.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
    palabras_rojas = ['malicious', 'malware', 'phishing', 'trojan', 'virus', 'harmful']

    if last_analysis_results:
        print(f"\n{VERDE}=== Resultados del análisis de motores de seguridad ==={RESET}")
        for engine, result in last_analysis_results.items():
            method = result.get("method", "Desconocido")
            engine_name = result.get("engine_name", "Desconocido")
            category = result.get("category", "Desconocida")
            result_status = result.get("result", "Desconocido")

            if any(p in category.lower() for p in palabras_rojas) or any(p in str(result_status).lower() for p in palabras_rojas):
                print(f"{ROJO}- {engine_name} ({method}){RESET}: {category} - {result_status}")
            else:
                print(f"{CIAN}- {engine_name} ({method}){RESET}: {category} - {result_status}")
    print("\n===============================")

def main():
    parser = argparse.ArgumentParser(description="Consulta a VirusTotal")
    parser.add_argument('--url', help='Buscar información sobre una URL', type=str)
    parser.add_argument('--ip', help='Buscar información sobre una IP', type=str)
    parser.add_argument('--domain', help='Buscar información sobre un dominio', type=str)
    parser.add_argument('--hash', help='Buscar información sobre un hash (SHA256, MD5, etc)', type=str)
    parser.add_argument('--upload', help='Subir archivo para escaneo', type=str)
    args = parser.parse_args()

    if args.url:
        tipo = 'url'
        valor = args.url
    elif args.ip:
        tipo = 'ip'
        valor = args.ip
    elif args.domain:
        tipo = 'domain'
        valor = args.domain
    elif args.hash:
        tipo = 'hash'
        valor = args.hash
    elif args.upload:
        print(f"{Fore.CYAN}[*] Subiendo archivo a VirusTotal...{Fore.RESET}")
        info = subir_y_analizar_archivo(args.upload)
        if info:
            imprimir_estadisticas(info, 'file', args.upload)
        else:
            print(f"{Fore.RED}[!] No se pudo obtener información del archivo.{Fore.RESET}")
        return
    else:
        print("Debe proporcionar al menos uno de los parámetros: --url, --ip, --domain, --hash, --upload")
        sys.exit(1)

    print(f"Consultando VirusTotal para {tipo}: {Fore.GREEN}{valor}{Fore.RESET}")
    info = obtener_info_virustotal(tipo, valor)

    if info:
        imprimir_estadisticas(info, tipo, valor)
    else:
        print(f"{Fore.RED}[!] No se pudo obtener información para {tipo}: {valor}.{Fore.RESET}")

if __name__ == '__main__':
    print(f"""{Fore.MAGENTA}

██╗   ██╗██╗██████╗ ██╗   ██╗███████╗████████╗ ██████╗ ████████╗ █████╗ ██╗     
██║   ██║██║██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔═══██╗╚══██╔══╝██╔══██╗██║     
██║   ██║██║██████╔╝██║   ██║███████╗   ██║   ██║   ██║   ██║   ███████║██║     
╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║   ██║   ██║   ██║   ██║   ██╔══██║██║     
 ╚████╔╝ ██║██║  ██║╚██████╔╝███████║   ██║   ╚██████╔╝   ██║   ██║  ██║███████╗
  ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝
\\________________________________ {Fore.GREEN}Mr r00t11{Fore.RESET}{Fore.MAGENTA} ________________________________/
{Fore.RESET}""")
    main()
