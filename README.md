# 🛡️ VirusTotal Lookup Tool

Este script en Python permite consultar y analizar indicadores de compromiso (IoCs) utilizando la API de VirusTotal. Ofrece soporte para búsquedas de IPs, URLs, dominios, hashes de archivos, y la capacidad de subir archivos para su escaneo automático.

---

## 🚀 Funcionalidades

- Consulta de información para:
  - URLs
  - Direcciones IP
  - Dominios
  - Hashes (MD5, SHA1, SHA256)
- Subida de archivos para análisis dinámico
- Visualización detallada del análisis:
  - Motores de detección
  - Estadísticas (malicioso, sospechoso, inofensivo, etc.)
  - Categorías y resultados relevantes
- Colores en la consola para facilitar la lectura
- Identificación visual de amenazas con palabras clave (malware, phishing, etc.)

---

## 🧰 Requisitos

- Python 3.6 o superior
- Módulos:
  - `requests`
  - `argparse`
  - `colorama`

Instala los módulos necesarios con:

```bash
pip install requests colorama
```

## 🔑 Configuración

Edita el script y reemplaza la siguiente línea con tu API Key de VirusTotal:

```bash
API_KEY = 'TU_API_KEY_AQUI'
```
Puedes obtener una clave gratuita en: [https://www.virustotal.com](https://www.virustotal.com)

## 🛠️ Uso

```bash
python virustotal_lookup.py --ip 8.8.8.8 
python virustotal_lookup.py --url https://example.com
python virustotal_lookup.py --domain example.com
python virustotal_lookup.py --hash d41d8cd98f00b204e9800998ecf8427e 
python virustotal_lookup.py --upload archivo_sospechoso.exe
```

## 📦 Parámetros

| Parámetro  | Descripción                     |
| ---------- | ------------------------------- |
| `--ip`     | Consulta una dirección IP       |
| `--url`    | Consulta una URL                |
| `--domain` | Consulta un dominio             |
| `--hash`   | Consulta el hash de un archivo  |
| `--upload` | Sube un archivo para su escaneo |
___
