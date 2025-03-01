import discord
from discord.ext import commands
import socket
import concurrent.futures
import asyncio
import requests
import platform
import os
import re
import random
import string
from bs4 import BeautifulSoup
import ping3
import json
import phonenumbers
from phonenumbers import carrier, geocoder
import time
import datetime
from phonenumbers import NumberParseException
import ssl
import whois
import cryptography
import qrcode
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import sqlite3

# Bot configuration
token = "MTI4NDU4OTY2OTIwNzUwNjk5NA.GH47xo.4G2SI-RkgVCNls0NgdIiNcEus97r5FR6_ALN7o"

intents = discord.Intents.default()
intents.messages = True  
intents.message_content = True 
attack_running = False
stop_flag = False

bot = commands.Bot(command_prefix="~$ ", intents=intents)

client = discord.Client(intents=intents)


# Listas de User-Agents y proxies
user_agents = [
    # Chrome (Windows, Mac, Linux)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",

    # Firefox (Windows, Mac, Linux)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:119.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:119.0) Gecko/20100101 Firefox/119.0",

    # Edge (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",

    # Safari (Mac)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/17.1 Safari/537.36",

    # Móviles (Android, iOS)
    "Mozilla/5.0 (Linux; Android 12; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/537.36"
]

proxies = [
    "http://198.50.191.95:8080",
    "http://51.158.186.141:3128",
    "http://178.128.60.226:8080",
    "http://161.97.158.118:8080",
    "http://195.154.42.163:3128",
    "http://8.219.97.248:80",
    "http://212.112.113.178:3128",
    "http://103.111.225.38:8080",
    "http://195.46.20.146:8080",
    "http://185.220.101.7:80",
    "http://103.108.90.129:8080"
]

# Evasión de detección
async def send_request(url):
    headers = {'User-Agent': random.choice(user_agents)}
    proxy = {'http': random.choice(proxies), 'https': random.choice(proxies)}
    try:
        response = requests.get(url, headers=headers, proxies=proxy, timeout=10)
        return f"Response: {response.status_code}"
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

# Escaneo de puertos con Nmap
async def scan_ports(target, range_ports):
    nm = nmap.PortScanner()
    try:
        nm.scan(target, range_ports, arguments="-sS -O")
        result = nm[target]
        return f"Scan result for `{target}`:\n`{result}`"
    except Exception as e:
        return f"Error scanning `{target}`: `{e}`"

# Ejecución de herramientas de seguridad
async def run_nikto(target):
    os.system(f"nikto -h {target}")

async def run_wpscan(target):
    os.system(f"wpscan --url {target}")

async def run_sqlmap(target):
    os.system(f"sqlmap -u {target} --batch --risk=3 --level=5")

# Email Breach Tracking with Hunter
@bot.command()
async def check_breach(ctx, email: str):
    """Checks if an email address has been compromised in a data breach."""
    api_key = "f7bf37f4eb14c3b899d4c70b19c016444be3924b"  # Replace with your valid API key
    url = f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={api_key}"

    try:
        response = requests.get(url)
        response.raise_for_status()  # Raises an error if response is not 200
        data = response.json()

        if "data" in data:
            status = data["data"].get("status", "unknown")
            if status == "valid":
                await ctx.send(f"✅ The email {email} is valid.")
            elif status == "invalid":
                await ctx.send(f"❌ The email {email} is invalid.")
            else:
                await ctx.send(f"⚠️ The email {email} could not be verified.")
        else:
            await ctx.send("⚠️ Error in the API response.")

    except requests.exceptions.RequestException as e:
        await ctx.send(f"❌ Error connecting to the API: {e}")

# Comandos del bot
@client.event
async def on_message(message):
    if message.content.startswith("~$ ping"):
        url = message.content.split(" ")[1]
        response = await send_request(url)
        await message.channel.send(response)
    elif message.content.startswith("~$ nmap"):
        parts = message.content.split(" ")
        target = parts[1]
        port_range = parts[2]
        scan_result = await scan_ports(target, port_range)
        await message.channel.send(scan_result)
    elif message.content.startswith("~$ full_scan"):
        parts = message.content.split(" ")
        target = parts[1]
        await run_nikto(target)
        await run_wpscan(target)
        await run_sqlmap(target)
        await message.channel.send(f"Full scan completed for `{target}`")
    elif message.content.startswith("~$ tracklu"):
        email = message.content.split(" ")[1]
        breach_info = await check_breach(email)
        await message.channel.send(breach_info)
        
        
# Comando para mostrar información del usuario
@bot.command()
async def whoami(ctx):
    user_name = ctx.author.name  # Obtiene el nombre del usuario
    user_id = ctx.author.id  # Obtiene el user_id del usuario
    roles = [role.name for role in ctx.author.roles if role.name != "@everyone"]  # Obtiene los roles del usuario, excluyendo @everyone
    roles_string = ", ".join(roles) if roles else "Sin roles"  # Si tiene roles, los lista, si no, muestra "Sin roles"
    
    await ctx.send(f"**Nombre de usuario**: `{user_name}`\n"
                   f" "
                   f"**ID de usuario**: `{user_id}`\n"
                   f" "
                   f"**Roles**: `{roles_string}`")

# Function to scan a specific port
def scan_port(target, port):
    """Scans a specific port on the target and returns its status."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        if s.connect_ex((target, port)) == 0:
            try:
                service = socket.getservbyport(port)
            except:
                service = "Unknown"
            return port, service
    return None

# Parallel port scanning
async def scan_target(target, port_range):
    """Scans multiple ports on the target and returns the open ones."""
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        loop = asyncio.get_running_loop()
        results = await asyncio.gather(*[loop.run_in_executor(executor, scan_port, target, port) for port in port_range])

    for result in results:
        if result:
            open_ports.append(result)

    return open_ports

# Get system information
def get_os_info(target):
    """Gets basic system information of the target"""
    try:
        info = os.uname()
        return f"[@#@] **Operating system**: \n`{info.sysname}` \n`{info.release}` \n`{info.version} on {info.machine}` \n`({platform.system()}) @ {target}`"
    except Exception as e:
        return f"[!] Error getting system info: {e}"


@bot.command()
async def AES(ctx, *, texto: str):
    # Genera una clave aleatoria de 32 bytes
    clave = os.urandom(32)

    # Crea un objeto Cipher con el algoritmo AES y la clave
    cipher = Cipher(algorithms.AES(clave), modes.CBC(os.urandom(16)), backend=default_backend())

    # Crea un objeto Encryptor
    encryptor = cipher.encryptor()

    # Ajusta el texto para que tenga un tamaño múltiplo de 16 bytes
    padder = padding.PKCS7(128).padder()
    texto_padded = padder.update(texto.encode()) + padder.finalize()

    # Cifra el texto
    texto_cifrado = encryptor.update(texto_padded) + encryptor.finalize()

    # Codifica el texto cifrado en base64
    texto_cifrado_base64 = base64.b64encode(texto_cifrado).decode()

    # Envía el texto cifrado y la clave
    await ctx.send(f"Texto cifrado: `{texto_cifrado_base64}`")
    await ctx.send(f"Clave: `{clave.hex()}`")



@bot.command()
async def server_info(ctx, url: str):
    try:
        response = requests.get(url)
        server = response.headers.get('Server', 'No server information found')
        await ctx.send(f"Server info for {url}: `{server}`")
    except Exception as e:
        await ctx.send(f"Error fetching server info for {url}: `{e}`")



# URL analysis with VirusTotal

@bot.command()
async def sec_url(ctx, url: str):
    api_key = "433bd0a7952b94a484e2ff81ec6f173efcdfd16ece3db6d1e64b02424f3950e5"  # Reemplaza con tu API key de VirusTotal
    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/urls/{url}"

    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        json_response = response.json()
        if json_response["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0:
            await ctx.send(f"Warning! `{url}` is flagged as malicious.")
        else:
            await ctx.send(f"`{url}` appears to be safe.")
    else:
        await ctx.send(f"Error: Unable to check `{url}` with VirusTotal. Status code: `{response.status_code}`")

# Event when the bot is ready
@bot.event
async def on_ready():
    print(f"[^!^] {bot.user} is online and ready to scan!")


@bot.command()
async def dns(ctx, domain: str):
    try:
        ip_address = socket.gethostbyname(domain)
        await ctx.send(f"DNS Lookup for `{domain}`: `{ip_address}`")
    except socket.gaierror:
        await ctx.send(f"Could not resolve the domain: `{domain}`")

@bot.command()
async def whois(ctx, domain: str):
    try:
        w = whois.whois(domain)
        await ctx.send(f"WHOIS information for `{domain}`:\n`{w}`")
    except Exception as e:
        await ctx.send(f"Could not retrieve WHOIS info for `{domain}`. Error: `{e}`")


@bot.command()
async def iptrack(ctx, ip: str):
    req_api = requests.get(f"http://ipwho.is/{ip}")
    ip_data = json.loads(req_api.text)
    time.sleep(2)
    await ctx.send(f"`IP target: {ip}`")
    await ctx.send(f"`Type IP: {ip_data['type']}`")
    await ctx.send(f"`Country: {ip_data['country']}`")
    await ctx.send(f"`City: {ip_data['city']}`")
    await ctx.send(f"`Latitude: {ip_data['latitude']}`")
    await ctx.send(f"`Longitude: {ip_data['longitude']}`")
    await ctx.send(f"`Maps:` https://www.google.com/maps/@{ip_data['latitude']},{ip_data['longitude']},8z  ")
    await ctx.send(f"`Organization: {ip_data['org']}`")
    await ctx.send(f"`Timezone: {ip_data['timezone']}`")
    await ctx.send(f"`Time: {datetime.datetime.now()}`")

# Definir el comando phoneGW
@bot.command()
async def phonegw(ctx, User_phone: str):
    default_region = "ID"  # Región predeterminada
    try:
        parsed_number = phonenumbers.parse(User_phone, default_region)
        region_code = phonenumbers.region_code_for_number(parsed_number)
        jenis_provider = carrier.name_for_number(parsed_number, "en")
        location = geocoder.description_for_number(parsed_number, "id")
        is_valid_number = phonenumbers.is_valid_number(parsed_number)
        await ctx.send(f"`Location: {location}`")
        await ctx.send(f"`Region Code: {region_code}`")
        await ctx.send(f"`Operator: {jenis_provider}`")
        await ctx.send(f"`Valid number: {is_valid_number}`")
        await ctx.send(f"`Phone number: {User_phone}`")
    except NumberParseException:
        await ctx.send("The provided string does not seem to be a valid phone number. Please check the format and try again.")

# Definir el comando TrackLu
@bot.command()
async def tracklu(ctx, username: str):
    results = {}
    social_media = [
        {"url": "https://www.facebook.com/{}", "name": "Facebook"},
        {"url": "https://www.twitter.com/{}", "name": "Twitter"},
        {"url": "https://www.instagram.com/{}", "name": "Instagram"},
        {"url": "https://www.linkedin.com/in/{}", "name": "LinkedIn"},
        {"url": "https://www.github.com/{}", "name": "GitHub"},
        {"url": "https://www.pinterest.com/{}", "name": "Pinterest"},
        {"url": "https://www.tumblr.com/blog/{}", "name": "Tumblr"},
        {"url": "https://www.flickr.com/people/{}", "name": "Flickr"},
        {"url": "https://www.vk.com/{}", "name": "VK"},
        {"url": "https://www.soundcloud.com/{}", "name": "SoundCloud"},
        {"url": "https://www.snapchat.com/add/{}", "name": "Snapchat"},
        {"url": "https://www.twitch.tv/{}", "name": "Twitch"},
        {"url": "https://www.tiktok.com/@{}", "name": "TikTok"},
        {"url": "https://www.reddit.com/user/{}", "name": "Reddit"},
        {"url": "https://www.youtube.com/{}", "name": "YouTube"},
        {"url": "https://www.medium.com/{}", "name": "Medium"},
        {"url": "https://www.quora.com/profile/{}", "name": "Quora"},
        {"url": "https://www.behance.net/{}", "name": "Behance"},
        {"url": "https://www.dribbble.com/{}", "name": "Dribbble"},
        {"url": "https://www.patreon.com/{}", "name": "Patreon"},
        {"url": "https://www.etsy.com/people/{}", "name": "Etsy"},
        {"url": "https://www.goodreads.com/{}", "name": "Goodreads"},
        {"url": "https://www.last.fm/user/{}", "name": "Last.fm"},
        {"url": "https://www.producthunt.com/@{}", "name": "Product Hunt"},
        {"url": "https://www.500px.com/{}", "name": "500px"},
        {"url": "https://www.tripadvisor.com/Profile/{}", "name": "TripAdvisor"},
        {"url": "https://www.ello.co/{}", "name": "Ello"},
        {"url": "https://www.myspace.com/{}", "name": "MySpace"},
        {"url": "https://www.foursquare.com/{}", "name": "Foursquare"},
        {"url": "https://www.badoo.com/en/{}/", "name": "Badoo"},
        {"url": "https://www.xing.com/profile/{}", "name": "Xing"},
        {"url": "https://www.couchsurfing.com/people/{}", "name": "Couchsurfing"},
        {"url": "https://www.meetup.com/members/{}", "name": "Meetup"},
        {"url": "https://www.reverbnation.com/{}", "name": "ReverbNation"},
        {"url": "https://www.scribd.com/{}", "name": "Scribd"},
        {"url": "https://www.livejournal.com/profile?userid={}", "name": "LiveJournal"},
        {"url": "https://www.angellist.com/u/{}", "name": "AngelList"},
        {"url": "https://www.bandcamp.com/{}", "name": "Bandcamp"},
        {"url": "https://www.care2.com/c2c/people/profile.html?pid={}", "name": "Care2"},
        {"url": "https://www.codementor.io/{}", "name": "Codementor"},
        {"url": "https://www.deviantart.com/{}", "name": "DeviantArt"},
        {"url": "https://www.flattr.com/profile/{}", "name": "Flattr"},
        {"url": "https://www.fiverr.com/{}", "name": "Fiverr"},
        {"url": "https://www.hackerone.com/{}", "name": "HackerOne"},
        {"url": "https://www.hackster.io/{}", "name": "Hackster"},
        {"url": "https://www.instructables.com/member/{}", "name": "Instructables"},
        {"url": "https://www.keybase.io/{}", "name": "Keybase"},
        {"url": "https://www.kickstarter.com/profile/{}", "name": "Kickstarter"},
        {"url": "https://www.kongregate.com/accounts/{}", "name": "Kongregate"},
        {"url": "https://www.lonelyplanet.com/profile/{}", "name": "Lonely Planet"},
        {"url": "https://www.moz.com/community/users/{}", "name": "Moz"},
        {"url": "https://www.pornhub.com/users/{}", "name": "Pornhub"},
        {"url": "https://www.xnxx.com/u/{}", "name": "XNXX"},
        {"url": "https://www.redtube.com/users/{}", "name": "RedTube"},
        {"url": "https://www.scoop.it/u/{}", "name": "Scoop.it"},
        # Agregar más plataformas si es necesario
    ]
    for site in social_media:
        url = site['url'].format(username)
        response = requests.get(url)
        if response.status_code == 200:
            results[site['name']] = url
        else:
            results[site['name']] = "`Username` **not found!**"
    
    for site, url in results.items():
        await ctx.send(f"`{site}`: {url}")


    
# Función que descarga el HTML de la URL proporcionada
def download_html(url):
    try:
        # Realiza una solicitud HTTP GET a la URL
        response = requests.get(url)

        # Verifica si la solicitud fue exitosa
        if response.status_code == 200:
            # Nombre del archivo basado en el dominio de la URL
            filename = url.split('//')[-1].split('/')[0] + '.html'

            # Guardamos el HTML en el archivo
            with open(filename, 'w', encoding='utf-8') as file:
                file.write(response.text)

            return filename
        else:
            return None
    except requests.exceptions.RequestException as e:
        print(f"[!] **Ocurrió un error**: `{e}`")
        return None

# Comando ~$ g_web (url) para descargar el HTML de una página
@bot.command()
async def g_web(ctx, url: str):
    # Llama a la función para descargar el HTML
    filename = download_html(url)

    if filename:
        # Envia el archivo HTML como un archivo adjunto en el canal de Discord
        with open(filename, 'rb') as file:
            await ctx.send(file=discord.File(file, filename=filename))
    else:
        await ctx.send("`[!] No se pudo descargar la página o el código de estado fue incorrecto.`.")

# Command to scan ports
@bot.command()
async def nmap(ctx, target: str, ports: str = "1-1024"):
    """Advanced scan for open ports on the target."""
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        await ctx.send("[!] **Unable to resolve the host**.")
        return

    await ctx.send(f"[@@] **Scanning** `{target}`  **in range** `{ports}`...")
    port_start, port_end = map(int, ports.split("-"))
    open_ports = await scan_target(ip, range(port_start, port_end + 1))

    if open_ports:
        output = "[@@@] **Open ports**:\n" + "\n".join([f"`{port}/tcp ({service})`" for port, service in open_ports])
    else:
        output = "[!] **No open ports found.**"

    await ctx.send(f"{output}")
    





@bot.command()
async def ping(ctx, ip: str):
    try:
        response = ping3.ping(ip)
        
        if response is None:
            await ctx.send(f"[!] `Error`: **Could not reach the address** `{ip}`.")
        else:
            await ctx.send(f"[&] **Response from** `{ip}`: `{response * 1000:.2f} ms`")
    except Exception as e:
        await ctx.send(f"[!] **An error occurred**: {e}")

# Command to scan a URL with VirusTotal
@bot.command()
async def scan_url(ctx, url: str):
    """Scans if a URL is malicious using VirusTotal or a similar API."""
    await ctx.send(f"[#] Analyzing {url} in security databases...")
    result = await analyze_url(url)
    await ctx.send(result)

# Command to get the OS information
@bot.command()
async def os_info(ctx, target: str):
    """Gets basic system information of the target."""
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        await ctx.send("Unable to resolve the host.")
        return

    os_info = get_os_info(target)
    await ctx.send(f"[%] System information for {target} ({ip}):\n{os_info}")
    
    
@bot.command()
async def check_security(ctx, url: str):
    """Scans a website to check if it's protected by Cloudflare or another firewall."""
    try:
        # Send a HEAD request to get the headers
        response = requests.head(url, timeout=10)
        
        # Check if Cloudflare is present in the headers
        headers = response.headers
        cloudflare_detected = "cf-ray" in headers or "server" in headers and "cloudflare" in headers["server"].lower()
        
        # Check if any firewall is detected
        firewall_detected = "x-sucuri-id" in headers or "x-cloudflare-proxy" in headers
        
        if cloudflare_detected:
            await ctx.send(f"[C] The site `{url}` is protected by `Cloudflare`.")
        elif firewall_detected:
            await ctx.send(f"[!] The site `{url}` is protected by a `firewall` (could be Cloudflare or another one).")
        else:
            await ctx.send(f"[@] The site `{url}` doesn't seem to have any known `Cloudflare` or `firewall` protection.")
    except requests.exceptions.RequestException as e:
        await ctx.send(f"[!] Error while trying to connect to the site: {e}")
        
@bot.command()
async def pass_gen(ctx):
    """Generates a secure random password and sends it privately to the user."""
    length = 16  # You can change this to the desired length

    # Create a pool of characters: lowercase, uppercase, digits, and special characters
    characters = string.ascii_letters + string.digits + string.punctuation

    # Generate a random password
    password = ''.join(random.choice(characters) for _ in range(length))

    # Send the password privately to the user
    await ctx.author.send(f"[$] **Your secure generated password is**: `{password}`")

    # Notify the user that the password has been sent privately
    await ctx.send("`[*] A secure password has been generated and sent to you privately.`")
    
    
@bot.command()
async def neofetch(ctx):
    """Simulates a neofetch output for a high-end Kali Linux machine."""
    
    # Fictitious system information
    fake_neofetch = """
    ```
    █████████████████████████████████
    OS: Kali Linux 2025.1 x86_64
    Kernel: 6.10.1-kali9-amd64
    Uptime: 79 days, 19 hours,
    19 minutes
    Packages: 3032+ (estimated)
    Shell: bash 6.1.4
    CPU: Intel Core i9-11900K 
    @ 3.50GHz
    GPU: NVIDIA RTX 3080
    RAM: 64GB DDR4
    Disk: 2TB SSD (1.2TB used)
    Battery: 89% (Plugged in)
    █████████████████████████████████
    ```
    """
    
    # Send the simulated neofetch output to the user
    await ctx.send(f"{fake_neofetch}")
    
    

# Función para convertir texto a binario
def text_to_binary(text):
    return ' '.join(format(ord(char), '08b') for char in text)

# Comando para convertir texto a binario
@bot.command()
async def text_to_bin(ctx, *, text: str):
    """Convierte un texto a binario y lo responde en el chat"""
    binary = text_to_binary(text)
    await ctx.send(f"[-] Binary representation: /n `{binary}`")

@bot.command()
async def pass_sec(ctx, password: str):
    """Checks the strength of a password."""
    # Criteria for a secure password
    min_length = 8
    max_length = 16
    special_chars = r"[@$!%*?&]"
    numbers = r"\d"
    uppercase = r"[A-Z]"
    lowercase = r"[a-z]"

    # Check password length
    if len(password) < min_length or len(password) > max_length:
        await ctx.send("[!] Password must be between 8 and 16 characters long.")
        return
    
    # Check if password contains special characters, numbers, uppercase and lowercase letters
    if not re.search(special_chars, password):
        await ctx.send("[!] Password must contain at least one special character (@, $, !, %, *, ?, &).")
        return
    if not re.search(numbers, password):
        await ctx.send("[!] Password must contain at least one number.")
        return
    if not re.search(uppercase, password):
        await ctx.send("[!] Password must contain at least one uppercase letter.")
        return
    if not re.search(lowercase, password):
        await ctx.send("[!] Password must contain at least one lowercase letter.")
        return

    # If the password meets all criteria
    await ctx.send("[*] Password is secure!")



        
# Your API key
API_KEY = 'f7bf37f4eb14c3b899d4c70b19c016444be3924b'

# Function to find an email using Hunter.io
def find_email(first_name, last_name, domain):
    url = f'https://api.hunter.io/v2/email-finder?domain={domain}&first_name={first_name}&last_name={last_name}&api_key={API_KEY}'
    response = requests.get(url)
    data = response.json()
    
    if data['data']:
        email = data['data']['email']
        return email
    else:
        return "No email found."
        
        
# Your API key
API_KEY = 'f7bf37f4eb14c3b899d4c70b19c016444be3924b'

# Function to search emails by domain using Hunter.io
def search_by_domain(domain):
    url = f'https://api.hunter.io/v2/domain-search?domain={domain}&api_key={API_KEY}'
    response = requests.get(url)
    data = response.json()
    
    if 'data' in data and 'emails' in data['data']:
        emails = data['data']['emails']
        email_list = [email['value'] for email in emails]
        return '\n'.join(email_list)
    else:
        return "No emails found for this domain."


@bot.command()
async def echo(ctx, *, mensaje: str):
    await ctx.send(mensaje)



        
api_key = "9AXWDZ78RROG0F1XLNGCR96ZQ0RD6JUNVF04DH6874GAINWLV8LZ53I5YEKHCF5RQN4ITDW3BM2VTN7K"
# Definir el comando de scraping
@bot.command()
async def scraping_url(ctx, url: str):
    # URL de la API de ScrapingBee
    scrapingbee_url = "https://app.scrapingbee.com/api/v1/"
    
    # Parámetros para la solicitud
    params = {
        "api_key": api_key,
        "url": url,
        "render": "true"  # Activar la renderización de JavaScript si es necesario
    }
    
    # Hacer la solicitud GET a la API de ScrapingBee
    response = requests.get(scrapingbee_url, params=params)

    if response.status_code == 200:
        # Enviar el contenido HTML como mensaje (limitado a 2000 caracteres)
        await ctx.send(f"Successfully scraped the content of {url}:\n{response.text[:2000]}")  # Limitar a 2000 caracteres
    else:
        await ctx.send(f"Error: {response.status_code}")


@bot.command()
async def headers(ctx, url: str):
    # Solicitar encabezados HTTP
    response = requests.head(url)
    
    # Mostrar los encabezados
    if response.status_code == 200:
        await ctx.send(f"Headers for {url}:\n{response.headers}")
    else:
        await ctx.send(f"Error: {response.status_code} while fetching headers")


@bot.command()
async def ssl_check(ctx, url: str):
    try:
        hostname = url.replace("https://", "").replace("http://", "")
        context = ssl.create_default_context()
        connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
        connection.connect((hostname, 443))  # Puerto 443 es para HTTPS
        cert = connection.getpeercert()
        await ctx.send(f"SSL certificate for {url} is valid.\nCertificate details:\n{cert}")
    except Exception as e:
        await ctx.send(f"SSL check failed for {url}. Error: {e}")


@bot.command()
async def qr_code(ctx, url: str):
    try:
        # Obtener el título de la URL
        response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string if soup.title else "Sin título"

        # Crear el código QR
        qr = qrcode.make(url)
        qr_path = f"qr_{ctx.author.id}.png"
        qr.save(qr_path)

        # Enviar el QR con el título y mención
        file = discord.File(qr_path)
        await ctx.send(content=f"{ctx.author.mention}\n**Título:** {title}", file=file)

        # Eliminar el archivo después de enviarlo
        os.remove(qr_path)
    except Exception as e:
        await ctx.send(f"Error: {str(e)}")


@bot.command()
async def id(ctx):
    await ctx.send(f"**ID:** `{ctx.author.id}`")

@bot.command()
async def repeat(ctx):
    if ctx.message.content.startswith('~$ '):
        comando = ctx.message.content[4:]
        await ctx.send(f"**Repeating command:** {comando}")
        await ctx.invoke(bot.get_command(comando))
    else:
        await ctx.send("**No command to repeat**")


import subprocess

@bot.command()
async def ls(ctx):
    try:
        output = subprocess.check_output(["ls"])
        await ctx.send(f"**File list:**\n{output.decode('utf-8')}")
    except Exception as e:
        await ctx.send(f"**Error executing command:** {e}")

# Command to search emails by domain
@bot.command()
async def get_domain_emails(ctx, domain: str):
    emails = search_by_domain(domain)
    await ctx.send(f'Emails found for **{domain}**:\n `{emails}` ')

# Command to get Gmail address based on first name and last name
@bot.command()
async def get_gmail(ctx, name: str):
    try:
        parts = name.split(' ')
        first_name = parts[0]
        last_name = parts[1]
        domain = 'gmail.com'

        email = find_email(first_name, last_name, domain)
        await ctx.send(f'Email found: {email}')
    
    except IndexError:
        await ctx.send('Please provide the name and surname in the format: `$ get_gmail <first_name> <last_name>`')


@bot.command()
async def processlist(ctx):
    try:
        output = subprocess.check_output(["ps", "-ef"])
        output_str = output.decode('utf-8')
        max_message_size = 2000  # Tamaño máximo del mensaje
        messages = [output_str[i:i+max_message_size] for i in range(0, len(output_str), max_message_size)]
        for i, message in enumerate(messages):
            if i == 0:
                await ctx.send(f"**Process List (Part {i+1}/{len(messages)}):**\n`{message}`")
            else:
                await ctx.send(f"**(Part {i+1}/{len(messages)}):**\n`{message}`")
    except Exception as e:
        await ctx.send(f"**Error:** `{e}`")



@bot.command()
async def searchsploit(ctx, *, args: str):
    """Searches for exploits in the Exploit-DB database"""
    try:
        if args.startswith("-p"):
            exploit = args.split(" ")[1]
            output = subprocess.check_output(["searchsploit", "-p", exploit])
            await ctx.send(f"**Exploit Path:**\n{output.decode('utf-8')}")
        else:
            output = subprocess.check_output(["searchsploit", args])
            output_str = output.decode('utf-8')
            max_message_size = 2000  # Tamaño máximo del mensaje
            messages = [output_str[i:i+max_message_size] for i in range(0, len(output_str), max_message_size)]
            for i, message in enumerate(messages):
                if i == 0:
                    await ctx.send(f"**Search Results (Part {i+1}/{len(messages)}):**\n`{message}`")
                else:
                    await ctx.send(f"**(Part {i+1}/{len(messages)}):**\n`{message}`")
    except Exception as e:
        await ctx.send(f"**Error:** `{e}`")


@bot.command()
async def sqlmap(ctx, *, args: str):
    """Ejecuta sqlmap con los parámetros proporcionados"""
    try:
        output = subprocess.check_output(["sqlmap", "-v", "3", "--batch", "--risk=3", "--level=5", args])
        output_str = output.decode('utf-8')
        max_message_size = 2000  # Tamaño máximo del mensaje
        messages = [output_str[i:i+max_message_size] for i in range(0, len(output_str), max_message_size)]
        for i, message in enumerate(messages):
            if i == 0:
                await ctx.send(f"**Sqlmap Output (Part {i+1}/{len(messages)}):**\n`{message}`")
            else:
                await ctx.send(f"**(Part {i+1}/{len(messages)}):**\n`{message}`")
    except Exception as e:
        await ctx.send(f"**Error:** `{e}`")


@bot.command()
async def touch(ctx, *, args: str):
    """Crea un archivo con el nombre proporcionado"""
    try:
        output = subprocess.check_output(["touch", args])
        await ctx.send(f"**Archivo creado:** `{args}`")
    except Exception as e:
        await ctx.send(f"**Error:** `{e}`")

@bot.command()
async def nano(ctx, archivo: str, *, texto: str):
    """Edita el archivo con el nombre proporcionado utilizando nano"""
    try:
        with open(archivo, "w") as f:
            f.write(texto)
        await ctx.send(f"**Archivo editado:** `{archivo}`")
    except Exception as e:
        await ctx.send(f"**Error:** `{e}`")


@bot.command()
async def dirbuster(ctx, *, args: str):
    """Ejecuta DirBuster con los parámetros proporcionados"""
    try:
        output = subprocess.check_output(["dirbuster", args])
        output_str = output.decode('utf-8')
        max_message_size = 2000  # Tamaño máximo del mensaje
        messages = [output_str[i:i+max_message_size] for i in range(0, len(output_str), max_message_size)]
        for i, message in enumerate(messages):
            if i == 0:
                await ctx.send(f"**DirBuster Output (Part {i+1}/{len(messages)}):**\n`{message}`")
            else:
                await ctx.send(f"**(Part {i+1}/{len(messages)}):**\n`{message}`")
    except Exception as e:
        await ctx.send(f"**Error:** `{e}`")

@bot.command()
async def hydra(ctx, *, args: str = None):
    """Ejecuta Hydra con los parámetros proporcionados"""
    if args is None:
        await ctx.send(f"**Uso de Hydra:**\n`~$ hydra -l <usuario> -P <archivo_contraseñas> <servidor>`\n\n**Parámetros:**\n`-l` : especifica el nombre de usuario para el ataque.\n`-P` : especifica el archivo de contraseñas para el ataque.\n`<servidor>` : especifica el servidor para el ataque.")
    else:
        try:
            output = subprocess.check_output(["hydra", args])
            output_str = output.decode('utf-8')
            max_message_size = 2000  # Tamaño máximo del mensaje
            messages = [output_str[i:i+max_message_size] for i in range(0, len(output_str), max_message_size)]
            for i, message in enumerate(messages):
                if i == 0:
                    await ctx.send(f"**Hydra Output (Part {i+1}/{len(messages)}):**\n`{message}`")
                else:
                    await ctx.send(f"**(Part {i+1}/{len(messages)}):**\n`{message}`")
        except Exception as e:
            await ctx.send(f"**Error:** `{e}`")

@bot.command()
async def sherlock(ctx, username: str):
    try:
        output = subprocess.check_output(["sherlock", username])
        await ctx.send(f"**Sherlock Results:**\n{output.decode('utf-8')}")
    except Exception as e:
        await ctx.send(f"**Error:** `{e}`")


@bot.command()
async def tor_start(ctx):
    try:
        output = subprocess.check_output(["tor"])
        await ctx.send("`Tor activated successfully.`")
    except Exception as e:
        await ctx.send(f"Error activating Tor: `{e}`")

@bot.command()
async def tor_stop(ctx):
    try:
        output = subprocess.check_output(["pkill", "tor"])
        await ctx.send("`Tor stopped successfully.`")
    except Exception as e:
        await ctx.send(f"Error stopping Tor: `{e}`")

@bot.command()
async def tor_restart(ctx):
    try:
        output = subprocess.check_output(["pkill", "tor"])
        output = subprocess.check_output(["tor"])
        await ctx.send("`Tor restarted successfully.`")
    except Exception as e:
        await ctx.send(f"Error restarting Tor: `{e}`")

@bot.command()
async def tor_request(ctx, url: str):
    try:
        output = subprocess.check_output(["torify", "curl", url])
        await ctx.send(f"`Response from the request:` {output.decode('utf-8')}")
    except Exception as e:
        await ctx.send(f"Error making the request: `{e}`")

@bot.command()
async def imports(ctx):
    try:
        output = subprocess.check_output(["pip", "list"])
        await ctx.send(f"**Imports:**\n`{output.decode('utf-8')}`")
    except Exception as e:
        await ctx.send(f"**Error:** `{e}`")

@bot.command()
async def btc_value(ctx):
    """Displays the current Bitcoin price."""
    url = "https://api.coinbase.com/v2/prices/BTC-USD/spot"
    response = requests.get(url)
    data = json.loads(response.text)
    btc_price = data["data"]["amount"]
    await ctx.send(f"Current Bitcoin price: `${btc_price}`")


@bot.event
async def on_message(message):
    if bot.user.mentioned_in(message) and message.mention_everyone is False:
        embed = discord.Embed(title="Comandos del bot:", color=0x2ecc71)
        embed.set_author(name=bot.user.name, icon_url=bot.user.avatar.url)
        embed.set_footer(text=f"ping for {message.author.name} at {message.created_at.strftime('%H:%M:%S')}")

        commands_list_1 = """
        - `~$ whoami` → Muestra información del usuario que ejecutó el comando.
        - `~$ ping <ip>` → Realiza un ping a una dirección IP y muestra el tiempo de respuesta.
        - `~$ neofetch` → Muestra información del sistema operativo y hardware del dispositivo.
        - `~$ btc_value` → Muestra el precio actual de Bitcoin en dólares.
        - `~$ check_breach <email>` → Verifica si un correo electrónico ha sido comprometido en una brecha de datos.
        """

        commands_list_2 = """
        - `~$ imports` → Muestra una lista de los paquetes de Python instalados.
        - `~$ g_web <url>` → Descarga el HTML de una página web y lo envía en el chat.
        - `~$ processlist` → Muestra una lista de procesos en el sistema.
        - `~$ sherlock <username>` → Realiza una búsqueda en Sherlock y muestra los perfiles encontrados.
        - `~$ nano <archivo> <texto>` → Edita un archivo con el texto proporcionado utilizando nano.
        """

        commands_list_3 = """
        - `~$ touch <archivo>` → Crea un archivo con el nombre proporcionado.
        - `~$ sec_url <url>` → Analiza una URL en VirusTotal para verificar si es malicioso.
        - `~$ hydra <parámetros>` → Ejecuta Hydra con los parámetros proporcionados.
        - `~$ sqlmap <parámetros>` → Ejecuta sqlmap con los parámetros proporcionados.
        - `~$ dirbuster <parámetros>` → Ejecuta DirBuster con los parámetros proporcionados.
        - `~$ searchsploit <parámetros>` → Busca exploits en la base de datos de Exploit-DB.
        - `~$ tor_start` → Inicia el servicio Tor en el sistema.
        - `~$ tor_stop` → Detiene el servicio Tor en el sistema.
        - `~$ tor_restart` → Reinicia el servicio Tor en el sistema.
        - `~$ tor_request <url>` → Realiza una solicitud HTTP a través de Tor.
        """

        commands_list_4 = """
        - `~$ nmap <parámetros>` → Ejecuta nmap con los parámetros proporcionados.
        - `~$ analyze_security <target>` → Analiza la seguridad de un objetivo y muestra un informe detallado.
        - `~$ pass_gen <longitud>` → Genera una contraseña aleatoria con la longitud especificada.
        - `~$ pass_sec <contraseña>` → Evalúa la seguridad de una contraseña y sugiere mejoras si es necesario.
        - `~$ AES <texto>` → Cifra un texto utilizando el algoritmo AES y muestra la clave y el texto cifrado.
        """

        embed.add_field(name="Información del sistema", value=commands_list_1, inline=False)
        embed.add_field(name="Herramientas de desarrollo", value=commands_list_2, inline=False)

        await message.channel.send(embed=embed)

        embed2 = discord.Embed(title="Comandos adicionales:", color=0x1f8b24)
        embed2.add_field(name="Seguridad y análisis", value=commands_list_3, inline=False)
        embed2.add_field(name="Herramientas de seguridad", value=commands_list_4, inline=False)

        await message.channel.send(embed=embed2)

    await bot.process_commands(message)


# 'git_owner' command
@bot.command()
async def git_owner(ctx):
    # Respond with the GitHub link of the bot creator
    await ctx.send("Here is the GitHub link of the bot creator: https://github.com/Rip70022")

        

# Command to perform a full scan of the target
@bot.command()
async def full_scan(ctx, target: str):
    """Performs a full scan (ports, services, and OS)."""
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        await ctx.send("[!] Unable to resolve the host.")
        return

    # Scan ports
    await ctx.send(f"Scanning ports of {target} ({ip}) ...")
    open_ports = await scan_target(ip, range(1, 65535))
    open_ports_output = "Open ports:\n" + "\n".join([f"{port}/tcp ({service})" for port, service in open_ports]) if open_ports else "No open ports found."

    # Get OS information
    os_info = get_os_info(target)

    # Send the full report
    await ctx.send(f"{open_ports_output}\n\nSystem info: {os_info}")


# 'get_kali' command
@bot.command()
async def get_kali(ctx):
    # Respond with the official Kali Linux download link
    await ctx.send("Here is the official Kali Linux download link: https://www.kali.org/downloads/")

# 'get_parrot' command
@bot.command()
async def get_parrot(ctx):
    # Respond with the official Parrot OS download link
    await ctx.send("Here is the official Parrot OS download link: https://www.parrotsec.org/download/")

# 'get_ubuntu' command
@bot.command()
async def get_ubuntu(ctx):
    # Respond with the official Ubuntu download link
    await ctx.send("Here is the official Ubuntu download link: https://ubuntu.com/download/desktop")

# 'get_debian' command
@bot.command()
async def get_debian(ctx):
    # Respond with the official Debian download link
    await ctx.send("Here is the official Debian download link: https://www.debian.org/distrib/")

# 'get_mint' command
@bot.command()
async def get_mint(ctx):
    # Respond with the official Linux Mint download link
    await ctx.send("Here is the official Linux Mint download link: https://linuxmint.com/download.php")

# 'get_fedora' command
@bot.command()
async def get_fedora(ctx):
    # Respond with the official Fedora download link
    await ctx.send("Here is the official Fedora download link: https://getfedora.org/")

# 'get_centos' command
@bot.command()
async def get_centos(ctx):
    # Respond with the official CentOS download link
    await ctx.send("Here is the official CentOS download link: https://www.centos.org/download/")

# 'get_arch' command
@bot.command()
async def get_arch(ctx):
    # Respond with the official Arch Linux download link
    await ctx.send("Here is the official Arch Linux download link: https://archlinux.org/download/")



# Run the bot
bot.run(token)
client.run('MTI4NDU4OTY2OTIwNzUwNjk5NA.GH47xo.4G2SI-RkgVCNls0NgdIiNcEus97r5FR6_ALN7o')
