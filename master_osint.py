#!/usr/bin/env python3

import time
import sys
import os
import re
import json
import webbrowser
from datetime import datetime

try:
    import requests
except ImportError:
    # For MCP, we return an error string instead of exiting
    requests = None

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

try:
    from waybackpy import WaybackMachineCDXServerAPI
except ImportError:
    WaybackMachineCDXServerAPI = None

try:
    import spacy
    SPACY_NLP = spacy.load("en_core_web_sm")
    SPACY_ENABLED = True
except Exception:
    SPACY_ENABLED = False

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, number_type, PhoneNumberType
    PHONENUMBERS_ENABLED = True
except ImportError:
    PHONENUMBERS_ENABLED = False

try:
    import tldextract
    import whois
    import dns.resolver
except ImportError:
    tldextract = whois = dns = None

# --- Helper Functions ---

def find_subdomains_crtsh(domain, max_retries=3, delay=8):
    """Helper function for domain_investigation. Returns a string result."""
    result = f"\nSearching Subdomains via crt.sh for: {domain}\n"
    if not requests:
        return result + "Error: 'requests' library not found."

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {'User-Agent': 'MASTER-OSINT-TOOL/1.0'}
    subdomains = set()

    for attempt in range(max_retries):
        try:
            r = requests.get(url, headers=headers, timeout=40)
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name_val = entry.get('name_value', '')
                    for sub in name_val.split('\n'):
                        sub = sub.strip().strip('.')
                        if sub.endswith('.' + domain) or sub == domain:
                            subdomains.add(sub)
                break
            else:
                result += f"crt.sh HTTP {r.status_code} on attempt {attempt+1}/{max_retries}\n"
        except Exception as e:
            result += f"crt.sh attempt {attempt+1} error: {e}\n"
        if attempt < max_retries -1:
            time.sleep(delay)

    if subdomains:
        result += f"Found {len(subdomains)} subdomains:\n"
        for s in sorted(subdomains):
            result += f" - {s}\n"
    else:
        result += "No subdomains found or failed after retries.\n"
    return result

# --- MCP-Compatible OSINT Functions ---
# Each function accepts parameters and returns a string.

def image_geolocation(image_path: str) -> str:
    """Extract GPS coordinates from an image's EXIF metadata."""
    try:
        import exifread
    except ImportError:
        return "Error: 'exifread' module not found. Please install it with 'pip install exifread'."

    if not os.path.exists(image_path):
        return f"Error: File not found at '{image_path}'."

    try:
        with open(image_path, 'rb') as f:
            tags = exifread.process_file(f)
            if not tags:
                return "No EXIF tags found."

            gps_latitude_ref = tags.get('GPS GPSLatitudeRef')
            gps_latitude = tags.get('GPS GPSLatitude')
            gps_longitude_ref = tags.get('GPS GPSLongitudeRef')
            gps_longitude = tags.get('GPS GPSLongitude')

            if gps_latitude and gps_latitude_ref and gps_longitude and gps_longitude_ref:
                def convert_to_degrees(value):
                    d = float(value.values[0].num) / float(value.values[0].den)
                    m = float(value.values[1].num) / float(value.values[1].den)
                    s = float(value.values[2].num) / float(value.values[2].den)
                    return d + (m / 60.0) + (s / 3600.0)

                lat_deg = convert_to_degrees(gps_latitude)
                if gps_latitude_ref.values[0] == 'S':
                    lat_deg *= -1
                lon_deg = convert_to_degrees(gps_longitude)
                if gps_longitude_ref.values[0] == 'W':
                    lon_deg *= -1

                result = f"GPS Data Found:\n"
                result += f"  Latitude: {lat_deg}\n"
                result += f"  Longitude: {lon_deg}\n"
                result += f"Google Maps Link: https://www.google.com/maps/search/?api=1&query={lat_deg},{lon_deg}\n"
                return result
            else:
                return "No GPS EXIF data found."
    except Exception as e:
        return f"Image processing error: {e}"

def social_media_investigation(username: str) -> str:
    """Generate social profile URLs for a username."""
    if not username:
        return "Error: No username provided."

    platforms = {
        "Facebook": f"https://facebook.com/{username}",
        "Twitter (X)": f"https://twitter.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "Telegram": f"https://t.me/{username}",
        "LinkedIn": f"https://linkedin.com/in/{username}",
        "GitHub": f"https://github.com/{username}",
        "Reddit": f"https://reddit.com/user/{username}",
        "YouTube": f"https://www.youtube.com/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "Medium": f"https://medium.com/@{username}",
        "Pinterest": f"https://www.pinterest.com/{username}",
        "Snapchat": f"https://www.snapchat.com/add/{username}",
        "Vimeo": f"https://vimeo.com/{username}",
        "SoundCloud": f"https://soundcloud.com/{username}",
        "Tumblr": f"https://{username}.tumblr.com",
        "Quora": f"https://www.quora.com/profile/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}",
        "Twitch": f"https://twitch.tv/{username}",
        "Patreon": f"https://www.patreon.com/{username}",
        "Blogger": f"https://{username}.blogspot.com",
        "Goodreads": f"https://www.goodreads.com/{username}",
        "VK": f"https://vk.com/{username}",
        "Ok.ru": f"https://ok.ru/{username}",
        "Dribbble": f"https://dribbble.com/{username}",
        "Flickr": f"https://www.flickr.com/people/{username}",
        "HackerNews": f"https://news.ycombinator.com/user?id={username}",
        "Badoo": f"https://badoo.com/profile/{username}",
        "Ello": f"https://ello.co/{username}",
        "DeviantArt": f"https://www.deviantart.com/{username}",
        "Mixcloud": f"https://www.mixcloud.com/{username}/",
        "Periscope": f"https://www.pscp.tv/{username}",
    }

    result = f"Profile URLs for '{username}':\n"
    for name, url in platforms.items():
        result += f"{name.ljust(15)}: {url}\n"

    result += "\nTip: Use tools like WhatsMyName.app for extensive recon."
    return result

def email_analysis(email: str) -> str:
    """Check email breaches and search public pastes."""
    if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
        return "Error: Invalid email format."

    result = f"Analyzing email: {email}\n"

    # HIBP Check (Disabled by default)
    hibp_api_key = "YOUR_HIBP_API_KEY"
    if hibp_api_key != "YOUR_HIBP_API_KEY" and requests:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {"hibp-api-key": hibp_api_key, "user-agent": "MASTER-OSINT-TOOL"}
        try:
            r = requests.get(url, headers=headers)
            if r.status_code == 200:
                breaches = r.json()
                result += f"Breached in {len(breaches)} breach(es):\n"
                for b in breaches:
                    result += f" - {b['Name']} ({b['BreachDate']})\n"
            elif r.status_code == 404:
                result += "No breaches found on HIBP.\n"
            else:
                result += f"HIBP HTTP Error {r.status_code}\n"
        except Exception as e:
            result += f"Error querying HIBP: {e}\n"
    else:
        result += "HIBP check skipped (API key not configured).\n"

    # Pastebin Search (Disabled for now due to complexity and rate limits)
    result += "\nPastebin search is disabled in API mode for stability.\n"
    # Manual instruction
    result += f"\nManual Google Search opened for: \"{email}\"\n"
    webbrowser.open(f"https://www.google.com/search?q=%22{email}%22")
    return result

def email_lookup_and_verification(email: str) -> str:
    """Uses Hunter.io for lookup (if API key is set)."""
    if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
        return "Error: Invalid email format."

    result = f"Looking up email: {email}\n"

    hunter_api_key = "b8f37109525dce9676fc0a17295461406f67a22b"
    if hunter_api_key != "YOUR_HUNTER_IO_API_KEY" and requests:
        try:
            r = requests.get(f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={hunter_api_key}", timeout=10)
            if r.status_code == 200:
                data = r.json().get('data', {})
                result += f"Status: {data.get('status')}\n"
                result += f"Result: {data.get('result')}\n"
                result += f"Score: {data.get('score')}\n"
                result += f"Disposable: {'Yes' if data.get('disposable') else 'No'}\n"
                result += f"MX Records: {'None' if not data.get('mx_records') else 'Present'}\n"
                result += f"SMTP Check: {data.get('smtp_check')}\n"
                sources = data.get('sources', [])
                if sources:
                    result += "Sources (Up to 3):\n"
                    for s in sources[:3]:
                        result += f" - {s.get('domain')} ({s.get('uri')})\n"
            else:
                result += f"Hunter.io HTTP {r.status_code}\n"
        except Exception as e:
            result += f"Error querying Hunter.io: {e}\n"
    else:
        result += "Hunter.io verification skipped (API key not configured).\n"

    result += "\nManual Lookups:\n"
    result += " - ReverseContact: https://www.reversecontact.com/\n"
    result += " - Epieos: https://epieos.com/\n"
    return result

def domain_investigation(domain: str) -> str:
    """Perform WHOIS, DNS, and subdomain enumeration on a domain."""
    if not domain:
        return "Error: No domain provided."

    if not tldextract or not whois or not dns:
        return "Error: Required modules (tldextract, whois, dnspython) not found."

    # Clean the input
    if domain.startswith(('http://', 'https://')):
        domain = domain.split("://")[1].split('/')[0]

    ext = tldextract.extract(domain)
    if not ext.domain or not ext.suffix:
        return "Error: Invalid domain."

    domain = f"{ext.domain}.{ext.suffix}"
    result = f"Analyzing domain: {domain}\n"

    # WHOIS Lookup
    result += "\n--- WHOIS Lookup ---\n"
    try:
        w = whois.whois(domain)
        registrar = ", ".join(w.registrar) if isinstance(w.registrar, list) else (w.registrar or "N/A")
        result += f"Registrar: {registrar}\n"

        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        creation_str = creation_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(creation_date, datetime) else "N/A"
        result += f"Creation Date: {creation_str}\n"

        if isinstance(creation_date, datetime):
            age_days = (datetime.now() - creation_date).days
            result += f"Domain Age: {age_days} days\n"

        expiration_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        expiration_str = expiration_date.strftime('%Y-%m-%d %H:%M:%S') if isinstance(expiration_date, datetime) else "N/A"
        result += f"Expiration Date: {expiration_str}\n"

        ns = ", ".join(w.name_servers) if w.name_servers else "N/A"
        result += f"Name Servers: {ns}\n"

        stat = w.status
        if stat:
            status_str = ", ".join(stat) if isinstance(stat, list) else stat
            result += f"Status: {status_str}\n"
    except Exception as e:
        result += f"WHOIS lookup failed: {e}\n"

    # DNS Records
    result += "\n--- DNS Records ---\n"
    try:
        for record in ['A','MX','NS']:
            try:
                answers = dns.resolver.resolve(domain, record)
                result += f"{record} Records:\n"
                for addr in answers:
                    if record == 'NS':
                        result += f" - {addr.target.to_text()}\n"
                    else:
                        result += f" - {addr.to_text()}\n"
            except Exception as dns_e:
                result += f"Could not resolve {record} record: {dns_e}\n"
    except Exception as e:
        result += f"General DNS error: {e}\n"

    # Subdomains
    result += "\n--- Subdomains (crt.sh) ---\n"
    result += find_subdomains_crtsh(domain)

    return result

def metadata_extraction(file_path: str) -> str:
    """Extract EXIF metadata from images or basic file metadata."""
    try:
        import exifread
    except ImportError:
        return "Error: 'exifread' module not found."

    if not os.path.exists(file_path):
        return "Error: File not found."

    try:
        with open(file_path, 'rb') as f:
            tags = exifread.process_file(f, details=False)
            if not tags:
                result = "No EXIF metadata found.\n"
                stats = os.stat(file_path)
                result += f"File size: {stats.st_size} bytes\n"
                result += f"Created: {datetime.fromtimestamp(stats.st_ctime)}\n"
                result += f"Modified: {datetime.fromtimestamp(stats.st_mtime)}\n"
                result += "For deeper analysis of other file types, use ExifTool: https://exiftool.org/\n"
                return result

            result = "EXIF Metadata found:\n"
            for t in sorted(tags):
                if t not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
                    result += f"{t.ljust(30)}: {tags[t]}\n"
            return result
    except Exception as e:
        return f"Error processing file: {e}"

def google_dorking(query: str) -> str:
    """Open a Google search with the provided dork query."""
    if not query:
        return "Error: No dork query provided."

    search_url = f"https://www.google.com/search?q={query}"
    webbrowser.open(search_url)
    return f"Google Dorking: Opened search for '{query}' in browser.\nDirect Link: {search_url}"

def wayback_machine_lookup(url: str) -> str:
    """Retrieve historical snapshots of a URL."""
    if not url or not url.startswith(('http://','https://')):
        return "Error: Invalid URL. Must start with http:// or https://."

    if not WaybackMachineCDXServerAPI:
        return "Error: 'waybackpy' library not found."

    user_agent = "MASTER-OSINT-TOOL/1.0"
    result = f"Looking up Wayback Machine snapshots for: {url}\n"

    try:
        api = WaybackMachineCDXServerAPI(url, user_agent)
        snaps = list(api.snapshots())
        if not snaps:
            return result + "No snapshots found."

        result += f"Found {len(snaps)} snapshots (showing up to 10):\n"
        for i, snap in enumerate(snaps):
            if i >= 10:
                break
            try:
                ts = datetime.strptime(snap.timestamp, "%Y%m%d%H%M%S")
                tsf = ts.strftime("%Y-%m-%d %H:%M:%S")
            except:
                tsf = snap.timestamp
            result += f"- {snap.archive_url} (Captured: {tsf}, Status: {snap.statuscode})\n"
        return result
    except Exception as e:
        return f"Error: {e}"

def ip_geolocation_blacklist(ip: str) -> str:
    """Find location and abuse data for an IP address."""
    if not ip:
        return "Error: No IP address provided."

    try:
        import ipaddress
        ipaddress.ip_address(ip)
    except:
        return "Error: Invalid IP address."

    result = f"Analyzing IP: {ip}\n"

    # Geolocation via ipinfo.io
    if not requests:
        return result + "Error: 'requests' library not found."

    try:
        geo_resp = requests.get(f"https://ipinfo.io/{ip}/json")
        geo = geo_resp.json()
        if geo_resp.status_code != 200:
            result += "Geo lookup failed.\n"
        else:
            for label in ("ip", "hostname", "city", "region", "country", "loc", "org", "postal", "timezone"):
                result += f"{label.capitalize().ljust(14)}: {geo.get(label, 'N/A')}\n"
    except Exception as e:
        result += f"Geo lookup error: {e}\n"
        return result

    # AbuseIPDB Check
    result += "\n--- AbuseIPDB Report ---\n"
    abuseipdb_api_key = "239f40913f0c240cd1afc55c99c351070d04383bb156ffc0defed5a284b601f79d878a07c2d49e2c"
    if abuseipdb_api_key != "YOUR_ABUSEIPDB_API_KEY":
        headers = {'Accept': 'application/json', 'Key': abuseipdb_api_key}
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json().get('data', {})
                score = data.get('abuseConfidenceScore', 0)
                reports = data.get('totalReports', 0)
                result += f"Abuse Confidence Score: {score}%\n"
                result += f"Total Reports (last 90 days): {reports}\n"
                status = "Potentially Malicious IP" if score > 0 else "No significant abuse reports."
                result += f"Status: {status}\n"

                if score > 0 and data.get('reports'):
                    result += "Sample Reports:\n"
                    for rep in data.get('reports', [])[:3]:
                        result += f" - {rep.get('comment','N/A')} (Reported at {rep.get('reportedAt','N/A')})\n"
                    if len(data.get('reports', [])) > 3:
                        result += f"   ... and {len(data['reports'])-3} more\n"
            else:
                result += f"API error HTTP {resp.status_code}\n"
        except Exception as e:
            result += f"Error fetching AbuseIPDB: {e}\n"
    else:
        result += "AbuseIPDB check skipped (API key not configured).\n"

    return result

def website_metadata_and_entity_scraper(url: str) -> str:
    """Extract title, meta tags, emails, persons, locations from a single URL."""
    if not SPACY_ENABLED:
        return "Error: Spacy model 'en_core_web_sm' not loaded."

    if not requests or not BeautifulSoup:
        return "Error: 'requests' or 'beautifulsoup4' library not found."

    headers = {"User-Agent": "MASTER-OSINT-TOOL/1.0"}

    def extract_emails(text):
        return sorted(set(re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text, re.I)))

    def extract_entities(text, labels):
        if not SPACY_ENABLED:
            return []
        doc = SPACY_NLP(text)
        return sorted(set(ent.text for ent in doc.ents if ent.label_ in labels))

    result = f"Scraping URL: {url}\n"

    try:
        r = requests.get(url, headers=headers, timeout=15)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, 'html.parser')

        title = soup.title.string.strip() if soup.title else "N/A"
        meta_tags = {}
        for m in soup.find_all("meta"):
            if "content" in m.attrs and ("name" in m.attrs or "property" in m.attrs):
                key = m.attrs.get("name") or m.attrs.get("property")
                meta_tags[key.lower()] = m.attrs["content"]

        emails = extract_emails(r.text)
        visible = soup.get_text(separator=" ", strip=True)
        names = extract_entities(visible, ["PERSON"])
        locations = extract_entities(visible, ["GPE", "LOC"])

        result += f"Title: {title}\n"
        result += f"Meta tags found: {len(meta_tags)}\n"
        for key, value in meta_tags.items():
            result += f"  {key}: {value}\n"
        result += f"Emails found: {len(emails)}\n"
        for email in emails:
            result += f"  {email}\n"
        result += f"Names found: {len(names)}\n"
        for name in names:
            result += f"  {name}\n"
        result += f"Locations found: {len(locations)}\n"
        for loc in locations:
            result += f"  {loc}\n"

        return result

    except Exception as e:
        return f"Error scraping {url}: {e}"

def phone_number_lookup(phone: str) -> str:
    """Validate a phone number and return its details."""
    if not PHONENUMBERS_ENABLED:
        return "Error: 'phonenumbers' module missing."

    if not phone:
        return "Error: No phone number provided."

    try:
        parsed = phonenumbers.parse(phone, None)
        valid = phonenumbers.is_valid_number(parsed)
        possible = phonenumbers.is_possible_number(parsed)

        if not possible:
            return "Error: Number is not possible."

        result = "Phone Number Details:\n"
        result += f"Valid: {'Yes' if valid else 'No'}\n"
        result += f"International: {phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}\n"
        result += f"National: {phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)}\n"
        result += f"Country/Location: {geocoder.description_for_number(parsed, 'en')}\n"
        result += f"Carrier: {carrier.name_for_number(parsed, 'en')}\n"

        type_num = number_type(parsed)
        types_map = {
            0: "Unknown", 1: "Fixed Line", 2: "Mobile", 3: "Fixed Line or Mobile", 4: "Toll Free",
            5: "Premium Rate", 6: "Shared Cost", 7: "VoIP", 8: "Personal Number", 9: "Pager", 10: "UAN"
        }
        result += f"Type: {types_map.get(type_num, 'Unknown')}\n"

        result += "\nSuggested Google Dorks:\n"
        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        nat = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        e164_clean = re.sub(r'\D', '', e164)
        nat_clean = re.sub(r'\D', '', nat)

        result += f'  "{e164}" OR "{nat}"\n'
        result += f'  "{e164_clean}" OR "{nat_clean}"\n'

        return result

    except Exception as e:
        return f"Error parsing: {e}"

def reverse_image_search() -> str:
    """Return URLs for reverse image search engines."""
    engines = {
        "Google Images": "https://images.google.com/",
        "TinEye": "https://tineye.com/",
        "Yandex": "https://yandex.com/images/",
        "Bing Visual Search": "https://www.bing.com/images/discover",
        "Baidu Image Search": "https://image.baidu.com/",
        "SauceNAO": "https://saucenao.com/",
        "ImgOps": "https://imgops.com/"
    }

    result = "Reverse Image Search Engines:\n"
    for name, url in engines.items():
        result += f"{name.ljust(18)}: {url}\n"

    return result

def geospatial_intelligence(location: str) -> str:
    """Generate Google Maps and OpenStreetMap links for coordinates or a location."""
    if not location:
        return "Error: No location data provided."

    lat, lon = None, None
    coords_ok = False
    try:
        parts = [p.strip() for p in location.split(',')]
        if len(parts) == 2:
            lat = float(parts[0])
            lon = float(parts[1])
            if -90 <= lat <= 90 and -180 <= lon <= 180:
                coords_ok = True
    except Exception:
        coords_ok = False

    if coords_ok:
        google_sat_url = f"https://www.google.com/maps/@{lat},{lon},15z/data=!5m1!1e4"
        osm_url = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=15/{lat}/{lon}"
        result = f"Valid coordinates: {lat}, {lon}\n"
    else:
        query = location.replace(' ', '+')
        google_sat_url = f"https://www.google.com/maps/search/?api=1&query={query}&layer=c"
        osm_url = f"https://www.openstreetmap.org/search?query={query}"
        result = f"Treating as location query: '{location}'\n"

    result += f"Google Satellite Map: {google_sat_url}\n"
    result += f"OpenStreetMap: {osm_url}\n"

    webbrowser.open(google_sat_url)
    webbrowser.open(osm_url)

    return result + "Maps opened in browser."

# --- Main Function (for standalone use) ---
# This is kept for backward compatibility if you run the script directly.
# The MCP server will NOT use this.

def main():
    """Standalone interactive mode (not used by MCP server)."""
    print("This is the standalone version. For MCP server, use mcp_server.py")
    # ... (You can keep your original interactive menu here if needed) ...
    pass

if __name__ == "__main__":
    main()
