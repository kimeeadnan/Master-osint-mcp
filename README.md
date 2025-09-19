# Master OSINT MCP

**Master OSINT MCP** is a modular framework for performing simple Open-Source Intelligence (OSINT) operations. This repository contains scripts to automate OSINT investigations.

## Features

* Username investigation 🌐
* Phone number investigation ��
* Data enrichment and analysis 📊
* Domain investigation and subdomain enumeration
* Email analysis and verification
* IP geolocation and blacklist checking
* Metadata extraction from files and images
* Website scraping and entity extraction
* Reverse image search
* Geospatial intelligence

## Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/kimeeadnan/Master-osint-mcp.git
   cd Master-osint-mcp
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   python -m spacy download en_core_web_sm
   ```

3. **Test the installation:**
   ```bash
   python3 master.py
   ```

## Setup

For detailed setup instructions, see [SETUP.md](SETUP.md).

## MCP Configuration

Add this to your MCP client configuration:

```json
{
  "mcpServers": {
    "master-osint": {
      "command": "python3",
      "args": ["master.py"],
      "cwd": "/path/to/Master-osint-mcp"
    }
  }
}
```

## Available Tools

- `social_media_investigation` - Generate social media profile URLs
- `domain_investigation` - WHOIS, DNS, and subdomain analysis
- `email_analysis` - Email breach checking
- `email_lookup_and_verification` - Email verification via Hunter.io
- `ip_geolocation_blacklist` - IP geolocation and abuse checking
- `phone_number_lookup` - Phone number validation and details
- `google_dorking` - Google search queries
- `wayback_machine_lookup` - Historical website snapshots
- `metadata_extraction` - File metadata extraction
- `website_metadata_and_entity_scraper` - Website content analysis
- `image_geolocation` - GPS data from images
- `reverse_image_search` - Reverse image search engines
- `geospatial_intelligence` - Location mapping

## Requirements

- Python 3.13+
- See `requirements.txt` for all dependencies

## License

This project is licensed under the MIT License - see the LICENSE file for details.
