# Master OSINT MCP Setup Guide

This guide will help you set up the Master OSINT MCP server after cloning the repository.

## Prerequisites

- Python 3.13 or higher
- pip (Python package installer)

## Installation Steps

### 1. Clone the Repository
```bash
git clone https://github.com/kimeeadnan/Master-osint-mcp.git
cd Master-osint-mcp
```

### 2. Install Dependencies

#### Option A: Using pip (Recommended)
```bash
pip install -r requirements.txt
```

#### Option B: Using uv (if you have uv installed)
```bash
uv sync
```

#### Option C: Using pip with pyproject.toml
```bash
pip install -e .
```

### 3. Install spaCy Language Model
The script requires the English language model for NLP features:
```bash
python -m spacy download en_core_web_sm
```

### 4. Test the Installation
```bash
python3 master.py
```
If the script runs without errors (silent output is expected), the installation is successful.

## MCP Configuration

Add this to your MCP client configuration (e.g., `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "master-osint": {
      "command": "python3",
      "args": [
        "master.py"
      ],
      "cwd": "/path/to/Master-osint-mcp"
    }
  }
}
```

Or if using uv:
```json
{
  "mcpServers": {
    "master-osint": {
      "command": "uv",
      "args": [
        "run",
        "master.py"
      ],
      "cwd": "/path/to/Master-osint-mcp"
    }
  }
}
```

## Troubleshooting

### Common Issues:

1. **ModuleNotFoundError**: Install missing dependencies with `pip install <module_name>`
2. **spaCy model not found**: Run `python -m spacy download en_core_web_sm`
3. **Permission errors**: Use `pip install --user` or create a virtual environment
4. **Python version**: Ensure you're using Python 3.13+

### Virtual Environment (Optional but Recommended)
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

## Available OSINT Tools

- Social Media Investigation
- Domain Investigation (WHOIS, DNS, Subdomains)
- Email Analysis and Verification
- IP Geolocation and Blacklist Checking
- Phone Number Lookup
- Google Dorking
- Wayback Machine Lookup
- Metadata Extraction
- Website Scraping and Entity Extraction
- Image Geolocation
- Reverse Image Search
- Geospatial Intelligence

## API Keys (Optional)

Some features work better with API keys:
- Hunter.io API key for email verification
- HaveIBeenPwned API key for breach checking
- AbuseIPDB API key for IP reputation checking

Edit the `master_osint.py` file to add your API keys.
