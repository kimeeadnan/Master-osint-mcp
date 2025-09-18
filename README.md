# Master OSINT MCP

**Master OSINT MCP** is a modular framework for performing simple Open-Source Intelligence (OSINT) operations. This repository contains scripts to automate OSINT investigations.

---

## Features
- Username investigation 🌐  
- Phone number investigation 🔍  
- Data enrichment and analysis 📊    

---

## Installation
Clone the repository:

```bash
git clone https://github.com/kimeeadnan/Master-osint-mcp.git
cd Master-osint-mcp
```
```bash
pip install -r requirements.txt
```

## Usage
Run the main module
```bash
python master.py
```

## Setup configuration
Open your client such as Claude desktop/Cursor
```bash
{
  "mcpServers": {
    "master-osint": {
      "command": "uv",
      "args": [
        "--directory",
        "/YOUR_DIRECTORY/",
        "run",
        "master_with_experiment.py",
        "master.py"
      ]
    }
  }
}
```


