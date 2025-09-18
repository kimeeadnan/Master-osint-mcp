#!/usr/bin/env python3
from typing import Any
import asyncio
import master_osint as mo  # your refactored OSINT tools module
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("master-osint")

# Helper to safely call functions from master_osint
async def safe_call(func, *args, **kwargs) -> str:
    try:
        if asyncio.iscoroutinefunction(func):
            result = await func(*args, **kwargs)
        else:
            result = func(*args, **kwargs)
        return str(result) if result is not None else "No output returned."
    except AttributeError:
        return f"Function {getattr(func, '__name__', 'unknown')} not found in master_osint."
    except Exception as e:
        return f"Error: {e}"

# All functions now use proper parameter signatures, no need for normalize_input

# --- MCP TOOLS ---
@mcp.tool()
async def social_media_investigation(username: str) -> str:
    """Investigate social media profiles for a given username."""
    if not username:
        return "Error: Missing required parameter: username"
    return await safe_call(getattr(mo, "social_media_investigation", lambda u: "Function not available."), username)

@mcp.tool()
async def domain_investigation(domain: str) -> str:
    """Investigate domain information including WHOIS, DNS, and subdomains."""
    if not domain:
        return "Error: Missing required parameter: domain"
    return await safe_call(getattr(mo, "domain_investigation", lambda d: "Function not available."), domain)

@mcp.tool()
async def email_analysis(email: str) -> str:
    """Analyze email for breaches and public information."""
    if not email:
        return "Error: Missing required parameter: email"
    return await safe_call(getattr(mo, "email_analysis", lambda e: "Function not available."), email)

@mcp.tool()
async def email_lookup_and_verification(email: str) -> str:
    """Lookup and verify email using various services."""
    if not email:
        return "Error: Missing required parameter: email"
    return await safe_call(getattr(mo, "email_lookup_and_verification", lambda e: "Function not available."), email)

@mcp.tool()
async def ip_geolocation_blacklist(ip: str) -> str:
    """Get IP geolocation and check blacklist status."""
    if not ip:
        return "Error: Missing required parameter: ip"
    return await safe_call(getattr(mo, "ip_geolocation_blacklist", lambda i: "Function not available."), ip)

@mcp.tool()
async def phone_number_lookup(phone: str) -> str:
    """Lookup phone number information and validation."""
    if not phone:
        return "Error: Missing required parameter: phone"
    return await safe_call(getattr(mo, "phone_number_lookup", lambda p: "Function not available."), phone)

@mcp.tool()
async def google_dorking(query: str) -> str:
    """Perform Google dorking with the provided search query."""
    if not query:
        return "Error: Missing required parameter: query"
    return await safe_call(getattr(mo, "google_dorking", lambda q: "Function not available."), query)

@mcp.tool()
async def wayback_machine_lookup(url: str) -> str:
    """Lookup historical snapshots of a URL using Wayback Machine."""
    if not url:
        return "Error: Missing required parameter: url"
    return await safe_call(getattr(mo, "wayback_machine_lookup", lambda u: "Function not available."), url)

@mcp.tool()
async def metadata_extraction(file_path: str) -> str:
    """Extract metadata from files and images."""
    if not file_path:
        return "Error: Missing required parameter: file_path"
    return await safe_call(getattr(mo, "metadata_extraction", lambda f: "Function not available."), file_path)

@mcp.tool()
async def website_metadata_and_entity_scraper(url: str) -> str:
    """Scrape website metadata and extract named entities using NLP."""
    if not url:
        return "Error: Missing required parameter: url"
    return await safe_call(getattr(mo, "website_metadata_and_entity_scraper", lambda u: "Function not available."), url)

@mcp.tool()
async def image_geolocation(image_path: str) -> str:
    """Extract GPS coordinates and geolocation from images."""
    if not image_path:
        return "Error: Missing required parameter: image_path"
    return await safe_call(getattr(mo, "image_geolocation", lambda i: "Function not available."), image_path)

@mcp.tool()
async def reverse_image_search() -> str:
    """Perform reverse image search using multiple engines."""
    return await safe_call(getattr(mo, "reverse_image_search", lambda: "Function not available."))

@mcp.tool()
async def geospatial_intelligence(location: str) -> str:
    """Get geospatial intelligence for coordinates or address."""
    if not location:
        return "Error: Missing required parameter: location"
    return await safe_call(getattr(mo, "geospatial_intelligence", lambda loc: "Function not available."), location)

if __name__ == "__main__":
    import asyncio
    # Run the MCP server over stdio
    mcp.run(transport='stdio')
