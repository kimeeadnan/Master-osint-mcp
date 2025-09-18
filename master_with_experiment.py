#!/usr/bin/env python3
from typing import Any
import asyncio
import master_osint as mo
from mcp.server.fastmcp import FastMCP
import time
import psutil
import os
from datetime import datetime

# Initialize experiment tracking
class AutoExperimentTracker:
    def __init__(self):
        self.process = psutil.Process(os.getpid())
        self.investigations = []
        self.start_time = time.time()
        self.context_history = []
        self.experiment_active = False
    
    def start_experiment(self):
        """Start tracking an experiment"""
        self.experiment_active = True
        self.investigations = []
        self.context_history = []
        self.start_time = time.time()
        print("🔬 EXPERIMENT TRACKING STARTED")
    
    def record_investigation(self, function_name: str, target: str, result: str):
        """Record an investigation for experiment tracking"""
        if not self.experiment_active:
            return
        
        current_time = time.time()
        memory_info = self.process.memory_info()
        
        investigation = {
            'function': function_name,
            'target': target,
            'result_length': len(result),
            'timestamp': current_time - self.start_time,
            'memory_mb': memory_info.rss / 1024 / 1024,
            'context_tokens': len(result.split())
        }
        
        self.investigations.append(investigation)
        self.context_history.append(result)
        
        print(f"📊 RECORDED: {function_name}({target}) - {len(result):,} chars, {memory_info.rss / 1024 / 1024:.2f} MB")
    
    def get_experiment_summary(self) -> str:
        """Get current experiment summary"""
        if not self.investigations:
            return "No investigations recorded yet."
        
        total_context = sum(len(ctx) for ctx in self.context_history)
        initial_context = len(self.context_history[0]) if self.context_history else 0
        growth_rate = (total_context / initial_context - 1) * 100 if initial_context > 0 else 0
        
        summary = f"""
🔬 CONTEXT EXPLOSION EXPERIMENT SUMMARY
========================================
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Investigations: {len(self.investigations)}
Total Context: {total_context:,} characters
Growth Rate: {growth_rate:.1f}%
Memory Usage: {self.investigations[-1]['memory_mb']:.2f} MB
Execution Time: {self.investigations[-1]['timestamp']:.2f} seconds

INVESTIGATION BREAKDOWN:
"""
        
        for i, inv in enumerate(self.investigations, 1):
            cumulative_context = sum(len(ctx) for ctx in self.context_history[:i])
            summary += f"Step {i}: {inv['function']}({inv['target']}) - {cumulative_context:,} chars, {inv['memory_mb']:.2f} MB\n"
        
        if growth_rate > 200:
            summary += "\n🚨 CONTEXT EXPLOSION DETECTED!"
        else:
            summary += "\n✅ Context growth within normal limits"
        
        return summary

# Initialize tracker
experiment_tracker = AutoExperimentTracker()

# Initialize MCP server
mcp = FastMCP("master-osint")

# Helper function
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

# MCP Tools with automatic experiment tracking
@mcp.tool()
async def social_media_investigation(username: str) -> str:
    """Investigate social media profiles for a given username."""
    if not username:
        return "Error: Missing required parameter: username"
    
    # Start experiment if not already started
    if not experiment_tracker.experiment_active:
        experiment_tracker.start_experiment()
    
    result = await safe_call(getattr(mo, "social_media_investigation", lambda u: "Function not available."), username)
    
    # Record for experiment
    experiment_tracker.record_investigation("social_media_investigation", username, result)
    
    return result

@mcp.tool()
async def domain_investigation(domain: str) -> str:
    """Investigate domain information including WHOIS, DNS, and subdomains."""
    if not domain:
        return "Error: Missing required parameter: domain"
    
    result = await safe_call(getattr(mo, "domain_investigation", lambda d: "Function not available."), domain)
    
    # Record for experiment
    experiment_tracker.record_investigation("domain_investigation", domain, result)
    
    return result

@mcp.tool()
async def email_analysis(email: str) -> str:
    """Analyze email for breaches and public information."""
    if not email:
        return "Error: Missing required parameter: email"
    
    result = await safe_call(getattr(mo, "email_analysis", lambda e: "Function not available."), email)
    
    # Record for experiment
    experiment_tracker.record_investigation("email_analysis", email, result)
    
    return result

@mcp.tool()
async def email_lookup_and_verification(email: str) -> str:
    """Lookup and verify email using various services."""
    if not email:
        return "Error: Missing required parameter: email"
    
    result = await safe_call(getattr(mo, "email_lookup_and_verification", lambda e: "Function not available."), email)
    
    # Record for experiment
    experiment_tracker.record_investigation("email_lookup_and_verification", email, result)
    
    return result

@mcp.tool()
async def ip_geolocation_blacklist(ip: str) -> str:
    """Get IP geolocation and check blacklist status."""
    if not ip:
        return "Error: Missing required parameter: ip"
    
    result = await safe_call(getattr(mo, "ip_geolocation_blacklist", lambda i: "Function not available."), ip)
    
    # Record for experiment
    experiment_tracker.record_investigation("ip_geolocation_blacklist", ip, result)
    
    return result

@mcp.tool()
async def phone_number_lookup(phone: str) -> str:
    """Lookup phone number information and validation."""
    if not phone:
        return "Error: Missing required parameter: phone"
    
    result = await safe_call(getattr(mo, "phone_number_lookup", lambda p: "Function not available."), phone)
    
    # Record for experiment
    experiment_tracker.record_investigation("phone_number_lookup", phone, result)
    
    return result

@mcp.tool()
async def google_dorking(query: str) -> str:
    """Perform Google dorking with the provided search query."""
    if not query:
        return "Error: Missing required parameter: query"
    
    result = await safe_call(getattr(mo, "google_dorking", lambda q: "Function not available."), query)
    
    # Record for experiment
    experiment_tracker.record_investigation("google_dorking", query[:50] + "..." if len(query) > 50 else query, result)
    
    return result

@mcp.tool()
async def wayback_machine_lookup(url: str) -> str:
    """Lookup historical snapshots of a URL using Wayback Machine."""
    if not url:
        return "Error: Missing required parameter: url"
    
    result = await safe_call(getattr(mo, "wayback_machine_lookup", lambda u: "Function not available."), url)
    
    # Record for experiment
    experiment_tracker.record_investigation("wayback_machine_lookup", url, result)
    
    return result

@mcp.tool()
async def metadata_extraction(file_path: str) -> str:
    """Extract metadata from files and images."""
    if not file_path:
        return "Error: Missing required parameter: file_path"
    
    result = await safe_call(getattr(mo, "metadata_extraction", lambda f: "Function not available."), file_path)
    
    # Record for experiment
    experiment_tracker.record_investigation("metadata_extraction", file_path, result)
    
    return result

@mcp.tool()
async def website_metadata_and_entity_scraper(url: str) -> str:
    """Scrape website metadata and extract named entities using NLP."""
    if not url:
        return "Error: Missing required parameter: url"
    
    result = await safe_call(getattr(mo, "website_metadata_and_entity_scraper", lambda u: "Function not available."), url)
    
    # Record for experiment
    experiment_tracker.record_investigation("website_metadata_and_entity_scraper", url, result)
    
    return result

@mcp.tool()
async def image_geolocation(image_path: str) -> str:
    """Extract GPS coordinates and geolocation from images."""
    if not image_path:
        return "Error: Missing required parameter: image_path"
    
    result = await safe_call(getattr(mo, "image_geolocation", lambda i: "Function not available."), image_path)
    
    # Record for experiment
    experiment_tracker.record_investigation("image_geolocation", image_path, result)
    
    return result

@mcp.tool()
async def reverse_image_search() -> str:
    """Perform reverse image search using multiple engines."""
    result = await safe_call(getattr(mo, "reverse_image_search", lambda: "Function not available."))
    
    # Record for experiment
    experiment_tracker.record_investigation("reverse_image_search", "no_target", result)
    
    return result

@mcp.tool()
async def geospatial_intelligence(location: str) -> str:
    """Get geospatial intelligence for coordinates or address."""
    if not location:
        return "Error: Missing required parameter: location"
    
    result = await safe_call(getattr(mo, "geospatial_intelligence", lambda loc: "Function not available."), location)
    
    # Record for experiment
    experiment_tracker.record_investigation("geospatial_intelligence", location, result)
    
    return result

# NEW: Experiment summary tool
@mcp.tool()
async def get_experiment_summary() -> str:
    """Get current context explosion experiment summary."""
    return experiment_tracker.get_experiment_summary()

# NEW: Reset experiment tool
@mcp.tool()
async def reset_experiment() -> str:
    """Reset the context explosion experiment tracking."""
    experiment_tracker.investigations = []
    experiment_tracker.context_history = []
    experiment_tracker.experiment_active = False
    return "Experiment tracking reset successfully."

if __name__ == "__main__":
    import asyncio
    mcp.run(transport='stdio')
