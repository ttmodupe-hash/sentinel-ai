import os
import json
import re
import hashlib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
import requests

CACHE_FILE = "search_cache.json"
CACHE_TTL_HOURS = 24
MAX_WORKERS = 5

HIGH_QUALITY_DOMAINS = {
    "gov", "edu", "ac.uk", "ac.jp", "europa.eu",
    "who.int", "un.org", "worldbank.org",
    "reuters.com", "bloomberg.com", "ft.com",
    "nature.com", "science.org", "ieee.org",
    "arxiv.org", "github.com", "stackoverflow.com"
}

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_cache(cache):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)

def get_cache_key(query):
    return hashlib.md5(query.lower().strip().encode()).hexdigest()

def is_cache_valid(entry):
    if not entry or "timestamp" not in entry:
        return False
    cached_time = datetime.fromisoformat(entry["timestamp"])
    return datetime.now() - cached_time < timedelta(hours=CACHE_TTL_HOURS)

def score_source(result):
    score = 100 - (result.get("position", 10) * 5)
    link = result.get("link", "")
    for domain in HIGH_QUALITY_DOMAINS:
        if domain in link:
            score += 30
            break
    if "wikipedia" in link:
        score += 10
    if any(bad in link for bad in ["forum", "reddit", "quora", "yahoo.answers"]):
        score -= 20
    return max(0, score)

def deduplicate_results(results):
    seen_urls = set()
    seen_snippets = set()
    unique = []
    for r in results:
        url = r.get("link", "")
        snippet = r.get("snippet", "")[:100]
        if url in seen_urls:
            continue
        is_duplicate = False
        for seen in seen_snippets:
            if snippet and seen and (snippet in seen or seen in snippet):
                is_duplicate = True
                break
        if not is_duplicate:
            seen_urls.add(url)
            seen_snippets.add(snippet)
            unique.append(r)
    return unique

def fetch_page(url, timeout=10):
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        res = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        if res.status_code == 200:
            text = re.sub(r"<script[^>]*>.*?</script>", " ", res.text, flags=re.DOTALL)
            text = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.DOTALL)
            text = re.sub(r"<[^>]+>", " ", text)
            text = re.sub(r"\s+", " ", text).strip()
            return text[:5000] + "..." if len(text) > 5000 else text
        return f"FETCH_FAILED: HTTP {res.status_code}"
    except Exception as e:
        return f"FETCH_ERROR: {type(e).__name__}: {str(e)}"

def deep_search(query, api_key, max_results=15, read_pages=True):
    cache = load_cache()
    cache_key = get_cache_key(query)
    
    if cache_key in cache and is_cache_valid(cache[cache_key]):
        return cache[cache_key]["data"]
    
    all_results = []
    
    # Primary: Serper
    try:
        url = "https://google.serper.dev/search"
        headers = {"X-API-KEY": api_key, "Content-Type": "application/json"}
        payload = {"q": query, "num": max_results}
        res = requests.post(url, headers=headers, json=payload, timeout=15)
        if res.status_code == 200:
            data = res.json()
            organic = data.get("organic", [])
            for item in organic:
                all_results.append({
                    "title": item.get("title", ""),
                    "link": item.get("link", ""),
                    "snippet": item.get("snippet", ""),
                    "source": "serper",
                    "position": item.get("position", 0)
                })
    except Exception as e:
        print(f"Serper error: {e}")
    
    # Fallback: DuckDuckGo
    if len(all_results) < 5:
        try:
            ddg_url = f"https://html.duckduckgo.com/html/?q={requests.utils.quote(query)}"
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
            res = requests.get(ddg_url, headers=headers, timeout=15)
            if res.status_code == 200:
                links = re.findall(r'<a rel="nofollow" class="result__a" href="(https?://[^"]+)">([^<]+)</a>', res.text)
                snippets = re.findall(r'<a class="result__snippet"[^>]*>([^<]+)</a>', res.text)
                for i, (link, title) in enumerate(links[:max_results]):
                    snippet = snippets[i] if i < len(snippets) else ""
                    all_results.append({
                        "title": title,
                        "link": link,
                        "snippet": snippet,
                        "source": "duckduckgo",
                        "position": i + 1
                    })
        except Exception as e:
            print(f"DuckDuckGo error: {e}")
    
    all_results = deduplicate_results(all_results)
    for r in all_results:
        r["quality_score"] = score_source(r)
    all_results.sort(key=lambda x: x["quality_score"], reverse=True)
    top_results = all_results[:max_results]
    
    if read_pages:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_result = {
                executor.submit(fetch_page, r["link"]): r 
                for r in top_results
            }
            for future in as_completed(future_to_result):
                result = future_to_result[future]
                try:
                    content = future.result()
                    result["full_content"] = content
                except Exception as e:
                    result["full_content"] = f"ERROR: {e}"
    
    sources = list(set([re.findall(r"https?://([^/]+)", r["link"])[0] 
                        for r in top_results if r.get("link")]))
    
    summary_parts = []
    for r in top_results[:5]:
        snippet = r.get("snippet", "")
        if snippet:
            summary_parts.append(f"• {snippet[:200]}")
    
    output = {
        "query": query,
        "timestamp": datetime.now().isoformat(),
        "results": top_results,
        "sources": sources,
        "summary": "\n".join(summary_parts) if summary_parts else "No summary available.",
        "from_cache": False,
        "engines_used": ["serper"] + (["duckduckgo"] if len(all_results) < 5 else [])
    }
    
    cache[cache_key] = {
        "timestamp": datetime.now().isoformat(),
        "data": output
    }
    save_cache(cache)
    
    return output
