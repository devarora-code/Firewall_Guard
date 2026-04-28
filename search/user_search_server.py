from flask import Flask, jsonify, request, render_template
from ddgs import DDGS
from bs4 import BeautifulSoup
import requests, re, time
from urllib.parse import urlparse, urljoin

app = Flask(__name__)
MAX_RESULTS = 25

@app.route("/")
def home():
    return "Firewall Search Engine Running (No Admin Panel)"

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "search_engine"
    })

@app.route("/search")
def search():
    query = request.args.get("q", "").strip()

    if not query:
        return jsonify({"query": "", "results": []})

    results = []

    try:
        with DDGS() as ddgs:
            for r in ddgs.text(query, max_results=MAX_RESULTS):
                url = r.get("href") or r.get("url")
                if url:
                    results.append({
                        "url": url,
                        "title": r.get("title", url)
                    })
    except Exception as e:
        return jsonify({"error": str(e)})

    return jsonify({
        "query": query,
        "count": len(results),
        "results": results
    })

@app.route("/fetch")
def fetch():
    url = request.args.get("url")

    if not url:
        return jsonify({"error": "No URL provided"})

    try:
        res = requests.get(url, timeout=5)
        html = res.text

        soup = BeautifulSoup(html, "html.parser")

        for tag in soup(["script", "style"]):
            tag.decompose()

        text = "\n".join(line.strip() for line in soup.get_text().splitlines() if line.strip())

        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("/"):
                href = urljoin(url, href)

            if href.startswith("http"):
                links.append({
                    "url": href,
                    "text": a.get_text(strip=True) or href
                })

        return jsonify({
            "url": url,
            "content": text[:5000],
            "links": links[:20]
        })

    except Exception as e:
        return jsonify({
            "error": str(e),
            "url": url
        })

if __name__ == "__main__":
    print("Starting Search Engine ONLY...")
    print("http://localhost:4000")
    app.run(host="localhost", port=4000, debug=True)