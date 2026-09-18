import base64
import json
import os
import urllib.error
import urllib.request

GITHUB_API = "https://api.github.com"
USER = os.environ.get("GITHUB_USER", "Renato1909")
TOKEN = os.environ.get("GITHUB_TOKEN", "")
OUTPUT = os.environ.get("OUTPUT_PATH", "profile/languages.svg")

LANG_COLORS = {
    "Python": "#3572A5",
    "PHP": "#4F5D95",
    "HTML": "#e34c26",
    "CSS": "#563d7c",
    "JavaScript": "#f1e05a",
    "TypeScript": "#3178c6",
    "Java": "#b07219",
    "Kotlin": "#A97BFF",
    "C": "#555555",
    "C++": "#f34b7d",
    "C#": "#178600",
    "Go": "#00ADD8",
    "Shell": "#89e051",
    "Ruby": "#701516",
    "Rust": "#dea584",
    "Dockerfile": "#384d54",
    "PowerShell": "#012456",
    "Batchfile": "#C1F12E",
    "SQL": "#e38c00",
    "Lua": "#000080",
    "Dart": "#00B4AB",
    "Swift": "#F05138",
}
FALLBACK = ["#8957e5", "#1f6feb", "#238636", "#bf3989", "#d29922", "#3fb950", "#a371f7", "#db61a2"]


def api(path):
    req = urllib.request.Request(f"{GITHUB_API}{path}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "languages-svg-generator")
    if TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


def get_repos():
    repos, page = [], 1
    while True:
        batch = api(f"/users/{USER}/repos?per_page=100&page={page}")
        if not batch:
            break
        repos.extend(batch)
        page += 1
    return [r for r in repos if not r["fork"]]


def esc(text):
    return (
        text.replace("&", "&" + "amp;")
        .replace("<", "&" + "lt;")
        .replace(">", "&" + "gt;")
    )


def main():
    repos = get_repos()
    stats = {}
    for repo in repos:
        try:
            langs = api(f"/repos/{repo['full_name']}/languages")
        except Exception:
            continue
        for lang, size in langs.items():
            entry = stats.setdefault(lang, {"bytes": 0, "repos": set()})
            entry["bytes"] += size
            entry["repos"].add(repo["name"])

    total = sum(e["bytes"] for e in stats.values()) or 1
    ordered = sorted(stats.items(), key=lambda kv: -kv[1]["bytes"])

    row_h = 46
    header_h = 64
    footer_h = 16
    width = 495
    height = header_h + row_h * len(ordered) + footer_h

    parts = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img">'
    )
    parts.append(f"<title>Top Languages by Repo — {esc(USER)}</title>")
    parts.append(
        f'<rect x="0.5" y="0.5" width="{width - 1}" height="{height - 1}" rx="13" '
        f'fill="#0D1117" stroke="#E1B447" stroke-opacity="0.4"/>'
    )
    parts.append(
        '<text x="24" y="38" fill="#C9D1D9" font-family="Segoe UI, Ubuntu, Sans-Serif" '
        'font-size="17" font-weight="600">Top Languages by Repo</text>'
    )
    parts.append(
        f'<text x="{width - 24}" y="38" text-anchor="end" fill="#8B949E" '
        f'font-family="Segoe UI, Ubuntu, Sans-Serif" font-size="11">{len(repos)} repositórios</text>'
    )

    max_bytes = ordered[0][1]["bytes"] if ordered else 1
    y = header_h + 8
    for i, (lang, entry) in enumerate(ordered):
        pct = entry["bytes"] / total * 100
        bar_w = max(6.0, (entry["bytes"] / max_bytes) * (width - 48))
        color = LANG_COLORS.get(lang, FALLBACK[i % len(FALLBACK)])
        n_repos = len(entry["repos"])
        repos_label = f'{n_repos} repo' if n_repos == 1 else f'{n_repos} repos'
        parts.append(
            f'<text x="24" y="{y}" fill="#C9D1D9" font-family="Segoe UI, Ubuntu, Sans-Serif" '
            f'font-size="12.5" font-weight="600">{esc(lang)}</text>'
        )
        parts.append(
            f'<text x="{width - 24}" y="{y}" text-anchor="end" fill="#8B949E" '
            f'font-family="Segoe UI, Ubuntu, Sans-Serif" font-size="11">'
            f'{repos_label} · {pct:.1f}%</text>'
        )
        parts.append(f'<rect x="24" y="{y + 7}" width="{bar_w:.1f}" height="9" rx="4.5" fill="{color}"/>')
        y += row_h
    parts.append("</svg>")

    svg = "\n".join(parts) + "\n"
    os.makedirs(os.path.dirname(OUTPUT) or ".", exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write(svg)
    print(f"OK: {len(ordered)} linguagens em {len(repos)} repos -> {OUTPUT}")


if __name__ == "__main__":
    main()
