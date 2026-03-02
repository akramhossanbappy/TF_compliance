#!/usr/bin/env python3
"""
generate_report.py
Reads merged_*.json and produces a self-contained HTML dashboard.
"""
import argparse
import json
from pathlib import Path
from datetime import datetime


SEVERITY_COLOR = {
    "CRITICAL": "#FF2D55",
    "HIGH":     "#FF6B35",
    "MEDIUM":   "#FFB800",
    "LOW":      "#00C896",
    "INFO":     "#6B7280",
}

SEVERITY_BG = {
    "CRITICAL": "#1a0008",
    "HIGH":     "#1a0800",
    "MEDIUM":   "#1a1200",
    "LOW":      "#001a12",
    "INFO":     "#0d0f14",
}

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Terraform Security Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

  :root {{
    --bg:       #0a0b0e;
    --surface:  #111318;
    --border:   #1e2028;
    --text:     #e2e4ea;
    --muted:    #6b7280;
    --accent:   #4F8EF7;
    --crit:     {crit_color};
    --high:     {high_color};
    --med:      {med_color};
    --low:      {low_color};
  }}

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: 'IBM Plex Sans', sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    font-size: 14px;
    line-height: 1.6;
  }}

  /* ── Header ── */
  .header {{
    background: linear-gradient(135deg, #0d0f14 0%, #111520 100%);
    border-bottom: 1px solid var(--border);
    padding: 2rem 2.5rem;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    position: sticky;
    top: 0;
    z-index: 100;
    backdrop-filter: blur(10px);
  }}

  .header-left h1 {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 1.4rem;
    font-weight: 600;
    letter-spacing: -0.5px;
    color: #fff;
  }}

  .header-left h1 span {{ color: var(--accent); }}

  .header-meta {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.72rem;
    color: var(--muted);
    margin-top: 0.35rem;
  }}

  .risk-badge {{
    padding: 0.4rem 1.2rem;
    border-radius: 4px;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.8rem;
    font-weight: 600;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    border: 1px solid currentColor;
  }}

  /* ── Summary cards ── */
  .summary {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 1px;
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
    margin: 1.5rem 2.5rem;
  }}

  .stat-card {{
    background: var(--surface);
    padding: 1.4rem 1.5rem;
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
  }}

  .stat-label {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.65rem;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: var(--muted);
  }}

  .stat-value {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 2rem;
    font-weight: 600;
    line-height: 1;
  }}

  .stat-card.total   .stat-value {{ color: var(--text); }}
  .stat-card.crit    .stat-value {{ color: var(--crit); }}
  .stat-card.high    .stat-value {{ color: var(--high); }}
  .stat-card.med     .stat-value {{ color: var(--med);  }}
  .stat-card.low     .stat-value {{ color: var(--low);  }}
  .stat-card.sources .stat-value {{ color: var(--accent); font-size: 1rem; margin-top: 0.3rem; }}

  /* ── Tool bar ── */
  .toolbar {{
    display: flex;
    gap: 0.5rem;
    padding: 0 2.5rem 1rem;
    flex-wrap: wrap;
    align-items: center;
  }}

  .filter-btn {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.72rem;
    padding: 0.4rem 1rem;
    border-radius: 4px;
    border: 1px solid var(--border);
    background: var(--surface);
    color: var(--muted);
    cursor: pointer;
    transition: all 0.15s;
    letter-spacing: 0.5px;
  }}

  .filter-btn:hover, .filter-btn.active {{
    border-color: var(--accent);
    color: var(--accent);
    background: rgba(79, 142, 247, 0.08);
  }}

  .filter-btn.sev-CRITICAL.active {{ border-color: var(--crit); color: var(--crit); background: rgba(255,45,85,0.08); }}
  .filter-btn.sev-HIGH.active     {{ border-color: var(--high); color: var(--high); background: rgba(255,107,53,0.08); }}
  .filter-btn.sev-MEDIUM.active   {{ border-color: var(--med);  color: var(--med);  background: rgba(255,184,0,0.08);  }}
  .filter-btn.sev-LOW.active      {{ border-color: var(--low);  color: var(--low);  background: rgba(0,200,150,0.08);  }}

  .spacer {{ flex: 1; }}

  .search-wrap {{
    position: relative;
  }}
  .search-wrap input {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.78rem;
    padding: 0.4rem 1rem 0.4rem 2.2rem;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--surface);
    color: var(--text);
    width: 220px;
    outline: none;
    transition: border-color 0.15s;
  }}
  .search-wrap input:focus {{ border-color: var(--accent); }}
  .search-icon {{
    position: absolute;
    left: 0.7rem;
    top: 50%;
    transform: translateY(-50%);
    color: var(--muted);
    font-size: 0.8rem;
  }}

  /* ── Findings table ── */
  .findings-wrap {{
    padding: 0 2.5rem 2.5rem;
  }}

  .count-label {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.72rem;
    color: var(--muted);
    margin-bottom: 0.8rem;
    letter-spacing: 0.5px;
  }}

  .findings-table {{
    width: 100%;
    border-collapse: collapse;
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }}

  .findings-table thead th {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.65rem;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: var(--muted);
    background: var(--surface);
    padding: 0.8rem 1rem;
    text-align: left;
    border-bottom: 1px solid var(--border);
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
  }}

  .findings-table thead th:hover {{ color: var(--text); }}
  .findings-table thead th .sort-arrow {{ margin-left: 4px; opacity: 0.4; }}
  .findings-table thead th.sorted .sort-arrow {{ opacity: 1; color: var(--accent); }}

  .findings-table tbody tr {{
    border-bottom: 1px solid var(--border);
    transition: background 0.1s;
  }}

  .findings-table tbody tr:last-child {{ border-bottom: none; }}
  .findings-table tbody tr:hover {{ background: rgba(255,255,255,0.02); }}
  .findings-table tbody tr.expanded {{ background: rgba(255,255,255,0.03); }}

  .findings-table td {{
    padding: 0.9rem 1rem;
    vertical-align: top;
    font-size: 0.82rem;
  }}

  .sev-pill {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.6rem;
    font-weight: 600;
    letter-spacing: 1.5px;
    padding: 0.2rem 0.55rem;
    border-radius: 3px;
    white-space: nowrap;
    border: 1px solid currentColor;
  }}

  .sev-CRITICAL {{ color: var(--crit); background: rgba(255,45,85,0.1);  }}
  .sev-HIGH     {{ color: var(--high); background: rgba(255,107,53,0.1); }}
  .sev-MEDIUM   {{ color: var(--med);  background: rgba(255,184,0,0.1);  }}
  .sev-LOW      {{ color: var(--low);  background: rgba(0,200,150,0.1);  }}
  .sev-INFO     {{ color: var(--muted); background: rgba(107,114,128,0.1); }}

  .source-pill {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.6rem;
    padding: 0.15rem 0.5rem;
    border-radius: 3px;
    background: rgba(79,142,247,0.1);
    color: var(--accent);
    border: 1px solid rgba(79,142,247,0.2);
    white-space: nowrap;
  }}

  .check-id {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.72rem;
    color: var(--muted);
  }}

  .file-path {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.72rem;
    color: var(--muted);
  }}

  .file-path .line {{ color: var(--accent); }}

  .expand-btn {{
    background: none;
    border: 1px solid var(--border);
    border-radius: 3px;
    color: var(--muted);
    cursor: pointer;
    font-size: 0.7rem;
    padding: 0.1rem 0.4rem;
    transition: all 0.15s;
  }}
  .expand-btn:hover {{ border-color: var(--accent); color: var(--accent); }}

  /* Detail row */
  .detail-row td {{
    padding: 0 1rem 1rem;
    background: rgba(0,0,0,0.3);
  }}
  .detail-row {{ display: none; }}
  .detail-row.visible {{ display: table-row; }}

  .detail-inner {{
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
  }}

  .detail-section {{
    padding: 0.8rem 1rem;
    border-bottom: 1px solid var(--border);
  }}
  .detail-section:last-child {{ border-bottom: none; }}

  .detail-label {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.6rem;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 0.3rem;
  }}

  .detail-text {{
    font-size: 0.82rem;
    color: var(--text);
    line-height: 1.5;
  }}

  .link-list {{ list-style: none; }}
  .link-list li a {{
    color: var(--accent);
    text-decoration: none;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.75rem;
  }}
  .link-list li a:hover {{ text-decoration: underline; }}

  /* ── Bar chart ── */
  .chart-wrap {{
    margin: 0 2.5rem 1.5rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.2rem 1.5rem;
  }}

  .chart-title {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.65rem;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 1rem;
  }}

  .bar-row {{
    display: flex;
    align-items: center;
    gap: 0.8rem;
    margin-bottom: 0.6rem;
  }}

  .bar-label {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.7rem;
    width: 70px;
    color: var(--text);
  }}

  .bar-track {{
    flex: 1;
    height: 14px;
    background: rgba(255,255,255,0.04);
    border-radius: 2px;
    overflow: hidden;
  }}

  .bar-fill {{
    height: 100%;
    border-radius: 2px;
    transition: width 0.8s cubic-bezier(0.16,1,0.3,1);
  }}

  .bar-count {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.72rem;
    width: 30px;
    text-align: right;
    color: var(--muted);
  }}

  .hidden {{ display: none !important; }}

  /* ── Footer ── */
  footer {{
    text-align: center;
    padding: 2rem;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.65rem;
    color: var(--muted);
    border-top: 1px solid var(--border);
  }}
</style>
</head>
<body>

<div class="header">
  <div class="header-left">
    <h1>// <span>terraform</span>.security_report</h1>
    <div class="header-meta">
      scan_time: {scan_time} &nbsp;|&nbsp;
      tfsec + checkov &nbsp;|&nbsp;
      {total} findings
    </div>
  </div>
  <div class="risk-badge" id="risk-badge">{risk_label}</div>
</div>

<!-- Summary Cards -->
<div class="summary">
  <div class="stat-card total">
    <div class="stat-label">Total</div>
    <div class="stat-value">{total}</div>
  </div>
  <div class="stat-card crit">
    <div class="stat-label">Critical</div>
    <div class="stat-value">{critical}</div>
  </div>
  <div class="stat-card high">
    <div class="stat-label">High</div>
    <div class="stat-value">{high}</div>
  </div>
  <div class="stat-card med">
    <div class="stat-label">Medium</div>
    <div class="stat-value">{medium}</div>
  </div>
  <div class="stat-card low">
    <div class="stat-label">Low</div>
    <div class="stat-value">{low}</div>
  </div>
  <div class="stat-card sources">
    <div class="stat-label">Sources</div>
    <div class="stat-value">tfsec: {tfsec_count}<br>checkov: {checkov_count}</div>
  </div>
</div>

<!-- Distribution Chart -->
<div class="chart-wrap">
  <div class="chart-title">Severity Distribution</div>
  {chart_bars}
</div>

<!-- Toolbar -->
<div class="toolbar">
  <button class="filter-btn active" data-filter="ALL" onclick="setFilter('ALL', this)">All</button>
  <button class="filter-btn sev-CRITICAL" data-filter="CRITICAL" onclick="setFilter('CRITICAL', this)">Critical</button>
  <button class="filter-btn sev-HIGH"     data-filter="HIGH"     onclick="setFilter('HIGH', this)">High</button>
  <button class="filter-btn sev-MEDIUM"   data-filter="MEDIUM"   onclick="setFilter('MEDIUM', this)">Medium</button>
  <button class="filter-btn sev-LOW"      data-filter="LOW"      onclick="setFilter('LOW', this)">Low</button>
  <button class="filter-btn" data-filter="tfsec"   onclick="setFilter('tfsec', this)">tfsec</button>
  <button class="filter-btn" data-filter="checkov" onclick="setFilter('checkov', this)">checkov</button>
  <div class="spacer"></div>
  <div class="search-wrap">
    <span class="search-icon">⌕</span>
    <input type="text" id="search-box" placeholder="Search findings..." oninput="applyFilters()">
  </div>
</div>

<!-- Findings Table -->
<div class="findings-wrap">
  <div class="count-label" id="count-label">Showing {total} findings</div>
  <table class="findings-table">
    <thead>
      <tr>
        <th onclick="sortBy('severity_rank')" class="sorted">
          Severity <span class="sort-arrow">↓</span>
        </th>
        <th onclick="sortBy('id')">Check ID <span class="sort-arrow">↕</span></th>
        <th>Title</th>
        <th onclick="sortBy('resource')">Resource <span class="sort-arrow">↕</span></th>
        <th>File</th>
        <th>Source</th>
        <th></th>
      </tr>
    </thead>
    <tbody id="findings-body">
    </tbody>
  </table>
</div>

<footer>
  Generated by terraform-scanner · tfsec + checkov · {scan_time}
</footer>

<script>
const FINDINGS = {findings_json};

let currentFilter = 'ALL';
let currentSort   = {{ key: 'severity_rank', dir: -1 }};

const SEV_RANK = {{ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 }};
const SEV_COLOR = {{
  CRITICAL: '#FF2D55', HIGH: '#FF6B35', MEDIUM: '#FFB800',
  LOW: '#00C896', INFO: '#6B7280'
}};

function setFilter(f, btn) {{
  currentFilter = f;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  applyFilters();
}}

function sortBy(key) {{
  if (currentSort.key === key) currentSort.dir *= -1;
  else {{ currentSort.key = key; currentSort.dir = -1; }}
  document.querySelectorAll('thead th').forEach(th => th.classList.remove('sorted'));
  event.currentTarget.classList.add('sorted');
  applyFilters();
}}

function applyFilters() {{
  const q = document.getElementById('search-box').value.toLowerCase();

  let data = [...FINDINGS].filter(f => {{
    if (currentFilter === 'ALL') return true;
    if (['tfsec','checkov'].includes(currentFilter)) return f.source === currentFilter;
    return f.severity === currentFilter;
  }}).filter(f => {{
    if (!q) return true;
    return (f.id + f.title + f.resource + f.file + f.description).toLowerCase().includes(q);
  }});

  data.sort((a, b) => {{
    const av = a[currentSort.key] ?? 0;
    const bv = b[currentSort.key] ?? 0;
    return (av < bv ? -1 : av > bv ? 1 : 0) * currentSort.dir;
  }});

  document.getElementById('count-label').textContent = `Showing ${{data.length}} findings`;
  renderRows(data);
}}

function renderRows(data) {{
  const tbody = document.getElementById('findings-body');
  tbody.innerHTML = '';
  if (data.length === 0) {{
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:3rem;color:#6b7280;font-family:'IBM Plex Mono',monospace;font-size:.8rem;">no findings match current filter</td></tr>`;
    return;
  }}

  data.forEach((f, i) => {{
    const rowId = `row-${{i}}`;
    const detailId = `detail-${{i}}`;

    const fileShort = f.file ? f.file.split('/').slice(-2).join('/') : '—';
    const lineInfo  = f.line_start ? `<span class="line">:${{f.line_start}}</span>` : '';

    const tr = document.createElement('tr');
    tr.dataset.severity = f.severity;
    tr.dataset.source   = f.source;
    tr.id = rowId;

    tr.innerHTML = `
      <td><span class="sev-pill sev-${{f.severity}}">${{f.severity}}</span></td>
      <td><span class="check-id">${{f.id || '—'}}</span></td>
      <td style="max-width:280px;word-break:break-word;">${{f.title || '—'}}</td>
      <td style="max-width:160px;word-break:break-all;font-family:'IBM Plex Mono',monospace;font-size:.72rem;color:#9ca3af;">${{f.resource || '—'}}</td>
      <td><span class="file-path">${{fileShort}}${{lineInfo}}</span></td>
      <td><span class="source-pill">${{f.source}}</span></td>
      <td><button class="expand-btn" onclick="toggleDetail('${{detailId}}', '${{rowId}}', this)">+</button></td>
    `;
    tbody.appendChild(tr);

    // Detail row
    const links = (f.links || []).filter(Boolean).map(l =>
      `<li><a href="${{l}}" target="_blank" rel="noopener">${{l}}</a></li>`
    ).join('');

    const dtr = document.createElement('tr');
    dtr.className = 'detail-row';
    dtr.id = detailId;
    dtr.innerHTML = `
      <td colspan="7">
        <div class="detail-inner">
          <div class="detail-section">
            <div class="detail-label">Description</div>
            <div class="detail-text">${{f.description || f.title || 'No description available.'}}</div>
          </div>
          ${{f.impact ? `<div class="detail-section"><div class="detail-label">Impact</div><div class="detail-text">${{f.impact}}</div></div>` : ''}}
          ${{f.resolution ? `<div class="detail-section"><div class="detail-label">Resolution</div><div class="detail-text">${{f.resolution}}</div></div>` : ''}}
          ${{f.file ? `<div class="detail-section"><div class="detail-label">Location</div><div class="detail-text" style="font-family:'IBM Plex Mono',monospace;font-size:.78rem;">${{f.file}} · lines ${{f.line_start}}–${{f.line_end}}</div></div>` : ''}}
          ${{links ? `<div class="detail-section"><div class="detail-label">References</div><ul class="link-list">${{links}}</ul></div>` : ''}}
        </div>
      </td>
    `;
    tbody.appendChild(dtr);
  }});
}}

function toggleDetail(detailId, rowId, btn) {{
  const row = document.getElementById(rowId);
  const detail = document.getElementById(detailId);
  const open = detail.classList.contains('visible');
  if (open) {{
    detail.classList.remove('visible');
    row.classList.remove('expanded');
    btn.textContent = '+';
  }} else {{
    detail.classList.add('visible');
    row.classList.add('expanded');
    btn.textContent = '−';
  }}
}}

// Set risk badge color
const badge = document.getElementById('risk-badge');
const crit  = {critical_val};
const high  = {high_val};
if (crit > 0)      {{ badge.style.color = '#FF2D55'; badge.style.borderColor = '#FF2D55'; }}
else if (high > 0) {{ badge.style.color = '#FF6B35'; badge.style.borderColor = '#FF6B35'; }}
else               {{ badge.style.color = '#FFB800'; badge.style.borderColor = '#FFB800'; }}

// Initial render
applyFilters();
</script>
</body>
</html>
"""


def build_chart_bars(summary: dict, total: int) -> str:
    bars = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = summary.get(sev.lower(), 0)
        pct   = (count / total * 100) if total else 0
        color = SEVERITY_COLOR[sev]
        bars.append(f"""
    <div class="bar-row">
      <div class="bar-label">{sev}</div>
      <div class="bar-track">
        <div class="bar-fill" style="width:{pct:.1f}%;background:{color};"></div>
      </div>
      <div class="bar-count">{count}</div>
    </div>""")
    return "\n".join(bars)


def risk_label(summary: dict) -> str:
    if summary.get("critical", 0) > 0: return "CRITICAL RISK"
    if summary.get("high",     0) > 0: return "HIGH RISK"
    if summary.get("medium",   0) > 0: return "MEDIUM RISK"
    return "LOW RISK"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input",  required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    data     = json.loads(args.input.read_text())
    summary  = data["summary"]
    findings = data["findings"]
    total    = summary["total"]

    html = HTML_TEMPLATE.format(
        scan_time     = data.get("scan_time", datetime.utcnow().isoformat()+"Z"),
        total         = total,
        critical      = summary.get("critical", 0),
        high          = summary.get("high", 0),
        medium        = summary.get("medium", 0),
        low           = summary.get("low", 0),
        tfsec_count   = summary.get("tfsec_count", 0),
        checkov_count = summary.get("checkov_count", 0),
        crit_color    = SEVERITY_COLOR["CRITICAL"],
        high_color    = SEVERITY_COLOR["HIGH"],
        med_color     = SEVERITY_COLOR["MEDIUM"],
        low_color     = SEVERITY_COLOR["LOW"],
        chart_bars    = build_chart_bars(summary, total),
        risk_label    = risk_label(summary),
        findings_json = json.dumps(findings),
        critical_val  = summary.get("critical", 0),
        high_val      = summary.get("high", 0),
    )

    args.output.write_text(html)
    print(f"[report] HTML report written to {args.output}")


if __name__ == "__main__":
    main()
