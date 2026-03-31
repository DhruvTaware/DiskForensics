"""
Forensic Report Generator for DiskForensics.

Generates professional forensic investigation reports in HTML and JSON formats.
Reports include all analysis results: partition table, filesystem contents,
deleted file recovery, timeline, and hash values.

A forensic report must be:
  - Complete: Document every finding
  - Verifiable: Include all hash values for evidence integrity
  - Reproducible: Another examiner should reach the same conclusions
  - Defensible: Ready to withstand legal scrutiny

Author: Edward Marez
License: MIT
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Any, Dict

from jinja2 import Environment, BaseLoader

from .hash_engine import ImageHashReport
from .mbr_parser import MBRResult
from .gpt_parser import GPTResult
from .fat32_parser import FAT32Result
from .ntfs_parser import NTFSResult
from .file_recovery import RecoveryResult
from .timeline_generator import TimelineResult
from .utils import format_bytes


# ---------------------------------------------------------------------------
# HTML Template
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DiskForensics Report — {{ report.image_filename }}</title>
<style>
:root {
    --bg: #0f1117;
    --surface: #1a1d27;
    --surface2: #252836;
    --border: #2d3148;
    --text: #e2e8f0;
    --text-dim: #94a3b8;
    --accent: #3b82f6;
    --accent-glow: rgba(59,130,246,0.15);
    --green: #22c55e;
    --red: #ef4444;
    --yellow: #f59e0b;
    --orange: #f97316;
    --mono: 'Courier New', Consolas, monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 14px;
    line-height: 1.6;
}
.page-wrap { max-width: 1200px; margin: 0 auto; padding: 2rem; }
header {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 1.5rem 2rem;
    margin-bottom: 2rem;
    border-radius: 8px;
}
header h1 { font-size: 1.6rem; font-weight: 700; color: var(--accent); margin-bottom: 0.25rem; }
header .subtitle { color: var(--text-dim); font-size: 0.85rem; }
.meta-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 1rem;
    margin: 1.5rem 0;
}
.meta-card {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1rem;
}
.meta-card .label { font-size: 0.75rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.25rem; }
.meta-card .value { font-size: 1rem; font-weight: 600; font-family: var(--mono); word-break: break-all; }
section { margin-bottom: 2.5rem; }
h2 {
    font-size: 1.1rem;
    font-weight: 600;
    padding: 0.6rem 1rem;
    background: var(--surface);
    border-left: 3px solid var(--accent);
    border-radius: 0 4px 4px 0;
    margin-bottom: 1rem;
}
h3 { font-size: 0.95rem; font-weight: 600; color: var(--text-dim); margin: 1rem 0 0.5rem; }
table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.82rem;
    margin-bottom: 1rem;
}
th {
    background: var(--surface2);
    color: var(--text-dim);
    font-weight: 600;
    text-align: left;
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    white-space: nowrap;
}
td {
    padding: 0.4rem 0.75rem;
    border-bottom: 1px solid var(--border);
    font-family: var(--mono);
    font-size: 0.8rem;
}
tr:hover td { background: var(--surface2); }
.badge {
    display: inline-block;
    padding: 0.1rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
}
.badge-green { background: rgba(34,197,94,0.15); color: var(--green); }
.badge-red { background: rgba(239,68,68,0.15); color: var(--red); }
.badge-yellow { background: rgba(245,158,11,0.15); color: var(--yellow); }
.badge-blue { background: rgba(59,130,246,0.15); color: var(--accent); }
.hash-block {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1rem;
    font-family: var(--mono);
    font-size: 0.8rem;
    margin-bottom: 0.75rem;
}
.hash-block .algo { color: var(--accent); font-weight: 700; margin-bottom: 0.3rem; font-size: 0.75rem; }
.hash-block .digest { word-break: break-all; color: var(--text); }
.hash-block .meta { color: var(--text-dim); font-size: 0.75rem; margin-top: 0.3rem; }
.deleted-row td { color: var(--red); opacity: 0.8; }
.timeline-deleted { color: var(--red); }
.timeline-created { color: var(--green); }
.timeline-modified { color: var(--yellow); }
.timeline-accessed { color: var(--text-dim); }
footer {
    margin-top: 3rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
    text-align: center;
    color: var(--text-dim);
    font-size: 0.75rem;
}
.summary-stats { display: flex; gap: 1.5rem; flex-wrap: wrap; margin-bottom: 1rem; }
.stat { background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; padding: 0.75rem 1.25rem; }
.stat .n { font-size: 1.5rem; font-weight: 700; color: var(--accent); font-family: var(--mono); }
.stat .l { font-size: 0.75rem; color: var(--text-dim); }
code { background: var(--surface2); padding: 0.1rem 0.4rem; border-radius: 3px; font-family: var(--mono); font-size: 0.8rem; }
</style>
</head>
<body>
<div class="page-wrap">

<header>
  <h1>&#x1F50D; DiskForensics Examination Report</h1>
  <div class="subtitle">
    Generated by DiskForensics v1.0.0 &mdash; Author: Edward Marez &mdash;
    {{ report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC') }}
  </div>
</header>

<!-- Evidence Info -->
<section>
<h2>Evidence Information</h2>
<div class="meta-grid">
  <div class="meta-card">
    <div class="label">Image File</div>
    <div class="value">{{ report.image_filename }}</div>
  </div>
  <div class="meta-card">
    <div class="label">Image Size</div>
    <div class="value">{{ report.image_size_human }}</div>
  </div>
  <div class="meta-card">
    <div class="label">Analysis Date</div>
    <div class="value">{{ report.generated_at.strftime('%Y-%m-%d') }}</div>
  </div>
  <div class="meta-card">
    <div class="label">Partition Scheme</div>
    <div class="value">{{ report.partition_scheme }}</div>
  </div>
</div>
</section>

<!-- Hashes -->
{% if report.hash_report %}
<section>
<h2>Evidence Integrity (Cryptographic Hashes)</h2>
{% for h in report.hash_report.full_image_hashes %}
<div class="hash-block">
  <div class="algo">{{ h.algorithm.upper() }} — {{ h.target }}</div>
  <div class="digest">{{ h.digest }}</div>
  <div class="meta">{{ h.size_human }} &bull; Computed {{ h.computed_at.strftime('%Y-%m-%d %H:%M:%S UTC') }} &bull; {{ "%.2f"|format(h.elapsed_seconds) }}s</div>
</div>
{% endfor %}
{% if report.hash_report.partition_hashes %}
<h3>Partition Hashes</h3>
{% for h in report.hash_report.partition_hashes %}
<div class="hash-block">
  <div class="algo">{{ h.algorithm.upper() }} — {{ h.target }}</div>
  <div class="digest">{{ h.digest }}</div>
  <div class="meta">{{ h.size_human }}</div>
</div>
{% endfor %}
{% endif %}
</section>
{% endif %}

<!-- Partition Table -->
{% if report.mbr_result %}
<section>
<h2>MBR Partition Table</h2>
<div class="summary-stats">
  <div class="stat"><div class="n">{{ report.mbr_result.active_partitions|length }}</div><div class="l">Partitions</div></div>
  <div class="stat"><div class="n">{{ 'VALID' if report.mbr_result.valid_signature else 'INVALID' }}</div><div class="l">Boot Signature</div></div>
  <div class="stat"><div class="n">{{ 'YES' if report.mbr_result.has_gpt else 'NO' }}</div><div class="l">GPT Protected</div></div>
</div>
<table>
<thead><tr>
  <th>#</th><th>Bootable</th><th>Type</th><th>LBA Start</th><th>LBA End</th><th>Size</th>
</tr></thead>
<tbody>
{% for p in report.mbr_result.active_partitions %}
<tr>
  <td>{{ p.index + 1 }}</td>
  <td>{% if p.is_bootable %}<span class="badge badge-green">YES</span>{% else %}No{% endif %}</td>
  <td>{{ p.type_name }} <code>0x{{ "%02X"|format(p.partition_type) }}</code></td>
  <td>{{ "{:,}".format(p.lba_start) }}</td>
  <td>{{ "{:,}".format(p.lba_end) }}</td>
  <td>{{ p.size_human }}</td>
</tr>
{% endfor %}
</tbody>
</table>
</section>
{% endif %}

{% if report.gpt_result and report.gpt_result.header %}
<section>
<h2>GPT Partition Table</h2>
<div class="meta-grid">
  <div class="meta-card"><div class="label">Disk GUID</div><div class="value">{{ report.gpt_result.header.disk_guid }}</div></div>
  <div class="meta-card"><div class="label">Header CRC</div><div class="value">{{ 'VALID' if report.gpt_result.header_crc_valid else 'INVALID' }}</div></div>
  <div class="meta-card"><div class="label">Revision</div><div class="value">{{ report.gpt_result.header.revision_str }}</div></div>
</div>
<table>
<thead><tr><th>#</th><th>Name</th><th>Type</th><th>LBA Start</th><th>LBA End</th><th>Size</th></tr></thead>
<tbody>
{% for p in report.gpt_result.active_partitions %}
<tr>
  <td>{{ p.index + 1 }}</td>
  <td>{{ p.name }}</td>
  <td>{{ p.type_name }}</td>
  <td>{{ "{:,}".format(p.lba_start) }}</td>
  <td>{{ "{:,}".format(p.lba_end) }}</td>
  <td>{{ p.size_human }}</td>
</tr>
{% endfor %}
</tbody>
</table>
</section>
{% endif %}

<!-- Filesystem Files -->
{% if report.fat32_result %}
<section>
<h2>FAT32 Filesystem Contents</h2>
{% if report.fat32_result.boot_sector %}
<div class="summary-stats">
  <div class="stat"><div class="n">{{ report.fat32_result.boot_sector.volume_label or '(none)' }}</div><div class="l">Volume Label</div></div>
  <div class="stat"><div class="n">{{ report.fat32_result.files|length }}</div><div class="l">Active Files</div></div>
  <div class="stat"><div class="n">{{ report.fat32_result.deleted_files|length }}</div><div class="l">Deleted Files</div></div>
</div>
{% endif %}
<table>
<thead><tr>
  <th>Name</th><th>Size</th><th>Created</th><th>Modified</th><th>Cluster</th><th>Status</th>
</tr></thead>
<tbody>
{% for f in report.fat32_result.files + report.fat32_result.deleted_files %}
<tr {% if f.is_deleted %}class="deleted-row"{% endif %}>
  <td>{{ f.name }}</td>
  <td>{{ f.size_human }}</td>
  <td>{{ f.created.strftime('%Y-%m-%d %H:%M') if f.created else 'N/A' }}</td>
  <td>{{ f.modified.strftime('%Y-%m-%d %H:%M') if f.modified else 'N/A' }}</td>
  <td>{{ f.first_cluster }}</td>
  <td>{% if f.is_deleted %}<span class="badge badge-red">DELETED</span>{% else %}<span class="badge badge-green">Active</span>{% endif %}</td>
</tr>
{% endfor %}
</tbody>
</table>
</section>
{% endif %}

{% if report.ntfs_result %}
<section>
<h2>NTFS Filesystem Contents (MFT Records)</h2>
{% if report.ntfs_result.boot_sector %}
<div class="summary-stats">
  <div class="stat"><div class="n">{{ report.ntfs_result.active_records|length }}</div><div class="l">Active Records</div></div>
  <div class="stat"><div class="n">{{ report.ntfs_result.deleted_records|length }}</div><div class="l">Deleted Records</div></div>
</div>
{% endif %}
<table>
<thead><tr>
  <th>MFT#</th><th>Name</th><th>Size</th><th>Created ($SI)</th><th>Modified ($SI)</th><th>Type</th><th>Status</th>
</tr></thead>
<tbody>
{% for r in report.ntfs_result.records %}
<tr {% if not r.in_use %}class="deleted-row"{% endif %}>
  <td>{{ r.record_number }}</td>
  <td>{{ r.primary_name }}</td>
  <td>{{ r.data_size|format_bytes if r.data_size else '-' }}</td>
  <td>{{ r.created.strftime('%Y-%m-%d %H:%M') if r.created else 'N/A' }}</td>
  <td>{{ r.modified.strftime('%Y-%m-%d %H:%M') if r.modified else 'N/A' }}</td>
  <td>{% if r.is_directory %}<span class="badge badge-blue">DIR</span>{% else %}File{% endif %}</td>
  <td>{% if not r.in_use %}<span class="badge badge-red">DELETED</span>{% else %}<span class="badge badge-green">Active</span>{% endif %}</td>
</tr>
{% endfor %}
</tbody>
</table>
</section>
{% endif %}

<!-- Recovery -->
{% if report.recovery_results %}
<section>
<h2>Deleted File Recovery</h2>
{% for recovery in report.recovery_results %}
<h3>{{ recovery.filesystem }} — {{ recovery.count }} deleted entries
  ({{ recovery.likely_recoverable_count }} likely recoverable)</h3>
{% if recovery.scan_notes %}<p style="color:var(--text-dim);font-size:0.82rem;margin-bottom:0.75rem;">{{ recovery.scan_notes }}</p>{% endif %}
<table>
<thead><tr>
  <th>Filename</th><th>Size</th><th>Modified</th><th>Cluster/MFT#</th><th>Recoverable?</th><th>Notes</th>
</tr></thead>
<tbody>
{% for f in recovery.recovered_files %}
<tr class="deleted-row">
  <td>{{ f.filename }}{% if f.filename_partial %} *{% endif %}</td>
  <td>{{ f.size_human }}</td>
  <td>{{ f.modified.strftime('%Y-%m-%d %H:%M') if f.modified else 'N/A' }}</td>
  <td>{{ f.first_cluster }}</td>
  <td>{% if f.likely_recoverable %}<span class="badge badge-green">YES</span>{% else %}<span class="badge badge-red">No</span>{% endif %}</td>
  <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="{{ f.recovery_notes }}">{{ f.recovery_notes[:80] }}</td>
</tr>
{% endfor %}
</tbody>
</table>
{% endfor %}
</section>
{% endif %}

<!-- Timeline -->
{% if report.timeline %}
<section>
<h2>Forensic Timeline ({{ report.timeline.count }} events)</h2>
{% if report.timeline.count > 0 %}
<table>
<thead><tr>
  <th>Timestamp</th><th>Event</th><th>FS</th><th>Filename</th><th>Size</th><th>Source</th><th>Del?</th>
</tr></thead>
<tbody>
{% for e in report.timeline.sorted_events[:500] %}
<tr>
  <td>{{ e.timestamp_str }}</td>
  <td class="timeline-{{ e.event_type.lower().split('_')[-1] }}">{{ e.event_type }}</td>
  <td>{{ e.filesystem }}</td>
  <td>{{ e.filename }}</td>
  <td>{{ e.file_size if e.file_size else '-' }}</td>
  <td>{{ e.source }}</td>
  <td>{% if e.is_deleted %}<span class="badge badge-red">Y</span>{% endif %}</td>
</tr>
{% endfor %}
{% if report.timeline.count > 500 %}
<tr><td colspan="7" style="text-align:center;color:var(--text-dim);">... {{ report.timeline.count - 500 }} more events truncated. Export to CSV for full timeline.</td></tr>
{% endif %}
</tbody>
</table>
{% endif %}
</section>
{% endif %}

<footer>
  DiskForensics v1.0.0 &mdash; Author: Edward Marez &mdash; MIT License<br>
  Report generated {{ report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC') }}<br>
  This report is intended for forensic investigation purposes only.
</footer>

</div>
</body>
</html>
"""


class ForensicReport:
    """Data object holding all results for one investigation."""

    def __init__(
        self,
        image_path: str,
        image_size: int,
    ):
        self.image_path = image_path
        self.image_filename = Path(image_path).name
        self.image_size = image_size
        self.image_size_human = format_bytes(image_size)
        self.generated_at = datetime.now(timezone.utc)
        self.partition_scheme = "Unknown"

        self.hash_report: Optional[ImageHashReport] = None
        self.mbr_result: Optional[MBRResult] = None
        self.gpt_result: Optional[GPTResult] = None
        self.fat32_result: Optional[FAT32Result] = None
        self.ntfs_result: Optional[NTFSResult] = None
        self.recovery_results: List[RecoveryResult] = []
        self.timeline: Optional[TimelineResult] = None

    def to_dict(self) -> dict:
        """Serialize all results to a JSON-compatible dictionary."""
        data = {
            "report_metadata": {
                "generator": "DiskForensics v1.0.0",
                "author": "Edward Marez",
                "image_path": self.image_path,
                "image_filename": self.image_filename,
                "image_size_bytes": self.image_size,
                "image_size_human": self.image_size_human,
                "generated_at": self.generated_at.isoformat(),
                "partition_scheme": self.partition_scheme,
            }
        }

        if self.hash_report:
            data["hashes"] = self.hash_report.to_dict()

        if self.mbr_result:
            data["mbr"] = self.mbr_result.to_dict()

        if self.gpt_result:
            data["gpt"] = self.gpt_result.to_dict()

        if self.fat32_result:
            data["fat32"] = self.fat32_result.to_dict()

        if self.ntfs_result:
            data["ntfs"] = self.ntfs_result.to_dict()

        if self.recovery_results:
            data["recovery"] = [r.to_dict() for r in self.recovery_results]

        if self.timeline:
            data["timeline"] = self.timeline.to_list()

        return data


class ReportGenerator:
    """
    Generates forensic investigation reports in HTML and JSON format.

    Usage:
        report = ForensicReport(image_path, image_size)
        report.mbr_result = mbr_parser.parse()
        report.fat32_result = fat_parser.parse()
        # ...

        gen = ReportGenerator()
        gen.save_html(report, "./report/report.html")
        gen.save_json(report, "./report/report.json")
    """

    def __init__(self):
        """Initialize with Jinja2 environment."""
        self._env = Environment(loader=BaseLoader())
        self._env.filters["format_bytes"] = format_bytes

    def render_html(self, report: ForensicReport) -> str:
        """
        Render the forensic report as an HTML string.

        Args:
            report: ForensicReport with all analysis results.

        Returns:
            Complete HTML document string.
        """
        template = self._env.from_string(HTML_TEMPLATE)
        return template.render(report=report)

    def render_json(self, report: ForensicReport) -> str:
        """
        Render the forensic report as a JSON string.

        Args:
            report: ForensicReport with all analysis results.

        Returns:
            Pretty-printed JSON string.
        """
        return json.dumps(report.to_dict(), indent=2, default=str)

    def save_html(self, report: ForensicReport, output_path: str) -> str:
        """
        Save an HTML report to disk.

        Args:
            report: ForensicReport data.
            output_path: File path to write (including .html extension).

        Returns:
            Absolute path of written file.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        html = self.render_html(report)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        return str(output_path.absolute())

    def save_json(self, report: ForensicReport, output_path: str) -> str:
        """
        Save a JSON report to disk.

        Args:
            report: ForensicReport data.
            output_path: File path to write (including .json extension).

        Returns:
            Absolute path of written file.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        json_str = self.render_json(report)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_str)
        return str(output_path.absolute())

    def save_timeline_csv(self, timeline: TimelineResult, output_path: str) -> str:
        """Save the timeline as a CSV file."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8", newline="") as f:
            f.write(timeline.to_csv())
        return str(output_path.absolute())

    def save_all(
        self,
        report: ForensicReport,
        output_dir: str,
        formats: Optional[List[str]] = None,
    ) -> dict[str, str]:
        """
        Save all report formats to an output directory.

        Args:
            report: ForensicReport data.
            output_dir: Directory path for output files.
            formats: List of formats to generate ('html', 'json', 'csv').
                     Defaults to all formats.

        Returns:
            Dict mapping format name to output file path.
        """
        if formats is None:
            formats = ["html", "json"]

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        stem = Path(report.image_filename).stem
        timestamp = report.generated_at.strftime("%Y%m%d_%H%M%S")
        base_name = f"forensics_{stem}_{timestamp}"

        paths = {}

        if "html" in formats:
            html_path = output_dir / f"{base_name}.html"
            paths["html"] = self.save_html(report, str(html_path))

        if "json" in formats:
            json_path = output_dir / f"{base_name}.json"
            paths["json"] = self.save_json(report, str(json_path))

        if "csv" in formats and report.timeline:
            csv_path = output_dir / f"{base_name}_timeline.csv"
            paths["csv"] = self.save_timeline_csv(report.timeline, str(csv_path))

        return paths
