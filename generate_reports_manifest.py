from pathlib import Path
import json

reports_dir = Path("reports_output")

incident_files = sorted([p.name for p in reports_dir.glob("incident_*.html")], reverse=True)
summary_files  = sorted([p.name for p in reports_dir.glob("summary_*.html")],  reverse=True)
metrics_files  = sorted([p.name for p in reports_dir.glob("metrics_*.html")],  reverse=True)

# Combine and sort newest-first (filenames are timestamp-prefixed so lexicographic == chronological)
all_files = sorted(incident_files + summary_files + metrics_files, reverse=True)

manifest = {"files": all_files}

output_path = reports_dir / "reports_manifest.json"
output_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

print(f"Wrote {len(all_files)} entries to {output_path}")
print(f"  {len(incident_files)} incident(s), {len(summary_files)} summary/summaries, {len(metrics_files)} metrics report(s)")
