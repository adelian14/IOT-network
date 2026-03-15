from pathlib import Path
import json

reports_dir = Path("reports_output")

files = sorted(
    [p.name for p in reports_dir.glob("incident_*.html")],
    reverse=True
)

manifest = {
    "files": files
}

output_path = reports_dir / "reports_manifest.json"
output_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

print(f"Wrote {len(files)} entries to {output_path}")