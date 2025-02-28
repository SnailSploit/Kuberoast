# kuberoast/report.py

import json

def generate_report(findings_dict, output_format="json"):
    """
    Convert findings into JSON or a simple text summary.
    """
    if output_format.lower() == "json":
        return json.dumps(findings_dict, indent=2)
    else:
        lines = []
        for category, findings in findings_dict.items():
            lines.append(f"== {category.upper()} ==")
            for f in findings:
                lines.append(str(f))
            lines.append("")
        return "\n".join(lines)
