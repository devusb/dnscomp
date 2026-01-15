#!/usr/bin/env python3
"""
Export Cloudflare DNS records to Terraform format

Usage:
    export CLOUDFLARE_API_TOKEN=your_token
    export CLOUDFLARE_ZONE_ID_FLOX_DEV=zone_id
    export CLOUDFLARE_ZONE_ID_FLOXDEV_COM=zone_id
    python export_cloudflare.py > cloudflare_records.txt
"""

import os
import sys
import requests
import json

CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"

ZONES = {
    'flox.dev': os.getenv('CLOUDFLARE_ZONE_ID_FLOX_DEV'),
    'floxdev.com': os.getenv('CLOUDFLARE_ZONE_ID_FLOXDEV_COM')
}


def get_cloudflare_records(zone_id: str, api_token: str) -> list:
    """Get all DNS records from Cloudflare API."""
    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json'
    }

    records = []
    page = 1

    while True:
        url = f"{CLOUDFLARE_API_BASE}/zones/{zone_id}/dns_records?page={page}&per_page=100"
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        data = response.json()
        records.extend(data['result'])

        if page >= data['result_info']['total_pages']:
            break
        page += 1

    return records


def format_terraform_mx(records):
    """Format MX records for terraform."""
    lines = []
    for rec in sorted(records, key=lambda x: x['priority']):
        lines.append(f'    "{rec["priority"]} {rec["content"]}"')
    return ',\n'.join(lines)


def format_terraform_txt(records):
    """Format TXT records for terraform."""
    lines = []
    for rec in sorted(records, key=lambda x: x['content']):
        # Check if content needs splitting (>255 chars)
        content = rec['content']
        if len(content) > 255:
            # Find good split point around 250 chars
            split_point = 250
            parts = []
            while content:
                parts.append(content[:split_point])
                content = content[split_point:]
            lines.append(f'    # Split for 255 char limit')
            lines.append(f'    "{parts[0]}""')
            for part in parts[1:]:
                lines.append(f'    ""{part}"')
        else:
            lines.append(f'    "{content}"')
    return ',\n'.join(lines)


def export_zone(zone_name, zone_id, api_token):
    """Export all records for a zone."""
    print(f"\n{'='*80}")
    print(f"Zone: {zone_name}")
    print(f"{'='*80}\n")

    records = get_cloudflare_records(zone_id, api_token)

    # Group by name and type
    by_name_type = {}
    for rec in records:
        # Skip some types
        if rec['type'] in ['NS', 'SOA']:
            continue

        key = (rec['name'], rec['type'])
        if key not in by_name_type:
            by_name_type[key] = []
        by_name_type[key].append(rec)

    # Print organized by type
    for (name, rtype), recs in sorted(by_name_type.items()):
        print(f"\n# {name} ({rtype})")
        print(f"# Count: {len(recs)}")

        if rtype == 'MX':
            print("records = [")
            print(format_terraform_mx(recs))
            print("]")
        elif rtype == 'TXT':
            print("records = [")
            print(format_terraform_txt(recs))
            print("]")
        elif rtype in ['A', 'AAAA']:
            print(f"records = {json.dumps([r['content'] for r in recs])}")
        elif rtype == 'CNAME':
            if len(recs) > 1:
                print(f"WARNING: Multiple CNAME records!")
            print(f"records = [\"{recs[0]['content']}\"]")
        else:
            print(f"records = {json.dumps([r['content'] for r in recs])}")

        print(f"ttl = {recs[0]['ttl']}")


def main():
    api_token = os.getenv('CLOUDFLARE_API_TOKEN')
    if not api_token:
        print("Error: CLOUDFLARE_API_TOKEN environment variable not set", file=sys.stderr)
        sys.exit(1)

    for zone_name, zone_id in ZONES.items():
        if not zone_id:
            print(f"Warning: Skipping {zone_name} - zone ID not set", file=sys.stderr)
            continue

        try:
            export_zone(zone_name, zone_id, api_token)
        except Exception as e:
            print(f"Error processing {zone_name}: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()


if __name__ == '__main__':
    main()
