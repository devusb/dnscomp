#!/usr/bin/env python3
"""
DNS Comparison Tool - Compare Cloudflare (authoritative) vs Route53 DNS records

Uses Cloudflare API to enumerate records (authoritative source), then queries both
nameservers via DNS to compare actual responses.

Usage:
    export CLOUDFLARE_API_TOKEN=your_token_here
    python compare_dns.py
"""

import os
import sys
import dns.resolver
import dns.rdatatype
import dns.nameserver
import boto3
import requests
from collections import defaultdict

# Cloudflare API
CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"

# Zone IDs
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


def get_route53_nameservers(zone_name: str) -> list:
    """Get Route53 nameservers for a zone."""
    route53 = boto3.client('route53')

    # Find the zone ID
    paginator = route53.get_paginator('list_hosted_zones')
    zone_id = None
    for page in paginator.paginate():
        for zone in page['HostedZones']:
            if zone['Name'] == f"{zone_name}.":
                zone_id = zone['Id'].split('/')[-1]
                break
        if zone_id:
            break

    if not zone_id:
        raise ValueError(f"Zone {zone_name} not found in Route53")

    # Get nameservers
    zone_info = route53.get_hosted_zone(Id=zone_id)
    return zone_info['DelegationSet']['NameServers']


def get_cloudflare_nameservers(zone_id: str, api_token: str) -> list:
    """Get Cloudflare nameservers for a zone."""
    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json'
    }

    url = f"{CLOUDFLARE_API_BASE}/zones/{zone_id}"
    response = requests.get(url, headers=headers)
    response.raise_for_status()

    return response.json()['result']['name_servers']


def resolve_nameserver(nameserver: str) -> str:
    """Resolve a nameserver hostname to an IP address."""
    try:
        # Try to parse as IP address first
        import ipaddress
        ipaddress.ip_address(nameserver)
        return nameserver
    except ValueError:
        # It's a hostname, resolve it
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(nameserver, 'A')
        return str(answers[0])


def query_dns(name: str, rtype: str, nameserver: str) -> tuple:
    """Query DNS for a specific record via specified nameserver."""
    resolver = dns.resolver.Resolver()
    # Resolve nameserver hostname to IP if needed
    nameserver_ip = resolve_nameserver(nameserver)
    resolver.nameservers = [nameserver_ip]

    try:
        answers = resolver.resolve(name, rtype)
        values = []
        for rdata in answers:
            if rtype == 'TXT':
                # Concatenate TXT strings (handles multi-string TXT records)
                values.append(''.join(s.decode() if isinstance(s, bytes) else str(s) for s in rdata.strings))
            elif rtype == 'MX':
                values.append(f"{rdata.preference} {rdata.exchange}")
            else:
                values.append(str(rdata))
        return answers.rrset.ttl, sorted(values)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException) as e:
        return None, None


def normalize_value(value: str, rtype: str) -> str:
    """Normalize a DNS record value for comparison."""
    if rtype == 'TXT':
        return value.strip('"')
    elif rtype in ['CNAME', 'NS', 'MX']:
        # Ensure trailing dot for FQDN comparisons
        if ' ' in value:  # MX record
            pref, host = value.split(' ', 1)
            host = host if host.endswith('.') else f"{host}."
            return f"{pref} {host}"
        return value if value.endswith('.') else f"{value}."
    return value


def compare_zone(zone_name: str, cf_zone_id: str, api_token: str):
    """Compare DNS records between Cloudflare and Route53 nameservers."""
    print(f"\n{'='*80}")
    print(f"Comparing DNS records for: {zone_name}")
    print(f"{'='*80}\n")

    # Get records from Cloudflare API
    print("Fetching records from Cloudflare API...")
    cf_records = get_cloudflare_records(cf_zone_id, api_token)
    print(f"Found {len(cf_records)} records in Cloudflare\n")

    # Get nameservers
    cf_nameservers = get_cloudflare_nameservers(cf_zone_id, api_token)
    r53_nameservers = get_route53_nameservers(zone_name)

    print(f"Cloudflare Nameservers: {', '.join(cf_nameservers)}")
    print(f"Route53 Nameservers: {', '.join(r53_nameservers)}\n")

    # Use first nameserver from each
    cf_ns = cf_nameservers[0]
    r53_ns = r53_nameservers[0]

    print(f"Querying via DNS: CF={cf_ns}, R53={r53_ns}\n")

    matches = []
    differences = []
    missing_r53 = []

    # Group records by name and type
    record_groups = defaultdict(list)
    for record in cf_records:
        # Skip some record types
        if record['type'] in ['NS', 'SOA']:
            continue
        key = (record['name'], record['type'])
        record_groups[key].append(record)

    for (name, rtype), records in sorted(record_groups.items()):
        # Query both nameservers via DNS
        cf_ttl, cf_values = query_dns(name, rtype, cf_ns)
        r53_ttl, r53_values = query_dns(name, rtype, r53_ns)

        if cf_values is None:
            # Shouldn't happen since we got it from API, but handle it
            continue

        if r53_values is None:
            missing_r53.append(f"⚠️  {name:<40} {rtype:<6} - NOT FOUND in Route53")
            continue

        # Normalize values for comparison
        cf_normalized = sorted([normalize_value(v, rtype) for v in cf_values])
        r53_normalized = sorted([normalize_value(v, rtype) for v in r53_values])

        if cf_normalized == r53_normalized:
            matches.append(f"✅ {name:<40} {rtype:<6}")
        else:
            differences.append(f"\n❌ {name} ({rtype}):")
            differences.append(f"   Cloudflare: {cf_normalized}")
            differences.append(f"   Route53:    {r53_normalized}")

    # Print results
    print("MATCHES:")
    print("-" * 80)
    for match in matches:
        print(match)

    if missing_r53:
        print(f"\n\nMISSING IN ROUTE53:")
        print("-" * 80)
        for miss in missing_r53:
            print(miss)

    if differences:
        print(f"\n\nDIFFERENCES:")
        print("-" * 80)
        for diff in differences:
            print(diff)

    # Summary
    print(f"\n{'='*80}")
    print(f"Summary:")
    print(f"  ✅ Matches: {len(matches)}")
    print(f"  ⚠️  Missing in Route53: {len(missing_r53)}")
    print(f"  ❌ Differences: {len([d for d in differences if d.startswith('❌')])}")
    print(f"{'='*80}\n")

    if not differences and not missing_r53:
        print("🎉 All records match between Cloudflare and Route53!\n")


def main():
    api_token = os.getenv('CLOUDFLARE_API_TOKEN')
    if not api_token:
        print("Error: CLOUDFLARE_API_TOKEN environment variable not set")
        sys.exit(1)

    for zone_name, zone_id in ZONES.items():
        if not zone_id:
            print(f"Warning: Skipping {zone_name} - zone ID not set")
            continue

        try:
            compare_zone(zone_name, zone_id, api_token)
        except Exception as e:
            print(f"Error processing {zone_name}: {e}\n")
            import traceback
            traceback.print_exc()


if __name__ == '__main__':
    main()
