#!/usr/bin/python3


import argparse
import re
import json
import ipaddress
from datetime import datetime, timedelta

LEASE_FILE = 'leases.json'
subnet_v4 = '192.168.1.0/24'
subnet_v6 = '2001:db8::/64'
lease_duration = 3600  # 1 hour

def load_leases():
    try:
        with open(LEASE_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_leases(leases):
    with open(LEASE_FILE, 'w') as f:
        json.dump(leases, f, indent=2)

def validate_mac(mac):
    pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    return bool(pattern.match(mac))

def generate_eui64(mac, subnet):
    mac_clean = re.sub(r'[:.-]', '', mac).lower()
    if len(mac_clean) != 12:
        raise ValueError("Invalid MAC address")
    first_byte = int(mac_clean[:2], 16)
    first_byte ^= 0x02
    modified = f"{first_byte:02x}" + mac_clean[2:]
    modified = modified[:6] + 'fffe' + modified[6:]
    eui64 = ipaddress.EUI64(modified)
    network = ipaddress.IPv6Network(subnet)
    return str(network.network_address + int(eui64))

def assign_ipv4(mac, leases, used_ips):
    if mac in leases and 'ipv4' in leases[mac]:
        return leases[mac]['ipv4']['ip']
    network = ipaddress.IPv4Network(subnet_v4, strict=False)
    for host in network.hosts():
        ip = str(host)
        if ip not in used_ips:
            lease = {
                'ip': ip,
                'lease_time': lease_duration,
                'expiration': (datetime.now() + timedelta(seconds=lease_duration)).isoformat()
            }
            leases.setdefault(mac, {})['ipv4'] = lease
            used_ips.add(ip)
            return ip
    return None

def assign_ipv6(mac, subnet, leases):
    if mac in leases and 'ipv6' in leases[mac]:
        return leases[mac]['ipv6']['ip']
    try:
        ipv6 = generate_eui64(mac, subnet)
    except ValueError:
        return None
    lease = {
        'ip': ipv6,
        'lease_time': lease_duration,
        'expiration': (datetime.now() + timedelta(seconds=lease_duration)).isoformat()
    }
    leases.setdefault(mac, {})['ipv6'] = lease
    return ipv6

def main():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('--mac', required=True)
        parser.add_argument('--dhcp-version', required=True)
        args = parser.parse_args()

        leases = load_leases()
        used_ips = {lease['ipv4']['ip'] for mac in leases if 'ipv4' in leases[mac]}

        if not validate_mac(args.mac):
            print(json.dumps({'error': 'Invalid MAC'}))
            return

        mac = args.mac.lower()
        dhcp_version = args.dhcp_version

        ip = None
        if mac in leases:
            if dhcp_version == 'DHCPv4' and 'ipv4' in leases[mac]:
                ip = leases[mac]['ipv4']['ip']
            elif dhcp_version == 'DHCPv6' and 'ipv6' in leases[mac]:
                ip = leases[mac]['ipv6']['ip']

        if not ip:
            if dhcp_version == 'DHCPv4':
                ip = assign_ipv4(mac, leases, used_ips)
                subnet = subnet_v4
            else:
                ip = assign_ipv6(mac, subnet_v6, leases)
                subnet = subnet_v6

        if not ip:
            print(json.dumps({'error': 'No IP available'}))
            return

        save_leases(leases)
        response = {
            'mac_address': mac,
            'assigned_ipv4' if dhcp_version == 'DHCPv4' else 'assigned_ipv6': ip,
            'lease_time': f"{lease_duration} seconds",
            'subnet': subnet
        }
        print(json.dumps(response))
    except Exception as e:
        print(json.dumps({'error': f'Server error: {str(e)}'}))
if __name__ == '__main__':
    main()