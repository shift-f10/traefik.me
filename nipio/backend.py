#!/usr/bin/python3
import configparser
import os
import sys

def _is_debug():
    return True  # ✅ Enable debugging

def _log(msg):
    """Logs messages to stderr for debugging."""
    sys.stderr.write(f'backend ({os.getpid()}): {msg}\n')
    sys.stderr.flush()

def _write(*args):
    """Writes responses to PowerDNS."""
    response = "\t".join(args)
    if _is_debug():
        _log(f'writing: {response}')
    sys.stdout.write(response + "\n")
    sys.stdout.flush()

def _get_next():
    """Reads and processes input from PowerDNS."""
    line = sys.stdin.readline().strip()
    if _is_debug():
        _log(f'read line: {line if line else "<empty>"}')

    if not line:
        return None  # Ignore empty lines

    return line.split('\t')

class DynamicBackend:
    def __init__(self):
        self.id = ''
        self.soa = ''
        self.domain = ''
        self.ip_address = ''
        self.ttl = ''
        self.name_servers = {}
        self.static = {}
        self.blacklisted_ips = []
        self.acme_challenge = []

    def configure(self):
        """Loads backend configuration."""
        fname = self._get_config_filename()
        if not os.path.exists(fname):
            _log(f'Configuration file {fname} does not exist')
            sys.exit(1)

        config = configparser.ConfigParser()
        with open(fname) as fp:
            config.read_file(fp)

        self.id = config.get('soa', 'id')
        self.domain = config.get('main', 'domain')
        self.ip_address = config.get('main', 'ipaddress')
        self.ttl = config.get('main', 'ttl')

        self.name_servers = dict(config.items('nameservers'))
        self.static = dict(config.items('static')) if config.has_section("static") else {}
        self.blacklisted_ips = [entry[1] for entry in config.items("blacklist")] if config.has_section("blacklist") else []
        self.acme_challenge = [entry[1] for entry in config.items("acme")] if config.has_section("acme") else []

        # Fix SOA format with 7 required fields: primary NS, hostmaster, serial, refresh, retry, expire, minimum TTL
        self.soa = f"{self.name_servers['ns.instances.ctrlr.io']} info.ctrlr.io {self.id} 3600 1800 1209600 3600"

        _log(f'Configuration Loaded:')
        _log(f'  Name servers: {self.name_servers}')
        _log(f'  Static resolution: {self.static}')
        _log(f'  ID: {self.id}')
        _log(f'  TTL: {self.ttl}')
        _log(f'  SOA: {self.soa}')
        _log(f'  IP Address: {self.ip_address}')
        _log(f'  DOMAIN: {self.domain}')
        _log(f'  Blacklist: {self.blacklisted_ips}')
        _log(f'  ACME challenge: {self.acme_challenge}')

    def run(self):
        """Handles PowerDNS requests."""
        _log('Starting up')

        while True:
            handshake = _get_next()
            if handshake is None:
                _log("Ignoring empty input during handshake.")
                continue
            if handshake[0] == "HELO" and len(handshake) > 1 and handshake[1] == '1':
                _write('OK', 'We are good')
                _log('Handshake completed')
                break
            else:
                _log(f'Invalid handshake received: {handshake}')
                sys.exit(1)

        while True:
            cmd = _get_next()
            if cmd is None:
                _log("Received empty command, ignoring.")
                continue

            if _is_debug():
                _log(f"Received command: {cmd}")

            if cmd[0] == "END":
                _log("Completing execution")
                break

            if len(cmd) < 6:
                _log(f'Invalid command format: {cmd}')
                _write('FAIL')
                continue

            qname, qtype = cmd[1].lower(), cmd[3]

            if qtype in ('A', 'ANY') and qname.endswith(self.domain):
                self.handle_subdomains(qname)
            elif qtype == 'SOA' and qname.endswith(self.domain):
                self.handle_soa(qname)
            elif qtype == 'TXT' and qname == f'_acme-challenge.{self.domain}' and self.acme_challenge:
                self.handle_acme(qname)
            else:
                self.handle_unknown(qtype, qname)

    def handle_soa(self, qname):
        """Handles SOA queries correctly."""
        _log(f"Handling SOA query for {qname}")
        _write('DATA', qname, 'IN', 'SOA', self.ttl, self.id, self.soa)
        _write('END')

    def handle_subdomains(self, qname):
        """Handles dynamic subdomains like 192-168-1-1.instances.ctrlr.io."""
        _log(f"Handling subdomain query for {qname}")

        parts = qname.split('.')
        
        # Ensure we are dealing with a subdomain under instances.ctrlr.io
        if len(parts) >= 5 and parts[-4] == "instances":
            # Extract IP from the subdomain
            ip_parts = parts[0].split('-')  # "192-168-1-1" → ['192', '168', '1', '1']
            
            if len(ip_parts) == 4:  # Ensure it's a valid IPv4 address structure
                ip = ".".join(ip_parts)  # Convert to '192.168.1.1'
                _log(f"✅ Matched dynamic A record: {qname} -> {ip}")

                # Send A record response
                _write('DATA', qname, 'IN', 'A', self.ttl, self.id, ip)
                _write('END')
                return
            else:
                _log(f"❌ Invalid subdomain format for {qname}")

        _log(f"❌ No matching rule for {qname}")
        _write('LOG', f'No matching rule for {qname}')
        _write('END')

    def _get_config_filename(self):
        """Returns the backend configuration filename."""
        return os.path.join(os.path.dirname(os.path.realpath(__file__)), 'backend.conf')

if __name__ == '__main__':
    backend = DynamicBackend()
    backend.configure()
    backend.run()
