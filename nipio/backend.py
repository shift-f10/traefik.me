#!/usr/bin/python3
# Copyright 2019 Exentrique Solutions Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#!/usr/bin/python3
import configparser
import os
import sys

def _is_debug():
    return True  # Enable debugging

def _log(msg):
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
        self.soa = f"{config.get('soa', 'ns')} {config.get('soa', 'hostmaster')} {self.id}"
        self.domain = config.get('main', 'domain')
        self.ip_address = config.get('main', 'ipaddress')
        self.ttl = config.get('main', 'ttl')

        if config.has_section("acme"):
            self.acme_challenge = [entry[1] for entry in config.items("acme")]
        
        self.name_servers = dict(config.items('nameservers'))
        self.static = dict(config.items('static')) if config.has_section("static") else {}
        self.blacklisted_ips = [entry[1] for entry in config.items("blacklist")] if config.has_section("blacklist") else []

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
                if qname in self.static:
                    self.handle_static(qname)
                elif qname == self.domain:
                    self.handle_self(qname)
                elif qname in self.name_servers:
                    self.handle_nameservers(qname)
                elif qname == f'_acme-challenge.{self.domain}' and self.acme_challenge:
                    self.handle_acme(qname)
                else:
                    self.handle_subdomains(qname)
            elif qtype == 'SOA' and qname.endswith(self.domain):
                self.handle_soa(qname)  # FIX: Now SOA queries will not crash
            elif qtype == 'TXT' and qname == f'_acme-challenge.{self.domain}' and self.acme_challenge:
                self.handle_acme(qname)
            else:
                self.handle_unknown(qtype, qname)

    def handle_soa(self, qname):
        """Handles SOA queries to prevent backend crashes."""
        _log(f"Handling SOA query for {qname}")
        _write('DATA', qname, 'IN', 'SOA', self.ttl, self.id, self.soa)
        _write('END')

    def handle_acme(self, name):
        """Handles ACME DNS-01 challenges."""
        _write('DATA', name, 'IN', 'A', self.ttl, self.id, self.ip_address)
        for challenge in self.acme_challenge:
            _write('DATA', name, 'IN', 'TXT', self.ttl, self.id, challenge)
        self.write_name_servers(name)
        _write('END')

    def handle_static(self, qname):
        """Handles static DNS records."""
        if qname in self.static:
            ip = self.static[qname]
            _write('DATA', qname, 'IN', 'A', self.ttl, self.id, ip)
        else:
            _log(f"No static entry for {qname}")
        self.write_name_servers(qname)
        _write('END')

    def handle_self(self, qname):
        """Handles queries for the main domain."""
        _write('DATA', qname, 'IN', 'A', self.ttl, self.id, self.ip_address)
        self.write_name_servers(qname)
        _write('END')

    def handle_nameservers(self, qname):
        """Handles NS records."""
        _write('DATA', qname, 'IN', 'NS', self.ttl, self.id, self.name_servers[qname])
        _write('END')

    def handle_subdomains(self, qname):
        """Handles subdomains dynamically."""
        _write('LOG', f'No matching rule for {qname}')
        _write('END')

    def write_name_servers(self, qname):
        """Writes NS records."""
        for ns in self.name_servers:
            _write('DATA', qname, 'IN', 'NS', self.ttl, self.id, ns)

    def handle_unknown(self, qtype, qname):
        """Handles unknown query types."""
        _write('LOG', f'Unknown query type: {qtype}, domain: {qname}')
        _write('END')

    def _get_config_filename(self):
        """Returns the backend configuration filename."""
        return os.path.join(os.path.dirname(os.path.realpath(__file__)), 'backend.conf')

if __name__ == '__main__':
    backend = DynamicBackend()
    backend.configure()
    backend.run()
