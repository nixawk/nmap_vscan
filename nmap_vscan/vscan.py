#!/usr/bin/python
# -*- coding: utf-8 -*-

# Author: Nixawk

"""
$ python2.7 vscan.py
{'match': {'pattern': '^.*<address>Apache/([\\d.]+) Server at ([-\\w_.]+) Port \\d+</address>\\n</body></html>\\n',
           'versioninfo': {'cpename': ['apache:http_server:2.4.7'],
                           'devicetype': [' v'],
                           'hostname': ['www.nongnu.org'],
                           'info': [],
                           'operatingsystem': [],
                           'vendorproductname': ['Apache httpd'],
                           'version': ['2.4.7']}},
 'probe': {'probename': 'GetRequest',
           'probestring': 'GET / HTTP/1.0\\r\\n\\r\\n'}}
"""

import os
import re
import codecs
import socket
import logging
import contextlib


logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


SOCKET_TIMEOUT = 30                # SOCKET DEFAULT TIMEOUT
SOCKET_READ_BUFFERSIZE = 1024      # SOCKET DEFAULT READ BUFFER
NMAP_ENABLE_PROBE_INCLUED = True   # Scan probes inclued target port
NMAP_ENABLE_PROBE_EXCLUED = True   # Scan probes exclued target port


class NmapException(Exception):
    """Nmap Lib Exception
    """
    pass


class Nmap(object):
    """Please visit https://nmap.org/ for details.
    """

    def fatal(self, msg):
        raise NmapException(msg)


class ServiceProbe(Nmap):
    """nmap-service-probes File Format

    https://nmap.org/book/vscan-fileformat.html
    https://github.com/nmap/nmap/blob/master/service_scan.cc
    """

    g_exclude_directive = ''  # only one (1st line in the file)

    def parse_nmap_service_probe_file(self, filename):
        """parse nmap-service-probes, please read
        https://github.com/nmap/nmap/blob/master/service_scan.cc#L1327
        """

        if not os.path.exists(filename):
            self.fatal("Failed to open nmap-service-probes file %s for reading" % filename)

        lines = []
        with open(filename, "r") as fp:
            for line in fp:
                if line.startswith("\n") or line.startswith("#"): continue
                lines.append(line)

        # valid Exclude / Probe Directive
        self.isvalid_nmap_service_probe_file(lines)

        # parse valid probe data
        return self.parse_nmap_service_probes(lines)

    def isvalid_nmap_service_probe_file(self, lines):
        """check if nmap-service-probes is valid
        """

        # check if file has availabe data
        if not lines:  # None or []
            self.fatal("Failed to read nmap-service-probes file %s for probe data" % filename)

        # only one [Exclude Directive] can be included
        c = 0;
        for line in lines:
            if line.startswith("Exclude "):
                c += 1

            if c > 1:
                self.fatal("Only 1 Exclude directive is allowed in the nmap-service-probes file")

        # Probe file must begin with "Exclude " or "Probe "
        l = lines[0]
        if not (l.startswith("Exclude ") or l.startswith("Probe ")):
            self.fatal("Parse error on nmap-service-probes file: line was expected to begin with \"Probe \" or \"Exclude \"")

    def parse_nmap_service_probes(self, lines):
        """parse probes_parts (file data splited with "\nProbe" tag)
        """
        data = "".join(lines)

        # split data with "\nProbe" tag
        probes_parts = data.split("\nProbe ")

        # The part in front of the first probe is unuse.
        _ = probes_parts.pop(0)
        if _.startswith("Exclude "):
            g_exclude_directive = _

        return [
            self.parse_nmap_service_probe(probe_part)
            for probe_part in probes_parts
        ]

    def parse_nmap_service_probe(self, data):
        """parse every probe part, [Probe] is a split tag, so it will not be shown here, ex:

            TCP NULL q||
            ports 1-65535
            tcpwrappedms 3000
            ....
        """

        probe = {}

        lines = data.split("\n")

        probestr = lines.pop(0) # Probe string
        probe["probe"] = self.get_probe(probestr)

        matches = []
        softmatches = []

        for line in lines:
            if line.startswith("match "):
                match = self.get_match(line)
                if match not in matches:
                    matches.append(match)

            elif line.startswith("softmatch "):
                softmatch = self.get_softmatch(line)
                if softmatch not in softmatches:
                    softmatches.append(softmatch)

            elif line.startswith("ports "):
                probe["ports"] = self.get_ports(line)

            elif line.startswith("sslports "):
                probe["sslports"] = self.get_ssloirts(line)

            elif line.startswith("totalwaitms "):
                probe["totalwaitms"] = self.get_totalwaitms(line)

            elif line.startswith("tcpwrappedms "):
                probe["tcpwrappedms"] = self.get_tcpwrappedms(line)

            elif line.startswith("rarity "):
                probe["rarity"] = self.get_rarity(line)

            elif line.startswith("fallback "):
                probe["fallback"] = self.get_fallback(line)

        probe['matches'] = matches
        probe['softmatches'] = softmatches

        return probe

    def parse_directive_syntax(self, data):
        # <directive_name><blank_space><flag><delimiter><directive_str><flag>
        if data.count(" ") <= 0:
            raise NmapException("nmap-service-probes - error directive format")

        blank_index = data.index(" ")   # First blank character
        directive_name = data[:blank_index]  # Directive Name
        blank_space = data[blank_index: blank_index + 1]
        flag = data[blank_index + 1: blank_index + 2]
        delimiter = data[blank_index + 2: blank_index + 3]
        directive_str = data[blank_index + 3:]

        directive = {
            "directive_name": directive_name,
            "flag": flag,
            "delimiter": delimiter,
            "directive_str": directive_str
        }

        return directive

    def get_probe(self, data):
        # Format: [Proto][probename][blank_space][q][delimiter][probestring]
        # NULL q||
        # GenericLines q|\r\n\r\n|

        proto = data[:4]
        other = data[4:]

        if proto not in ["TCP ", "UDP "]:
            raise NmapException("Probe <protocol>must be either TCP or UDP.")

        if not (other and other[0].isalpha()):
            raise NmapException("nmap-service-probes - bad probe name")

        directive = self.parse_directive_syntax(other)

        probename = directive.get('directive_name')
        probestring, _ = directive.get('directive_str').split(
            directive.get('delimiter'), 1)

        probe = {
            'protocol': proto.strip(),
            'probename': probename,
            'probestring': probestring
        }

        return probe

    def get_match(self, data):
        # Syntax: match <service> <pattern> [<versioninfo>]
        # match iperf3 m|^\t$|
        # softmatch quic m|^\r\x89\xc1\x9c\x1c\*\xff\xfc\xf1((?:Q[0-8]\d\d)+)$| i/QUIC versions$SUBST(1,"Q",", Q")/

        matchtext = data[len("match") + 1:]
        directive = self.parse_directive_syntax(matchtext)

        pattern, versioninfo = directive.get('directive_str').split(
            directive.get('delimiter'), 1)

        # Optimizing
        try:
            pattern_compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
        except Exception as err:
            pattern_compiled = ''

        record = {
            "service": directive.get('directive_name'),
            "pattern": pattern,
            "pattern_compiled": pattern_compiled,
            "versioninfo": versioninfo
        }

        return record

    def get_softmatch(self, data):
        # Syntax: softmatch <service> <pattern>
        matchtext = data[len("softmatch") + 1:]
        directive = self.parse_directive_syntax(matchtext)
        pattern, _ = directive.get('directive_str').split(
            directive.get('delimiter'), 1)

        # Optimizing
        try:
            pattern_compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
        except Exception as err:
            pattern_compiled = ''

        record = {
            "service": directive.get('directive_name'),
            "pattern": pattern,
            "pattern_compiled": pattern_compiled
        }

        return record

    def get_ports(self, data):
        # Syntax: ports <portlist>
        ports = data[len("ports") + 1:]
        record = {
            "ports": ports
        }

        return record

    def get_ssloirts(self, data):
        # Syntax: sslports <portlist>
        sslports = data[len("sslports") + 1:]
        record = {
            "sslports": sslports
        }

        return record

    def get_totalwaitms(self, data):
        # Syntax: totalwaitms <milliseconds>
        totalwaitms = data[len("totalwaitms") + 1:]
        record =  {
            "totalwaitms": totalwaitms
        }

        return record

    def get_tcpwrappedms(self, data):
        # Syntax: tcpwrappedms <milliseconds>
        tcpwrappedms = data[len("tcpwrappedms") + 1:]
        record =  {
            "tcpwrappedms": tcpwrappedms
        }

        return record

    def get_rarity(self, data):
        # Syntax: rarity <value between 1 and 9>
                # Syntax: tcpwrappedms <milliseconds>
        rarity = data[len("rarity") + 1:]
        record =  {
            "rarity": rarity
        }

        return record

    def get_fallback(self, data):
        # Syntax: fallback <Comma separated list of probes>
        fallback = data[len("fallback") + 1:]
        record =  {
            "fallback": fallback
        }

        return record


class ServiceScan(ServiceProbe):

    def __init__(self, filename):
        self.allprobes = self.parse_nmap_service_probe_file(filename)

    def scan(self, host, port, protocol):

        # Probe TCP NULL  : default, True
        # Included Probes : default, True
        # Excluded Probes : default, False

        nmap_fingerprint = {}

        in_probes, ex_probes = self.filter_probes_by_port(port, self.allprobes)

        # print("al_probes", len(self.allprobes))
        # print("in_probes", len(in_probes))
        # print("ex_probes", len(ex_probes))

        if NMAP_ENABLE_PROBE_INCLUED and in_probes:
            # Sorted by rarity
            probes = self.sort_probes_by_rarity(in_probes)
            nmap_fingerprint = self.scan_with_probes(
                host, port, protocol, probes
            )

        # If included probes get finger, func exits.
        if nmap_fingerprint: return nmap_fingerprint

        if NMAP_ENABLE_PROBE_EXCLUED and ex_probes:
            nmap_fingerprint = self.scan_with_probes(
                host, port, protocol, ex_probes
            )

        return nmap_fingerprint

    def scan_with_probes(self, host, port, protocol, probes):
        """Send every probe in probes to specify port.
        """
        nmap_fingerprint = {}

        for probe in probes:
            record = self.send_probestring_request(
                host, port, protocol, probe, SOCKET_TIMEOUT
            )
            if bool(record["match"]["versioninfo"]):
                nmap_fingerprint = record
                break

        return nmap_fingerprint

    def send_probestring_request(self, host, port, protocol, probe, timeout):
        """Send request(s) based on nmap probestring(s)
        """
        proto = probe['probe']['protocol']
        payload = probe['probe']['probestring']
        payload, _ = codecs.escape_decode(payload)

        response = ""
        # protocol must be match nmap probe protocol
        if (proto.upper() == protocol.upper()):

            if (protocol.upper() == "TCP"):
                response = self.send_tcp_request(host, port, payload, timeout)
            elif (protocol.upper() == "UDP"):
                response = self.send_udp_request(host, port, payload, timeout)

        nmap_pattern, nmap_fingerprint = self.match_probe_pattern(response, probe)
        record = {
            "probe": {
                "probename": probe["probe"]["probename"],
                "probestring": probe["probe"]["probestring"]
            },
            "match": {
                "pattern": nmap_pattern,
                "versioninfo": nmap_fingerprint
            }
        }

        return record

    def send_tcp_request(self, host, port, payload, timeout):
        """Send tcp payloads by port number.
        """

        data = ''
        try:
            with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as client:
                client.settimeout(timeout)
                client.connect((host, int(port)))
                client.send(payload)
                while True:
                    _ = client.recv(SOCKET_READ_BUFFERSIZE)
                    if not _: break
                    data += _
        except Exception as err:
            log.exception("{} : {} - {}".format(host, port, err))

        return data

    def send_udp_request(self, host, port, payload, timeout):
        """Send udp payloads by port number.
        """
        data = ''
        try:
            with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as client:
                client.settimeout(timeout)
                client.sendto(payload, (host, port))
                while True:
                    _, addr = client.recvfrom(SOCKET_READ_BUFFERSIZE)
                    if not _: break
                    data += _
        except Exception as err:
            log.exception("{} : {} - {}".format(host, port, err))

        return data

    def match_probe_pattern(self, data, probe):
        """Match tcp/udp response based on nmap probe pattern.
        """
        nmap_pattern, nmap_fingerprint = "", {}

        if not data:
            return nmap_pattern, nmap_fingerprint

        try:
            matches = probe['matches']

            for match in matches:
                pattern = match['pattern']
                pattern_compiled = match['pattern_compiled']
                service = match['service']

                # https://github.com/nmap/nmap/blob/master/service_scan.cc#L476
                # regex = re.compile(pattern, re.IGNORECASE | re.DOTALL)

                rfind = pattern_compiled.findall(data)

                if rfind and ("versioninfo" in match):
                    versioninfo = match['versioninfo']

                    rfind = [rfind] if isinstance(rfind, str) else rfind[0]
                    for index, value in enumerate(rfind):
                        dollar_name = "${}".format(index + 1)

                        versioninfo = versioninfo.replace(dollar_name, value)

                    nmap_pattern = pattern
                    nmap_fingerprint = self.match_versioninfo(versioninfo)
                    break
        except Exception as err:
            log.exception("{}".format(err))

        return nmap_pattern, nmap_fingerprint

    def match_versioninfo(self, versioninfo):
        """Match Nmap versioninfo
        """
        # p/vendorproductname/
        # v/version/
        # i/info/
        # h/hostname/
        # o/operatingsystem/
        # d/devicetype/
        # cpe:/cpename/[a]

        # p/SimpleHTTPServer/ v/0.6/ i/Python 3.6.0/ cpe:/a:python:python:3.6.0/ cpe:/a:python:simplehttpserver:0.6/
        # p/Postfix smtpd/ cpe:/a:postfix:postfix/a
        # s
        # s p/TLSv1/
        # p/Postfix smtpd/ cpe:/a:postfix:postfix/a

        record = {
            "vendorproductname": [],
            "version": [],
            "info": [],
            "hostname": [],
            "operatingsystem": [],
            "cpename": []
        }

        if "p/" in versioninfo:
            regex = re.compile(r"p/([^/]*)/")
            vendorproductname = regex.findall(versioninfo)
            record["vendorproductname"] = vendorproductname

        if "v/" in versioninfo:
            regex = re.compile(r"v/([^/]*)/")
            version = regex.findall(versioninfo)
            record["version"] = version

        if "i/" in versioninfo:
            regex = re.compile(r"i/([^/]*)/")
            info = regex.findall(versioninfo)
            record["info"] = info

        if "h/" in versioninfo:
            regex = re.compile(r"h/([^/]*)/")
            hostname = regex.findall(versioninfo)
            record["hostname"] = hostname

        if "o/" in versioninfo:
            regex = re.compile(r"o/([^/]*)/")
            operatingsystem = regex.findall(versioninfo)
            record["operatingsystem"] = operatingsystem

        if "d/" in versioninfo:
            regex = re.compile(r"d/([^/]*)/")
            devicetype = regex.findall(versioninfo)
            record["devicetype"] = devicetype

        if "cpe:/" in versioninfo:
            regex = re.compile(r"cpe:/a:([^/]*)/")
            cpename = regex.findall(versioninfo)
            record["cpename"] = cpename

        return record

    def sort_probes_by_rarity(self, probes):
        """Sorts by rarity
        """
        newlist = sorted(probes, key=lambda k: k['rarity']['rarity'])
        return newlist

    def filter_probes_by_port(self, port, probes):
        """select probes by a port condition
        """
        # {'match': {'pattern': '^LO_SERVER_VALIDATING_PIN\\n$',
        #            'service': 'impress-remote',
        #            'versioninfo': ' p/LibreOffice Impress remote/ '
        #                           'cpe:/a:libreoffice:libreoffice/'},
        #  'ports': {'ports': '1599'},
        #  'probe': {'probename': 'LibreOfficeImpressSCPair',
        #            'probestring': 'LO_SERVER_CLIENT_PAIR\\nNmap\\n0000\\n\\n',
        #            'protocol': 'TCP'},
        #  'rarity': {'rarity': '9'}}

        included = []
        excluded = []

        for probe in probes:
            if "ports" in probe:
                ports = probe['ports']['ports']
                if self.is_port_in_range(port, ports):
                    included.append(probe)
                else: # exclude ports
                    excluded.append(probe)

            elif "sslports" in probe:
                sslports = probe['sslports']['sslports']
                if self.is_port_in_range(port, sslports):
                    included.append(probe)
                else: # exclude sslports
                    excluded.append(probe)

            else:  # no [ports, sslports] settings
                excluded.append(probe)

        return included, excluded

    def is_port_in_range(self, port, nmap_port_rule):
        """Check port if is in nmap port range
        """
        bret = False

        ports = nmap_port_rule.split(',')  # split into serval string parts
        if str(port) in ports:
            bret = True
        else:
            for nmap_port in ports:
                if "-" in nmap_port:
                    s, e = nmap_port.split('-')
                    if int(port) in range(int(s), int(e)):
                        bret = True

        return bret


if __name__ == "__main__":
    from pprint import pprint

    nmap = ServiceScan("./nmap-service-probes")
    data = nmap.scan("www.gnu.org", 80, "tcp")
    pprint(data)
