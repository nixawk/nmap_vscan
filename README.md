
# Nmap Vscan #

Let's finish Service and Application Version Detection without [**Nmap**](https://nmap.org/) installation.


```python
>>> from nmap_vscan import vscan
>>> nmap = vscan.ServiceScan('./nmap-service-probes')
```

```
>>> nmap.scan('www.apache.org', 80, "tcp")

{'match': {'pattern': '^HTTP/1\\.[01] \\d\\d\\d .*\\r\\nServer: Apache[/ ](\\d[-.\\w]+) ([^\\r\\n]+)',
  'versioninfo': {'cpename': ['apache:http_server:2.4.7'],
   'devicetype': [' v'],
   'hostname': [],
   'info': ['(Ubuntu)'],
   'operatingsystem': [],
   'vendorproductname': ['Apache httpd'],
   'version': ['2.4.7']}},
 'probe': {'probename': 'GetRequest',
  'probestring': 'GET / HTTP/1.0\\r\\n\\r\\n'}}
```

```
>>> nmap.scan('192.168.1.245', 3306, 'tcp')

{'match': {'pattern': '^.\\0\\0\\0\\x0a(5\\.[-_~.+\\w]+)\\0',
  'versioninfo': {'cpename': ['mysql:mysql:5.5.28-log'],
   'hostname': [],
   'info': [],
   'operatingsystem': [],
   'vendorproductname': ['MySQL'],
   'version': ['5.5.28-log']}},
 'probe': {'probename': 'NULL', 'probestring': ''}}
```

```
>>> nmap.scan('192.168.1.245', 6379, 'tcp')

{'match': {'pattern': '^\\$\\d+\\r\\n(?:#[^\\r\\n]*\\r\\n)*redis_version:([.\\d]+)\\r\\n',
  'versioninfo': {'cpename': [],
   'hostname': [],
   'info': [],
   'operatingsystem': [],
   'vendorproductname': ['Redis key-value store'],
   'version': ['2.6.12']}},
 'probe': {'probename': 'redis-server',
  'probestring': '*1\\r\\n$4\\r\\ninfo\\r\\n'}}
```

## Installation ##

```python
pip install nmap_vscan
```


## References

- https://nmap.org/book/vscan.html
- https://nmap.org/book/vscan-fileformat.html
- https://github.com/nmap/nmap/blob/master/service_scan.cc