
# Nmap Vscan #

Let's finish Service and Application Version Detection without [**Nmap**](https://nmap.org/) installation.


```python
>>> from nmap_vscan import vscan
>>> nmap = vscan.ServiceScan('./nmap-service-probes')
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

## Installation ##

```python
pip install nmap_vscan
```


## References

- https://nmap.org/book/vscan.html
- https://nmap.org/book/vscan-fileformat.html
- https://github.com/nmap/nmap/blob/master/service_scan.cc