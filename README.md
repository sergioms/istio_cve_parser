# istio_cve_parser
Retrieves published CVEs for provided Istio version. Requires python 3. 

```code 
python client.py <version>
```

Eg,
```code 
python client.py 1.4.6
```


Parses Istio [Security Bulletins](https://istio.io/news/security/) page to find out advisories applicable to provided version and builds a list with the corresponding CVEs. Afterwards, uses [NVD REST API](https://nvd.nist.gov/General/News/New-NVD-CVE-CPE-API-and-SOAP-Retirement) to download the CVE information from the NVD CVE DB. 
