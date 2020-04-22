# https://services.nvd.nist.gov/rest/json/cve/1.0/CVE-2015-5611
# https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=cherokee
# To find vulnerabilities for Microsoft Windows 10, use:
# cves/1.0?cpeMatchString=cpe:2.3:o:microsoft:windows_10
# To find vulnerabilities for version 1511 use:
# cves/1.0?cpeMatchString=cpe:2.3:o:microsoft:windows_10:1511
# To find all vulnerabilities associated with anyMicrosoft product, use:
# cves/1.0?cpeMatchString=cpe:2.3:*:microsoft

import requests
import re
from bs4 import BeautifulSoup


def retrieve_cve_nvd(cve: str):
    nvd_api_url = f'https://services.nvd.nist.gov/rest/json/cve/1.0/{cve.strip()}'
    print(f'Sending')
    headers = {'Content-Type': 'application/json'}
    response = requests.get(nvd_api_url, verify=True)
    body = response.json()
    print(f'Response {response.status_code}')
    print(f'CVE Response:\r\n{body}')
    print(f"Total results: {body['totalResults']}")
    print(f"{body['result']['CVE_Items'][0]['cve']['CVE_data_meta']['ID']}")
    print(f"CVE Desc\r\n{body['result']['CVE_Items'][0]['cve']['description']}")
    print(f"CVE Impact\r\n{body['result']['CVE_Items'][0]['impact']}")


def retrieve_istio_sec_advisories():
    ISTIO_VULNS_URL = 'https://istio.io/news/security/'
    istio_vulns_html = requests.get(ISTIO_VULNS_URL, verify=True).text
    soup = BeautifulSoup(istio_vulns_html, 'html.parser')
    rows = soup.find('table').find('tbody').find_all('tr')
    links = []
    versions = []
    for row in rows:
        link = row.find('a', href=True)['href']
        affected_versions = row.find_all('td')[2]
        brs = affected_versions.find_all('br')
        for br in brs:
            br.extract()
        affected_versions = row.find_all('td')[2].contents
        links.append(link)
        versions.append(affected_versions)

    return list(zip(links, versions))


def retrieve_cve_from_advisory_page(advisory_url: str):
    adv_html = requests.get(advisory_url, verify=True).text
    soup = BeautifulSoup(adv_html, 'html.parser')
    rows = soup.find('table').find('tbody').find_all('tr')
    cves = []
    for row in rows:
        columns = row.find_all('td')
        content = "".join(columns[0].contents)
        if content.find('CVE') >= 0:
            cve_col = columns[1]
            brs = cve_col.find_all('br')
            # TODO filter
            for br in brs:
                br.extract()
            cve_links = cve_col.find_all('a')
            for cve_link in cve_links:
                cves.append(cve_link.contents[0])
    return cves


def is_in_version_range(version: str, version_range: str):
    major, minor, _ = norm_version(version)

    if version_range.find(" to ") < 0:
        if norm_version(version) == norm_version(version_range):
            return True
        else:
            return False
    else:
        low, high = version_range.split(" to ")
        if low <= version <= high:
            return True
        else:
            return False


def norm_version(version: str):
    version.strip()
    num_dots = version.count('.')
    if num_dots < 1 or num_dots > 2:
        return None, None, None
    if num_dots == 1:
        version = f'{version}.0'
    x = re.search("([0-9]+?)\.([0-9]+?)\.([0-9]+)", version)
    if x is not None:
        try:
            major = int(x.group(1))
            minor = int(x.group(2))
            build = int(x.group(3))
        except ValueError:
            major = None
            minor = None
            build = None
        return major, minor, build
    # raise Exception
    return None, None, None


def filter_not_applicable_vulns(version: str, advisories: list):
    filtered = []
    for adv_link, affected_versions in advisories:
        for affected_version in affected_versions:
            if is_in_version_range(version, affected_version):
                filtered.append(adv_link)
    return filtered


advisory_links = retrieve_istio_sec_advisories()
applicable_adv = filter_not_applicable_vulns("1.4.6", advisory_links)
print(f'Found {len(applicable_adv)} advisories')
cves = []

for adv in applicable_adv:
    print(f'Advisory {adv}')
    cves.extend(retrieve_cve_from_advisory_page(adv))
print(f'CVEs found {", ".join(cves)}')
for cve in cves:
    retrieve_cve_nvd(cve)
