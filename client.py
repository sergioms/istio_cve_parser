import requests
from bs4 import BeautifulSoup

import utils

ISTIO_VULNS_URL = 'https://istio.io/news/security/'


def retrieve_cve_nvd(cve: str):
    nvd_api_url = f'https://services.nvd.nist.gov/rest/json/cve/1.0/{cve.strip()}'
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
    """
    Retrieves list of advisories from main istio advisory page (see ISTIO_VULNS_URL)
    :return: list of tuples, where each tuple contains link to the specific advisory page and
    an array of range versions the advisory applies to:
    [(link_to_adv_page, [version_ranges])]
    Eg:
    [
        ('https://istio.io/news/security/istio-security-2020-004/', ['1.4 to 1.4.6', '1.5']),
        ('https://istio.io/news/security/istio-security-2020-003/', ['1.4 to 1.4.5'])
    ]
    """
    istio_advisories_html = requests.get(ISTIO_VULNS_URL, verify=True).text
    soup = BeautifulSoup(istio_advisories_html, 'html.parser')
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
    istio_advisory_html = requests.get(advisory_url, verify=True).text
    soup = BeautifulSoup(istio_advisory_html, 'html.parser')
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


if __name__ == '__main__':
    advisory_links = retrieve_istio_sec_advisories()
    print(f'Advisory links {advisory_links}')
    applicable_adv = utils.filter_not_applicable_advisories("1.4.6", advisory_links)
    print(f'Found {len(applicable_adv)} advisories')
    cves = []
    for adv in applicable_adv:
        print(f'Advisory {adv}')
        cves.extend(retrieve_cve_from_advisory_page(adv))
        print(f'CVEs found {", ".join(cves)}')
    for cve in cves:
        retrieve_cve_nvd(cve)
