from bs4 import BeautifulSoup
import requests

ISTIO_VULNS_URL = 'https://istio.io/news/security/'


def retrieve_istio_sec_advisories(html=None):
    """
    Retrieves list of advisories from main istio advisory page (see ISTIO_VULNS_URL)
    :param html: html content to read (str). If not provided, ISTIO_VULNS_URL retrieved
    :return: list of tuples, where each tuple contains link to the specific advisory page and
    an array of range versions the advisory applies to:
    [(link_to_adv_page, [version_ranges])]
    Eg:
    [
        ('https://istio.io/news/security/istio-security-2020-004/', ['1.4 to 1.4.6', '1.5']),
        ('https://istio.io/news/security/istio-security-2020-003/', ['1.4 to 1.4.5'])
    ]
    """
    istio_advisories_html = html
    if istio_advisories_html is None:
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


def retrieve_cve_from_advisory_page(advisory_url, html=None):
    istio_advisory_html = html
    if advisory_url is not None:
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
