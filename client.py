import requests

import utils
import istio_advisory_parser


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


if __name__ == '__main__':
    advisory_links = istio_advisory_parser.retrieve_istio_sec_advisories()
    print(f'Advisory links {advisory_links}')
    applicable_adv = utils.filter_not_applicable_advisories("1.4.6", advisory_links)
    print(f'Found {len(applicable_adv)} advisories')
    cves = []
    for adv in applicable_adv:
        print(f'Advisory {adv}')
        cves.extend(istio_advisory_parser.retrieve_cve_from_advisory_page(adv))
        print(f'CVEs found {", ".join(cves)}')
    for cve in cves:
        retrieve_cve_nvd(cve)
