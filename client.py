import requests
import sys

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


def get_cve_list(istio_version: str):
    advisory_links = istio_advisory_parser.retrieve_istio_sec_advisories()
    applicable_adv = utils.filter_not_applicable_advisories(istio_version, advisory_links)
    cves = []
    for adv in applicable_adv:
        cves.extend(istio_advisory_parser.retrieve_cve_from_advisory_page(adv))
    return cves


if __name__ == '__main__':

    if len(sys.argv) != 2:
        raise ValueError(f'Provide an istio version to check, eg, 1.4.6')

    istio_version = sys.argv[1]
    eol_versions = istio_advisory_parser.retrieve_istio_unsupported_versions()
    if not utils.is_supported_version(istio_version, eol_versions):
        print(f'WARN Version {istio_version} is no longer supported - consider updating to current version')
    cves = get_cve_list(istio_version)
    if len(cves) < 1:
        print(f'No CVEs found cve')
    else:
        print(f'Found cve: {", ".join(cves)}')
        for cve in cves:
            retrieve_cve_nvd(cve)
