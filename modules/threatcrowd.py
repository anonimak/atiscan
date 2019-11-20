import json
import requests
import config


class ThreatcrowdScan:

    def __init__(self, p='', scan_type=0):
        self.scan_type = scan_type
        self.p = p
        self.url = config.API_SEARCH["threatcrowd"]["api"]

    def run(self):
        if self.scan_type == 0:
            self.domains()
        if self.scan_type == 1:
            self.ips()
        if self.scan_type == 2:
            self.files()

    def domains(self):
        url = self.url+"domain/report/?domain="+self.p
        print(url)
        self.search(url)

    def ips(self):
        url = self.url+"ip/report/?ip="+self.p
        print(url)
        self.search(url)

    def files(self):
        url = self.url+"file/report/?resource="+self.p
        print(url)
        self.search(url)

    def search(self, url):
        response = requests.get(url)

        json_response = response.json()
        print(f'result {self.scan_type}: {json_response}')
        return json_response
