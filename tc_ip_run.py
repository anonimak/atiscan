#!/usr/bin/python

import requests
import json
import sys


class ThreatcrowdScanIp:

    array_domain = []

    def __init__(self, ip=''):
        self.p = ip
        self.url = "https://www.threatcrowd.org/searchApi/v2/ip/report/?ip="+self.p
        self.url_domain = "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain="
        self.proxies = {
            "http": "http://10.190.45.11:8080",
            "https": "http://10.190.45.11:8080"
        }

    def run(self):
        response_url = self.search(self.url)
        data = response_url.json()
        for resolution in data["resolutions"]:
            url = self.url_domain+resolution["domain"]
            data_domain = self.search(url)
            res = data_domain.json()
            votes = res["votes"]

            if votes <= 0:
                self.array_domain.append(votes)
            pass

        msg = "secure"
        malicious_status = False

        if self.array_domain:
            msg = "is malicious"
            malicious_status = True

        j = {
            "response_code": data["response_code"],
            "malicious_status": malicious_status,
            "msg": msg,
            "votes": data["votes"],
            "permalink": data["permalink"],
            "resolutions": data["resolutions"]
        }

        print(json.dumps(j))

    def search(self, url):
        response = requests.get(url, proxies=self.proxies)
        return response


def main():
    tc = ThreatcrowdScanIp(ip=sys.argv[1])
    tc.run()


if __name__ == '__main__':
    main()
