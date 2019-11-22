#!/usr/bin/python

import requests
import json
import sys
import asyncio
import aiohttp


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
        self.proxy = "http://10.190.45.11:8080"

        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.main())

    async def fetch(self, session, url):
        async with session.get(url) as response:
            return await response.read()

    async def main(self):
        async with aiohttp.ClientSession() as session:
            data = await self.fetch(session, self.url)
            data_json = json.loads(data)

            async with aiohttp.ClientSession() as session_domain:
                for resolution in data_json["resolutions"]:
                    url = self.url_domain+resolution["domain"]
                    data_domain = await self.fetch(session_domain, url)
                    res = json.loads(data_domain)
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
                    "response_code": data_json["response_code"],
                    "malicious_status": malicious_status,
                    "msg": msg,
                    "votes": data_json["votes"],
                    "permalink": data_json["permalink"],
                    "resolutions": data_json["resolutions"]
                }

                print(json.dumps(j))


def main():
    ThreatcrowdScanIp(ip=sys.argv[1])


if __name__ == '__main__':
    main()
