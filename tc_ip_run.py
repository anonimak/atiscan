#!/usr/bin/python

import requests
import json
import sys
import asyncio
import aiohttp

class ThreatcrowdScan:
    
    def __init__(self, p=''):
        self.p = p
        self.url = "https://www.threatcrowd.org/searchApi/v2/"
    	self.proxies = {
        	"http":"http://10.190.45.11:8080",
            "https":"http://10.190.45.11:8080"
        }
        
        loop = asyncio.get_event_loop()
        loop.run_until_complete(run())

    def domains(self):
        url = self.url+"ip/report/?ip="+self.p
        self.search(url)

    def search(self, url):
        
        try:
            response = requests.get(url, proxies=self.proxies)
            data =response.json()

            msg = "secure"
            malicious_status = False

            if data["votes"] <= 0:
                msg = "is malicious"
                malicious_status = True

            j = {
                "response_code":data["response_code"],
                "malicious_status":malicious_status,
                "msg":msg,
                "votes":data["votes"],
                "permalink":data["permalink"],
                "resolutions":data["resolutions"]
            }
            print(json.dumps(j))
        except requests.exceptions.RequestException as e:
            print e
    
    def searchdomain(self,url):
        
    
def main():
    threatcrowdip = ThreatcrowdScan(sys.argv[1])
    threatcrowdip.run()

if __name__ == '__main__':
    main()
