#!/usr/bin/env python3

import re
from app.lib.common import get_useragent
from app.lib.request import request

class Nginx_Httproxy_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Nginx反向代理可访问内网漏洞',
            'description': 'Nginx反向代理可访问内网漏洞,Reference: https://mp.weixin.qq.com/s/EtUmfMxxJjYNl7nIOKkRmA',
            'date': '',
            'exptype': 'check',
            'type': 'Info'
        }
        self.url = url
        self.headers = {
            "User-Agent": get_useragent()
       }

    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        url = "http://www.net.cn/static/customercare/yourip.asp"
        try:
            local_req = await request.get(url)
            pattern = re.compile('<h2>(.*?)</h2')
            local_ip = re.findall(pattern, await local_req.text())[0]
            proxies = {
                'http': self.url
            }
            proxy_req = await request.get(url, proxies = proxies)
            proxy_ip = re.findall(pattern, await proxy_req.text())[0]
            if local_ip != proxy_ip:
                # print('存在Nginx反向代理可访问内网漏洞')
                return True
        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    Nginx_httproxy = Nginx_Httproxy_BaseVerify('http://127.0.0.1')
    Nginx_httproxy.check()
