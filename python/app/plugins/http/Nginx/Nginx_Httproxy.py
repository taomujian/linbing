#!/usr/bin/env python3

import re
from app.lib.utils.request import request
from app.lib.utils.common import get_useragent

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

    def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        url = "http://www.net.cn/static/customercare/yourip.asp"
        try:
            local_req = request.get(url)
            pattern = re.compile('<h2>(.*?)</h2')
            local_ip = re.findall(pattern, local_req.text)[0]
            proxies = {
                'http': self.url
            }
            proxy_req = request.get(url, proxies = proxies)
            proxy_ip = re.findall(pattern, proxy_req.text)[0]
            if local_ip != proxy_ip:
                print('存在Nginx反向代理可访问内网漏洞')
            else:
                print('不存在Nginx反向代理可访问内网漏洞')
        except Exception as e:
            print('不存在Nginx反向代理可访问内网漏洞')
            print(e)
            return False
        finally:
            pass

if __name__ == '__main__':
    Nginx_httproxy = Nginx_Httproxy_BaseVerify('http://127.0.0.1')
    Nginx_httproxy.check()
