#!/usr/bin/env python3

'''
name: Hadoop 未授权访问漏洞
description: Hadoop 未授权访问漏洞
'''

from app.lib.utils.request import request


class Hadoop_Unauthorized_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0'
        }

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            req = request.get(self.url + '/cluster/cluster', headers = self.headers)
            if "hbase" in req.text or "url=/rs-status" in req.text or "hadoop" in req.text:
                print('存在Hadoop 未授权访问漏洞')
                return True
            else:
                print('不存在Hadoop 未授权访问漏洞')
                return False
        except Exception as e:
            print(e)
            print('不存在Hadoop 未授权访问漏洞')
            return False
        finally:
            pass

if  __name__ == "__main__":
    Hadoop_Unauthorized = Hadoop_Unauthorized_BaseVerify('http://baidu.com')
    Hadoop_Unauthorized.run()