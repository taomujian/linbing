#!/usr/bin/env python3

from urllib.parse import urlparse
from kazoo.client import KazooClient

class Zookeeper_Unauthorized_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Zookeeper 未授权访问漏洞',
            'description': 'Zookeeper 未授权访问漏洞',
            'date': '',
            'exptype': 'check',
            'type': 'Unauthorized'
        }
        self.ip = urlparse(url).hostname
        self.port =urlparse(url).port
        if not self.port:
            self.port = '2181'

    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            zk = KazooClient(hosts='{}:{}'.format(self.ip, self.port), timeout = 3, connection_retry = None )
            zk.start_async
            chidlrens = zk.get_children('/')
            if len(chidlrens) > 0:
                zk.stop()
                return True
        except Exception as e:
            # print(e)
            pass
        finally:
            try:
                zk.stop()
            except:
                pass

if __name__ == '__main__':
    Zookeeper_Unauthorized = Zookeeper_Unauthorized_BaseVerify('https://baidu.com')
    Zookeeper_Unauthorized.check()

