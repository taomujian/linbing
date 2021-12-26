#!/usr/bin/env python3

import ssl
import time
import random
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    # Legacy Python that doesn't verify HTTPS certificates by default
    pass
else:
 # Handle target environment that doesn't support HTTPS verification
 ssl._create_default_https_context = _create_unverified_https_context

class Dnslog:
    def __init__(self):
        self.headers = {
            'User-Agent': self.get_ua()
        }
        self.s = requests.session()
        req = self.s.get("http://www.dnslog.cn/getdomain.php", headers = self.headers, timeout = 10)
        self.domain = req.text
        
    def get_ua(self):
        user_agent_list = [
            'Mozilla/5.0 (Windows; U; Win98; en-US; rv:1.8.1) Gecko/20061010 Firefox/2.0',
            'Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/3.0.195.6 Safari/532.0',
            'Mozilla/5.0 (Windows; U; Windows NT 5.1 ; x64; en-US; rv:1.9.1b2pre) Gecko/20081026 Firefox/3.1b2pre',
            'Opera/10.60 (Windows NT 5.1; U; zh-cn) Presto/2.6.30 Version/10.60','Opera/8.01 (J2ME/MIDP; Opera Mini/2.0.4062; en; U; ssr)',
            'Mozilla/5.0 (Windows; U; Windows NT 5.1; ; rv:1.9.0.14) Gecko/2009082707 Firefox/3.0.14',
            'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
            'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr; rv:1.9.2.4) Gecko/20100523 Firefox/3.6.4 ( .NET CLR 3.5.30729)',
            'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
            'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/533.18.1 (KHTML, like Gecko) Version/5.0.2 Safari/533.18.5'
        ]
        return random.choice(user_agent_list)

    def get_logs(self):
        self.headers = {
            'User-Agent': self.get_ua()
        }
        req = self.s.get("http://www.dnslog.cn/getrecords.php", headers = self.headers,  timeout = 10)
        if req.content.decode() != []:
            return req.json()
        else:
            return None

if __name__ == '__main__':
    dnslog = Dnslog()
    print('获取到的域名为:' + dnslog.domain)
    while True:
        print(dnslog.get_logs())
        time.sleep(10)