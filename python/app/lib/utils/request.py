#!/usr/bin/env python3

import ssl
import random
import requests
import configparser

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

def get_conf():

    """"
    从配置文件中读取代理地址和超时时间

    :param:
    :return tuple result: 代理地址和超时时间
    """
    
    config = configparser.ConfigParser()
    config.read('conf.ini')
    proxy = config.get('request', 'proxy')
    if not config.get('request', 'timeout'):
        timeout = 5
    else:
        timeout = int(config.get('request', 'timeout'))
    if not proxy:
        proxies = None
    else:
        proxies = {
            'http': '%s' %(proxy),
            'https': '%s' %(proxy),
        }
    return proxies, timeout
    
class request:

    """
    封装requests函数
    """

    def __init__(self):
        pass
    
    @classmethod
    def get(cls, url, params = None, data = None, json = None, headers = None, proxies = None, stream = False, files = None, cookies = None, verify = False, allow_redirects = False):
        result = get_conf()
        proxies = result[0]
        timeout = result[1]
        req = requests.get(url, params = params, data = data, json = json, headers = headers, proxies = proxies, stream = stream, files = files, cookies = cookies, timeout = timeout, verify = verify, allow_redirects = allow_redirects)
        return req

    @classmethod
    def post(cls, url, params = None, data = None, json = None, headers = None, proxies = None, stream = False, files = None, cookies = None, verify = False, allow_redirects = False):
        result = get_conf()
        proxies = result[0]
        timeout = result[1]
        req = requests.post(url, params = params, data = data, json = json, headers = headers, proxies = proxies, stream = stream, files = files, cookies = cookies, timeout = timeout, verify = verify, allow_redirects = allow_redirects)
        return req

    @classmethod
    def put(cls, url, params = None, data = None, json = None, headers = None, proxies = None, stream = False, files = None, cookies = None, verify = False, allow_redirects = False):
        result = get_conf()
        proxies = result[0]
        timeout = result[1]
        req = requests.put(url, params = params, data = data, json = json, headers = headers, proxies = proxies, stream = stream, files = files, cookies = cookies, timeout = timeout, verify = verify, allow_redirects = allow_redirects)
        return req

    @classmethod
    def head(cls, url, params = None, data = None, json = None, headers = None, proxies = None, stream = False, files = None, cookies = None, verify = False, allow_redirects = False):
        result = get_conf()
        proxies = result[0]
        timeout = result[1]
        req = requests.head(url, params = params, data = data, json = json, headers = headers, proxies = proxies, stream = stream, files = files, cookies = cookies, timeout = timeout, verify = verify, allow_redirects = allow_redirects)
        return req

    @classmethod
    def patch(cls, url, params = None, data = None, json = None, headers = None, proxies = None, stream = False, files = None, cookies = None, verify = False, allow_redirects = False):
        result = get_conf()
        proxies = result[0]
        timeout = result[1]
        req = requests.patch(url, params = params, data = data, json = json, headers = headers, proxies = proxies, stream = stream, files = files, cookies = cookies, timeout = timeout, verify = verify, allow_redirects = allow_redirects)
        return req

    @classmethod
    def options(cls, url, params = None, data = None, json = None, headers = None, proxies = None, stream = False, files = None, cookies = None, verify = False, allow_redirects = False):
        result = get_conf()
        proxies = result[0]
        timeout = result[1]
        req = requests.options(url, params = params, data = data, json = json, headers = headers, proxies = proxies, stream = stream, files = files, cookies = cookies, timeout = timeout, verify = verify, allow_redirects = allow_redirects)
        return req
    
    @classmethod
    def delete(cls, url, params = None, data = None, json = None, headers = None, proxies = None, stream = False, files = None, cookies = None, verify = False, allow_redirects = False):
        result = get_conf()
        proxies = result[0]
        timeout = result[1]
        req = requests.delete(url, params = params, data = data, json = json, headers = headers, proxies = proxies, stream = stream, files = files, cookies = cookies, timeout = timeout, verify = verify, allow_redirects = allow_redirects)
        return req

    @classmethod
    def request(cls, method, url, params = None, data = None, json = None, headers = None, proxies = None, stream = False, files = None, cookies = None, verify = False, allow_redirects = False):
        result = get_conf()
        proxies = result[0]
        timeout = result[1]
        req = requests.request('MOVE', url, params = params, data = data, json = json, headers = headers, proxies = proxies, stream = stream, files = files, cookies = cookies, timeout = timeout, verify = verify, allow_redirects = allow_redirects)
        return req

class TrickUrlSession(requests.Session):
    def seturl(self, url):
        self.url = url
    def send(self, request, **kwargs):
        if self.url:
            request.url = self.url
        return requests.Session.send(self, request, **kwargs)