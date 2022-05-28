#!/usr/bin/env python3

import aiohttp
import configparser

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
    封装aiohttp
    """

    def __init__(self):
        pass
        
    @classmethod
    async def get(self, url, params = None, data = None, json = None, headers = None, proxy = None, cookies = None, verify_ssl = False, allow_redirects = False):
        result = get_conf()
        proxy = result[0]
        timeout = result[1]
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params = params, data = data, json = json, headers = headers, proxy = proxy, cookies = cookies, timeout = timeout, verify_ssl = verify_ssl, allow_redirects = allow_redirects) as response:
                await response.text()
                return response

    @classmethod
    async def post(self, url, params = None, data = None, json = None, headers = None, proxy = None, cookies = None, verify_ssl = False, allow_redirects = False):
        result = get_conf()
        proxy = result[0]
        timeout = result[1]
        async with aiohttp.ClientSession() as session:
            async with session.post(url, params = params, data = data, json = json, headers = headers, proxy = proxy, cookies = cookies, timeout = timeout, verify_ssl = verify_ssl, allow_redirects = allow_redirects) as response:
                await response.text()
                return response

    @classmethod
    async def put(self, url, params = None, data = None, json = None, headers = None, proxy = None, cookies = None, verify_ssl = False, allow_redirects = False):
        result = get_conf()
        proxy = result[0]
        timeout = result[1]
        async with aiohttp.ClientSession() as session:
            async with session.put(url, params = params, data = data, json = json, headers = headers, proxy = proxy, cookies = cookies, timeout = timeout, verify_ssl = verify_ssl, allow_redirects = allow_redirects) as response:
                await response.text()
                return response

    @classmethod
    async def head(self, url, params = None, data = None, json = None, headers = None, proxy = None, cookies = None, verify_ssl = False, allow_redirects = False):
        result = get_conf()
        proxy = result[0]
        timeout = result[1]
        async with aiohttp.ClientSession() as session:
            async with session.head(url, params = params, data = data, json = json, headers = headers, proxy = proxy, cookies = cookies, timeout = timeout, verify_ssl = verify_ssl, allow_redirects = allow_redirects) as response:
                await response.text()
                return response

    @classmethod
    async def patch(self, url, params = None, data = None, json = None, headers = None, proxy = None, cookies = None, verify_ssl = False, allow_redirects = False):
        result = get_conf()
        proxy = result[0]
        timeout = result[1]
        async with aiohttp.ClientSession() as session:
            async with session.patch(url, params = params, data = data, json = json, headers = headers, proxy = proxy, cookies = cookies, timeout = timeout, verify_ssl = verify_ssl, allow_redirects = allow_redirects) as response:
                await response.text()
                return response

    @classmethod
    async def options(self, url, params = None, data = None, json = None, headers = None, proxy = None, cookies = None, verify_ssl = False, allow_redirects = False):
        result = get_conf()
        proxy = result[0]
        timeout = result[1]
        async with aiohttp.ClientSession() as session:
            async with session.options(url, params = params, data = data, json = json, headers = headers, proxy = proxy, cookies = cookies, timeout = timeout, verify_ssl = verify_ssl, allow_redirects = allow_redirects) as response:
                await response.text()
                return response
    
    @classmethod
    async def delete(self, url, params = None, data = None, json = None, headers = None, proxy = None, cookies = None, verify_ssl = False, allow_redirects = False):
        result = get_conf()
        proxy = result[0]
        timeout = result[1]
        async with aiohttp.ClientSession() as session:
            async with session.delete(url, params = params, data = data, json = json, headers = headers, proxy = proxy, cookies = cookies, timeout = timeout, verify_ssl = verify_ssl, allow_redirects = allow_redirects) as response:
                await response.text()
                return response

    @classmethod
    async def request(self, method, url, params = None, data = None, json = None, headers = None, proxy = None, cookies = None, verify_ssl = False, allow_redirects = False):
        result = get_conf()
        proxy = result[0]
        timeout = result[1]
        async with aiohttp.ClientSession() as session:
            async with session.request(url, params = params, data = data, json = json, headers = headers, proxy = proxy, cookies = cookies, timeout = timeout, verify_ssl = verify_ssl, allow_redirects = allow_redirects) as response:
                await response.text()
                return response