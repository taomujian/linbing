#!/usr/bin/env python3

import re
import random
import string
import socket
import tldextract
from IPy import IP
from urllib.parse import urlparse

def get_useragent():
    """
    随机生成一个请求头

    :param:

    :return dict headers: 生成的请求头
    """
    user_agent = [
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
    user_agent = random.choice(user_agent)
    return user_agent

def get_capta():
    capta = ''
    words = ''.join((string.ascii_letters,string.digits))
    for i in range(8):
        capta = capta + random.choice(words)
    return capta

def get_live(url, num):
    """
    确认目标是否存活,尝试访问一定次数后确认目标是否存活

    :param str url: 请求的url
    :param int num: 请求的次数

    :return str result: 判断后的url
    """
        
    for i in range(num):
        UA = get_useragent()
        headers = {
            'User-Agent': UA
        }
        try:
            # 判断没有http协议类型的网站是http还是https,并判断是否存活
            if not url.startswith("http") and not url.startswith("https"):
                url = 'http://' + url
                req = request.get(url, headers = headers, allow_redirects = True)
                if req.status_code == 200:
                    return urlparse(req.url).scheme  + '://' + urlparse(req.url).netloc
            # 并判断目标是否存活
            else:
                req = request.get(url, headers = headers, allow_redirects = True)
                if req.status_code == 200:
                    return urlparse(req.url).scheme  + '://' + urlparse(req.url).netloc
        except Exception as e:
            print(e)
            pass
    return None

def parse_target(target):
    """
    解析目标为ip格式

    :param str target: 待解析的目标

    :return tuple scan_ip: 解析后的ip和域名
    """
    scan_ip = ''
    domain_result = ''
    main_domain = ''
    try:
        url_result = re.findall('https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', target)
        if url_result == []:
            ip_result = re.findall(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", target)
            if ip_result == []:
                result = tldextract.extract(target)
                main_domain = result.domain + '.' + result.suffix
                domain_regex = re.compile(r'(?:[A-Z0-9_](?:[A-Z0-9-_]{0,247}[A-Z0-9])?\.)+(?:[A-Z]{2,6}|[A-Z0-9-]{2,}(?<!-))\Z', re.IGNORECASE)
                domain_result = domain_regex.findall(target)
                if domain_result:
                    scan_ip = socket.gethostbyname(domain_result[0])
                else:
                    net = IP(target)
                    #print(net.len())
                    scan_ip = net
            else:
                scan_ip = ip_result[0]
        else:
            url_parse = urlparse(target)
            result = tldextract.extract(target)
            main_domain = result.domain + '.' + result.suffix
            domain_regex = re.compile(r'(?:[A-Z0-9_](?:[A-Z0-9-_]{0,247}[A-Z0-9])?\.)+(?:[A-Z]{2,6}|[A-Z0-9-]{2,}(?<!-))\Z', re.IGNORECASE)
            domain_result = domain_regex.findall(url_parse.netloc)
            scan_ip = socket.gethostbyname(url_parse.hostname)
    except Exception as e:
        print(e)
    finally:
        pass
    
    if domain_result:
        domain_result = domain_result[0]
    return scan_ip, main_domain, domain_result