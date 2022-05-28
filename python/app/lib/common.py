#!/usr/bin/env python3

import re
import shlex
import random
import string
import socket
import tldextract
from urllib.parse import urlparse
from app.lib.request import request

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

    """
    随机生成一个字符串

    :param:

    :return str capta: 随机字符串
    """

    capta = ''
    words = ''.join((string.ascii_letters,string.digits))
    for i in range(8):
        capta = capta + random.choice(words)
    return capta

async def get_live(url, num):
    
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
                req = await request.get(url, headers = headers, allow_redirects = True)
                return req.real_url
            else:
                req = await request.get(url, headers = headers, allow_redirects = True)
                return req.real_url
        except Exception as e:
            # print(e)
            pass

async def get_title(url):
    
    """
    获取网站的title与banner

    :param str url: 目标url

    :return tuple title,banner: 识别的结果
    """

    title = ''
    server = ''
    headers = ''
    body = ''
    try:
        req = await request.get(url, allow_redirects = True, verify_ssl = False)
        content = await req.text()
        response = re.findall('<title>(.*?)</title>', content, re.S)
        if content:
            #将页面解码为utf-8，获取中文标题
            if response:
                title = response[0]
        if 'server' in req.headers.keys():
            server = req.headers['server']
        for key in req.headers.keys():
            value = req.headers[key]
            headers = headers + key + ': ' + value + '\n'
        body = await req.text()
    except Exception as e:
        print(e)
        pass
    finally:
        return title, server, headers, body
    
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
                domain_regex = re.compile(r'(?:[A-Z0-9_](?:[A-Z0-9-_]{0,247}[A-Z0-9])?\.)+(?:[A-Z]{2,6}|[A-Z0-9-]{2,}(?<!-))\Z', re.IGNORECASE)
                domain_result = domain_regex.findall(target)
                if domain_result:
                    scan_ip = socket.gethostbyname(domain_result[0])
                else:
                    scan_ip = target
            else:
                if '/' in target:
                    scan_ip = target
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
        # print(e)
        pass
    finally:
        pass
    
    if domain_result:
        domain_result = domain_result[0]
    return scan_ip, main_domain, domain_result

def filter_str(check_str):
        
    """
    过滤无用字符

    :param str check_str:待过滤的字符串

    :return str temp:过滤后的字符串
    """

    temp = ''
    for i in check_str:
        if i != '\n' and i != '\x00':
            temp = temp + i
    return temp

def parser_cmd(cmd, type = 'string'):
    
    """
    命令解析,将要执行的命令解析为字符串格式,如echo 123 解析为"echo", "123"

    :param str cmd: 待解析的命令
    :param str type: 命令的类型
    :return: cmd_str 解析后的字符串
    """
    cmd = shlex.split(cmd)
    if type == 'string':
        cmd_str = '"' + '","'.join(cmd) + '"'
    elif type == 'xml':
        cmd_str = '<string>' + '</string><string>'.join(cmd) + '</string>'
    else:
        cmd_str = cmd
    return cmd_str

def parser_url(url):
    
    """
    解析出url的域名、端口信息

    :param str url: 待解析的ulr
    :return: parser_url: 解析url后的对象
    """
    data = urlparse(url)
    parser_url = data.scheme + '://' + data.netloc
    return parser_url