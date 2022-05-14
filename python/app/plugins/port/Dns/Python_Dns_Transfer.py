#!/usr/bin/env python3

import os
import re
import socket
import struct
import random
from urllib.parse import urlparse

class Python_Dns_Transfer_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'DNS域传送漏洞',
            'description': 'DNS域传送漏洞,获取大量域名',
            'date': '',
            'exptype': 'check',
            'type': 'Configure'
        }
        self.url = url
        url_parse = urlparse(self.url)
        self.domain = url_parse.netloc
        self.LEN_QUERY = 0    # Length of Query String
        self.OFFSET = 0    # Response Data offset
        self.TYPES = {
            1: 'A',
            2: 'NS', 
            5: 'CNAME', 
            6: 'SOA',
            12: 'PTR', 
            15: 'MX', 
            16: 'TXT',
            28: 'AAAA', 
            38: 'A6', 
            99: 'SPF'
        }

    def gen_query(self):
        
        """
        生成的数据包

        :param: 生成数据包

        :return str data: 生成的数据包
        """
        
        TRANS_ID = random.randint(1, 65535)       # random ID
        FLAGS = 0
        QDCOUNT = 1
        ANCOUNT = 0
        NSCOUNT = 0
        ARCOUNT = 0
        data = struct.pack(
            '!HHHHHH',
            TRANS_ID, FLAGS,QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
            )
        query = ''.encode('utf-8')
        for label in self.domain.strip().split('.'):
            query += struct.pack('!B', len(label)) + label.lower().encode('utf-8')
        query += '\x00'.encode('utf-8')    # end of domain name
        data += query
        self.LEN_QUERY = len(query)    # length of query section
        q_type = 252    # Type AXFR = 252
        q_class = 1    # CLASS IN
        data += struct.pack('!HH', q_type, q_class)
        data = struct.pack('!H', len(data) ) + data    # first 2 bytes should be length
        return data

    def decode(self, response):
        
        """
        解码内容
        :param str reponse: 要解码的内容

        :return bool True or False: 是否存在漏洞
        """
        
        RCODE = struct.unpack('!H', response[2:4] )[0] & 0b00001111 # last 4 bits is RCODE
        if RCODE == 0:
            # print('存在域传送漏洞')
            anwser_rrs = struct.unpack('!H', response[6:8])[0]
            # print ('总共%d records in total' % anwser_rrs)
            self.OFFSET = 12 + self.LEN_QUERY + 4    # header = 12, type + class = 4
            while self.OFFSET < len(response):
                name_offset = response[self.OFFSET: self.OFFSET + 2]    # 2 bytes
                name_offset = struct.unpack('!H', name_offset)[0]
                if name_offset > 0b1100000000000000:
                    #print(name_offset)
                    #print(name_offset - 0b1100000000000000)
                    #exit(0)
                    name = self.get_name(response, name_offset - 0b1100000000000000, True)
                else:
                    name = self.get_name(response, self.OFFSET)
                type = struct.unpack('!H', response[self.OFFSET: self.OFFSET+2] )[0]
                type = self.TYPES.get(type, '')
                if type != 'A':
                    print(name.ljust(20), type.ljust(10))
                self.OFFSET += 8    # type: 2 bytes, class: 2bytes, time to live: 4 bytes
                data_length = struct.unpack('!H', response[self.OFFSET: self.OFFSET+2] )[0]
                if data_length == 4 and type == 'A':
                    ip = [str(num) for num in struct.unpack('!BBBB', response[self.OFFSET+2: self.OFFSET+6] ) ]
                    print(name.ljust(20), type.ljust(10), '.'.join(ip))
                self.OFFSET += 2 + data_length
            return True, '总共%d records in total' % anwser_rrs

    # is_pointer: an name offset or not
    def get_name(self, response, name_offset, is_pointer = False):
        
        """
        检测是否存在漏洞

        :param str reponse: 响应
        :param int name_offset: 偏移位置
        :param boolean is_pointer: 是否偏移

        :return bool True or False: 是否存在漏洞
        """
        
        labels = []
        #print(name_offset)
        while True:
            num = response[name_offset]
            if num == 0 or num > 128: break    # end with 0b00000000 or 0b1???????
            labels.append(str(response[name_offset + 1: name_offset + 1 + num], encoding='utf-8'))
            name_offset += 1 + num
            if not is_pointer: self.OFFSET += 1 + num
        name = '.'.join(labels)
        self.OFFSET += 2    # 0x00
        return name

    async def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            cmd_res = os.popen('nslookup -type=ns %s' %(self.domain)).read()    # fetch DNS Server List
            dns_servers = re.findall('nameserver = ([\w\.]+)', cmd_res)
            if len(dns_servers) != 0:
                for server in dns_servers:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((server, 53))
                    data = self.gen_query()
                    s.send(data)
                    s.settimeout(2.0)    # In case recv() blocked
                    response = s.recv(4096)
                    res_len = struct.unpack('!H', response[:2])[0]    # Response Content Length
                    while len(response) < res_len:
                        response += s.recv(4096)
                    if self.decode(response[2:]):
                        return True
        except Exception as e:
            # print(e)
            pass
        finally:
            try:
                s.close()
            except:
                pass

if  __name__ == "__main__":
    Python_Dns_Transfer = Python_Dns_Transfer_BaseVerify('http://vulhub.org')
    Python_Dns_Transfer.check()