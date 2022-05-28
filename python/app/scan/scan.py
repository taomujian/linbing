#/usr/bin/python3

import os
import re
import time
import asyncio
import importlib
from urllib.parse import urlparse
from app.lib.common import get_live
from app.scan.port_scan import Port_Scan
from app.utils.finger import WhatCms, Fofa_Scanner
from app.thirdparty.oneforall.oneforall import OneForAll
from app.thirdparty.dirsearch.dirsearch import Program
from concurrent.futures import ThreadPoolExecutor

class Scan:
    def __init__(self, mysqldb):
        self.port_scan = Port_Scan(mysqldb)
        self.mysqldb = mysqldb
        self.plugin_path = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))),"plugins")
        if not os.path.isdir(self.plugin_path):
            raise EnvironmentError
        self.finger_list = ['memcached', 'mysql', 'mongod', 'mongodb', 'redis', 'oracle-tns', 'zookeeper', 'ms-sql-s', 'postgresql', 'java-rmi' ]

    def sub_domain(self, username, target, domain, scan_id):

        """
        调用oneforall爆破子域名
        
        :param: str username: 用户名
        :param: str targer: 目标
        :param: str domain: 要爆破的域名
        :param: str scan_id: 扫描id

        :return: list ip_list: 查找到子域名的IP列表
        """

        try:
            ip_list = set()
            oneforall = OneForAll(domain)
            datas = oneforall.run()
            data_set = set()
            if datas:
                for domain in datas:
                    data_set.add((domain['subdomain'], domain['ip']))
                    for ip in domain['ip'].split(','):
                        ip_list.add(ip)
                for data in data_set:
                    self.mysqldb.save_target_domain(username, target, scan_id, data[0], data[1])
        except Exception as e:
            # print(e)
            pass
        finally:
            ip_list = list(ip_list)
            return ip_list

    def dir_scan(self, username, target, url, scan_id):

        """
        调用dirsearch爆破目录,查找后台
        
        :param: str username: 用户名
        :param: str targer: 目标
        :param: str scan_id: 扫描id
        :param: str url: 要爆破的url

        :return:
        """
        
        try:
            path_scan = Program(url)
            for item in path_scan.result:
                path = item[0]
                status = item[1]
                if 'http' in path:
                    url_parse = urlparse(path)
                    url_header = url_parse.scheme + '://' + url_parse.netloc
                    path = path.replace(url_header, '')
                self.mysqldb.save_target_path(username, target, scan_id, path, str(status))
        except Exception as e:
            # print(e)
            pass
        finally:
            pass
    
    async def coroutine_execution(self, function, semaphore, username, target, ip_port, scan_id):

        """
        多协程执行方法
        
        :param: str function: 待执行方法
        :param: str semaphore: 协程并发数量
        :param dict kwargs: kwargs参数,方便与数据库联动,保存到数据库
        :param: str ip_port: 目标的ip和端口,方便与数据库联动,保存到数据库
        :param: str plugin_name: 插件的名字,方便与数据库联动,保存到数据库
        :return:
        """

        async with semaphore:
            try:
                result = await function.check()
                if result:
                    self.mysqldb.save_target_vulner(username, target, scan_id, ip_port, function.info['name'], function.info['description'])
                    self.mysqldb.save_vulner(username, target, ip_port, function.info['name'], function.info['description'])
            except Exception as e:
                # print(e)
                pass
            
    async def poc_scan(self, username, target, scan_id, scan_list, concurren_number, scan_option):
        
        """
        加载POC插件去扫描
        
        :param: str username: 用户名
        :param: str targer: 目标
        :param: str scan_id: 扫描id
        :param: list scan_list: 扫描的目标列表
        :param: str url: 要爆破的url
        :param: int concurren_number: 并发数量
        :param: object loop: loop对象
        :param: list loop: scan_option

        :return:
        """
        
        executor = ThreadPoolExecutor(500)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop = asyncio.get_running_loop()
        loop.set_default_executor(executor)
        semaphore = asyncio.Semaphore(concurren_number)

        for ip_port in scan_list:
            print('开始POC扫描: ', ip_port)
            tasks = []
            port_result = {'finger': '', 'protocol': ''}
            if 'http' in ip_port:
                items = os.listdir(self.plugin_path + '/http')
                path = self.plugin_path + '/http/'
            else:
                items = os.listdir(self.plugin_path + '/port')
                path = self.plugin_path + '/port/'
                
            port_result = self.mysqldb.get_target_port(username, target, ip_port.split(':')[-1])
            poc_path_list = []
            for item in items:
                if port_result and port_result['finger']:
                    if item.lower() in port_result['finger'].lower():
                        poc_path = os.path.join(path + item)
                        poc_path_list.append(poc_path)
                        break

                elif port_result and port_result['protocol']:
                    if port_result['protocol'].lower() in self.finger_list:
                        if port_result['protocol'].lower() == 'mongod' or port_result['protocol'].lower() == 'mongodb':
                            poc_path = os.path.join(path + 'Mongodb')
                            poc_path_list.append(poc_path)
                            break
                        elif port_result['protocol'].lower() == 'ms-sql-s':
                            poc_path = os.path.join(path + 'Mssql')
                            poc_path_list.append(poc_path)
                            break
                        elif port_result['protocol'].lower() == 'oracle-tns':
                            poc_path = os.path.join(path + 'Oracle')
                            poc_path_list.append(poc_path)
                            break
                        elif port_result['protocol'].lower() == 'java-rmi':
                            poc_path = os.path.join(path + 'Javarmi')
                            poc_path_list.append(poc_path)
                            break
                        elif port_result['protocol'].lower() == 'mysql':
                            poc_path = os.path.join(path + 'Mysql')
                            poc_path_list.append(poc_path)
                            break
                        elif port_result['protocol'].lower() == 'memcached':
                            poc_path = os.path.join(path + 'Memcached')
                            poc_path_list.append(poc_path)
                            break
                        elif port_result['protocol'].lower() == 'redis':
                            poc_path = os.path.join(path + 'Redis')
                            poc_path_list.append(poc_path)
                            break
                        elif port_result['protocol'].lower() == 'postgresql':
                            poc_path = os.path.join(path + 'Postgresql')
                            poc_path_list.append(poc_path)
                            break
                        elif port_result['protocol'].lower() == 'zookeeper':
                            poc_path = os.path.join(path + 'Zookeeper')
                            poc_path_list.append(poc_path)
                            break
            
            if not poc_path_list:
                for item in items:
                    poc_path = os.path.join(path + item)
                    poc_path_list.append(poc_path)

            for poc_path in poc_path_list:
                if '.py' not in poc_path:
                    poc_items = os.listdir(poc_path)
                    for poc_item in poc_items:
                        if poc_item.endswith(".py") and not poc_item.startswith('__') and 'ajpy' not in poc_item:
                            plugin_name = poc_item[:-3]
                            if plugin_name in scan_option:
                                if 'http' in ip_port:
                                    module = importlib.import_module('app.plugins.' + 'http' + '.' + poc_path.split('/')[-1] + '.' + plugin_name)
                                else:
                                    module = importlib.import_module('app.plugins.' + 'port' + '.' + poc_path.split('/')[-1] + '.' + plugin_name)
                                try:
                                    class_name = plugin_name + '_BaseVerify'
                                    if 'http' not in ip_port:
                                        url = 'http://' + ip_port
                                    else:
                                        url = ip_port
                                    get_class = getattr(module, class_name)(url)
                                    task = asyncio.create_task(self.coroutine_execution(get_class, semaphore, username, target, ip_port, scan_id))
                                    tasks.append(task)
                                except Exception as e:
                                    # print(e)
                                    pass
                        else:
                            continue

            # await asyncio.gather(*tasks, return_exceptions = True)
            for task in tasks:
                try:
                    await asyncio.wait_for(task, timeout = 15)
                except asyncio.exceptions.TimeoutError as e:
                    pass

            time.sleep(1)

    def run(self, kwargs):
        
        """
        执行入口

        :param: dict kwargs: 参数

        :return:
        """

        scan_set = self.mysqldb.get_scan(kwargs['username'], kwargs['target'])
        ip_result = re.findall(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", kwargs['target'])
        domain_regex = re.compile(r'(?:[A-Z0-9_](?:[A-Z0-9-_]{0,247}[A-Z0-9])?\.)+(?:[A-Z]{2,6}|[A-Z0-9-]{2,}(?<!-))\Z', re.IGNORECASE)
        # domain_result = domain_regex.findall(kwargs['target'])
        scan_option = self.mysqldb.get_scan_option(kwargs['username'], kwargs['scan_id'])
        if scan_option:
            scan_option = scan_option.split(',')
        else:
            scan_option = kwargs['scan_option']
            
        # 目标为ip类型时,不再探测指纹、扫描子域名和目录
        scan_list = []
        ip_list = []
        if kwargs['scan_ip']:
            ip_list.append(kwargs['scan_ip'])
        scan_list.append(kwargs['target'])
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        target = asyncio.run(get_live(kwargs['target'], 3))
        if target and '1' in scan_option and ('http://' in target or 'https://' in target):
            self.mysqldb.update_scan_schedule(kwargs['username'], kwargs['scan_id'], '指纹探测中')
            self.mysqldb.update_target_scan_schedule(kwargs['username'], kwargs['target'], '指纹探测中')

            finger_data = self.mysqldb.all_finger(kwargs['username'])
            cms = Fofa_Scanner(kwargs['target'], finger_data['fofa_cms'])
            fofa_finger = asyncio.run(cms.run())
            cms_name = ''
            for fofa_finger_tmp in fofa_finger:
                if fofa_finger_tmp.lower() in cms.cms_finger_list:
                    cms_name = fofa_finger_tmp
                    self.mysqldb.update_target_finger(kwargs['username'], kwargs['target'], cms_name)
            
            if not cms_name:
                whatcms = WhatCms(kwargs['target'], finger_data['cms'])
                cms_result = asyncio.run(whatcms.run())
                cms_result = list(set(cms_result))
                if cms_result:
                    cms_name = cms_name + '\n' + ''.join(cms_result)
                    self.mysqldb.update_target_finger(kwargs['username'], kwargs['target'], cms_name)
            scan_option.remove('1')
            self.mysqldb.update_scan_option(kwargs['username'], kwargs['scan_id'], ','.join(scan_option))

        if '2' in scan_option and not ip_result:
            if kwargs['domain']:
                self.mysqldb.update_scan_schedule(kwargs['username'], kwargs['scan_id'], '子域名探测中')
                self.mysqldb.update_target_scan_schedule(kwargs['username'], kwargs['target'], '子域名探测中')
                ip_list = ip_list + self.sub_domain(kwargs['username'], kwargs['target'], kwargs['main_domain'], kwargs['scan_id'])
                scan_option.remove('2')
                self.mysqldb.update_scan_option(kwargs['username'], kwargs['scan_id'], ','.join(scan_option))
       
        if kwargs['scan_ip'] and '3' in scan_option:
            self.mysqldb.update_scan_schedule(kwargs['username'], kwargs['scan_id'], '端口扫描中')
            self.mysqldb.update_target_scan_schedule(kwargs['username'], kwargs['target'], '端口扫描中')
            ip_list = list(set(ip_list))
            for ip in ip_list:
                if scan_set['scanner'] == 'nmap':
                    scan_list = scan_list + self.port_scan.nmap_scan(kwargs['username'], kwargs['target'], ip, kwargs['scan_id'], scan_set['nmap_cmd'], scan_set['port'])
                else:
                    scan_list = scan_list + self.port_scan.masscan_scan(kwargs['username'], kwargs['target'], ip, kwargs['scan_id'], scan_set['masscan_cmd'], scan_set['port'], scan_set['rate'])
            if '3' in scan_option:
                scan_option.remove('3')
                self.mysqldb.update_scan_option(kwargs['username'], kwargs['scan_id'], ','.join(scan_option))
        
        scan_list = list(set(scan_list))
        if target and '4' in scan_option and ('http://' in target or 'https://' in target):
            for url in scan_list:
                if url.startswith('http'):
                    self.mysqldb.update_scan_schedule(kwargs['username'], kwargs['scan_id'], '目录扫描中')
                    self.mysqldb.update_target_scan_schedule(kwargs['username'], kwargs['target'], '目录扫描中')
                    self.dir_scan(kwargs['username'], kwargs['target'], url, kwargs['scan_id'])
                    scan_option.remove('4')
                    self.mysqldb.update_scan_option(kwargs['username'], kwargs['scan_id'], ','.join(scan_option))

        if '5' in scan_option and scan_list != '不进行POC检测':
            self.mysqldb.update_scan_schedule(kwargs['username'], kwargs['scan_id'], 'POC扫描中')
            self.mysqldb.update_target_scan_schedule(kwargs['username'], kwargs['target'], 'POC扫描中')
            concurren_number = int(scan_set['concurren_number'])
            asyncio.run(self.poc_scan(kwargs['username'], kwargs['target'], kwargs['scan_id'], scan_list, concurren_number, scan_option))
            scan_option.remove('5')
            self.mysqldb.update_scan_option(kwargs['username'], kwargs['scan_id'], ','.join(scan_option))

        self.mysqldb.update_target_scan_status(kwargs['username'], kwargs['target'], '扫描结束')
        self.mysqldb.update_target_scan_schedule(kwargs['username'], kwargs['target'], '扫描结束')
        self.mysqldb.update_scan_status(kwargs['username'],  kwargs['scan_id'], '扫描结束')
        self.mysqldb.update_scan_schedule(kwargs['username'], kwargs['scan_id'], '扫描结束')