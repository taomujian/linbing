#/usr/bin/python3

import os
import time
import sched
import asyncio
import functools
import threading
import importlib
from urllib.parse import urlparse
from app.lib.utils.port_scan import Port_Scan
from app.oneforall.oneforall import OneForAll
from app.dirsearch.dirsearch import Program
from concurrent.futures import ThreadPoolExecutor

class Multiply_Thread():
    def __init__(self, mysqldb):
        self.port_scan = Port_Scan(mysqldb)
        self.mysqldb = mysqldb
        self.plugin_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),"plugins")
        if not os.path.isdir(self.plugin_path):
            raise EnvironmentError
        self.items = os.listdir(self.plugin_path)

    def async_exe(self, func, args = None, kwargs = None, delay = 0):
        """异步执行方法
        
        :param str func: 待执行方法
        :param str args: 方法args参数
        :param dict kwargs: 方法kwargs参数
        :param str delay: 执行延迟时间
        :return: str thread thread: 执行线程对象
        """
        args = args or ()
        kwargs = kwargs or {}
        def tmp():
            self.run(*args, **kwargs)
        scheduler = sched.scheduler(time.time, time.sleep)
        scheduler.enter(delay, 10, tmp, ())
        thread = threading.Thread(target = scheduler.run)
        thread.start()
        return thread

    async def coroutine_execution(self, function, loop, semaphore, kwargs, ip_port, plugin_name, scan_id):
        """
        多协程执行方法
        
        :param str func: 待执行方法
        :param str loop: loop 对象
        :param str semaphore: 协程并发数量
        :param dict kwargs: kwargs参数,方便与数据库联动,保存到数据库
        :param str ip_port: 目标的ip和端口,方便与数据库联动,保存到数据库
        :param str plugin_name: 插件的名字,方便与数据库联动,保存到数据库
        :return:
        """

        async with semaphore:
            try:
                result = await loop.run_in_executor(None, functools.partial(function.run))
                if result:
                    self.mysqldb.save_target_vulner(kwargs['username'], kwargs['target'], scan_id, ip_port, plugin_name, plugin_name)
                    
                    self.mysqldb.save_vulner(kwargs['username'], kwargs['target'], ip_port + '_' + plugin_name, ip_port, plugin_name, plugin_name)
                else:
                    pass
            except Exception as e:
                #print(e)
                pass
            
    def sub_domain(self, username, target, domain, scan_id):
        """
        调用oneforall爆破子域名
        
        :param str username: 用户名
        :param str targer: 目标
        :param str domain: 要爆破的域名
        :param: str scan_id: 扫描id
        :return:
        """

        oneforall = OneForAll(domain)
        datas = oneforall.run()
        data_set = set()
        for domain in datas:
            data_set.add((domain['subdomain'], domain['ip']))
        for data in data_set:
            self.mysqldb.save_target_domain(username, target, scan_id, data[0], data[1])
    
    def dir_scan(self, username, target, url, scan_id):
        """
        调用dirsearch爆破目录,查找后台
        
        :param str username: 用户名
        :param str targer: 目标
        :param: str scan_id: 扫描id
        :param str url: 要爆破的url

        :return:
        """

        path_scan = Program(url)
        for item in path_scan.result:
            path = item[0]
            status = item[1]
            if 'http' in path:
                url_parse = urlparse(path)
                url_header = url_parse.scheme + '://' + url_parse.netloc
                path = path.replace(url_header, '')
            self.mysqldb.save_target_path(username, target, scan_id, path, str(status))

    def run(self, *args, **kwargs):
        scan_set = self.mysqldb.get_scan(kwargs['username'], kwargs['target'])
        if kwargs['domain']:
            self.mysqldb.update_scan_schedule(kwargs['username'], kwargs['target'], kwargs['scan_id'], '子域名探测中')
            self.mysqldb.update_target_scan_schedule(kwargs['username'], kwargs['target'], '子域名探测中')
            self.sub_domain(kwargs['username'], kwargs['target'], kwargs['main_domain'], kwargs['scan_id'])

        if 'http://' in kwargs['target'] or 'https://' in kwargs['target']:
            self.mysqldb.update_scan_schedule(kwargs['username'], kwargs['target'], kwargs['scan_id'], '目录扫描中')
            self.mysqldb.update_target_scan_schedule(kwargs['username'], kwargs['target'], '目录扫描中')
            self.dir_scan(kwargs['username'], kwargs['target'], kwargs['target'], kwargs['scan_id'])

        self.mysqldb.update_scan_schedule(kwargs['username'], kwargs['target'], kwargs['scan_id'], '端口扫描中')
        self.mysqldb.update_target_scan_schedule(kwargs['username'], kwargs['target'], '端口扫描中')
        if scan_set['scanner'] == 'nmap':
            scan_list = self.port_scan.nmap_scan(kwargs['username'], kwargs['target'], kwargs['scan_ip'], kwargs['scan_id'], scan_set['min_port'], scan_set['max_port'])
        else:
            scan_list = self.port_scan.masscan_scan(kwargs['username'], kwargs['target'], kwargs['scan_ip'], kwargs['scan_id'], scan_set['min_port'], scan_set['max_port'], scan_set['rate'])
        
        self.mysqldb.update_scan_schedule(kwargs['username'], kwargs['target'], kwargs['scan_id'], 'POC扫描中')
        self.mysqldb.update_target_scan_schedule(kwargs['username'], kwargs['target'], 'POC扫描中')
        scan_list = ['127.0.0.1:7001', '127.0.0.1:8001']
        new_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_loop)
        # semaphore = asyncio.Semaphore(int(scan_set['concurren_number']))
        semaphore = asyncio.Semaphore(50)
        tasks = []
        loop = asyncio.get_event_loop()

        for ip_port in scan_list:
            for item in self.items:
                poc_path = os.path.join(self.plugin_path, item)
                if '.py' not in poc_path:
                    poc_items = os.listdir(poc_path)
                    for poc_item in poc_items:
                        if poc_item.endswith(".py") and not poc_item.startswith('__') and 'ajpy' not in poc_item:
                            plugin_name = poc_item[:-3]
                            module = importlib.import_module('app.plugins.' + item + '.' + plugin_name)
                            try:
                                class_name = plugin_name + '_BaseVerify'
                                url = 'http://' + ip_port
                                get_class = getattr(module, class_name)(url)
                                future = asyncio.ensure_future(self.coroutine_execution(get_class, loop, semaphore, kwargs, ip_port, plugin_name, kwargs['scan_id']))
                                tasks.append(future)
                            except Exception as e:
                                print(e)
                                pass
                        else:
                            continue

        loop.run_until_complete(asyncio.wait(tasks))

        self.mysqldb.update_target_scan_status(kwargs['username'], kwargs['target'], '扫描结束')
        self.mysqldb.update_target_scan_schedule(kwargs['username'], kwargs['target'], '扫描结束')                                 
        self.mysqldb.update_scan_status(kwargs['username'], kwargs['target'], kwargs['scan_id'], '扫描结束')
        self.mysqldb.update_scan_schedule(kwargs['username'], kwargs['target'], kwargs['scan_id'], '扫描结束')

if __name__ == '__main__':
    multiply_thread = Multiply_Thread()
    data = {
        'username': '127.0.0.1',
        'target': 'http://baidu.com'
    }
    multiply_thread.async_exe(multiply_thread.run, (), data)