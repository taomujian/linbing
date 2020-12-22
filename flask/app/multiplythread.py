#/usr/bin/python3

import os
import time
import sched
import asyncio
import functools
import threading
import importlib
from app.lib.utils.scan import Port_Scan
from app.oneforall.oneforall import OneForAll
from concurrent.futures import ThreadPoolExecutor

class Multiply_Thread():
    def __init__(self, mysqldb, aes_crypto):
        self.port_scan = Port_Scan(mysqldb, aes_crypto)
        self.mysqldb = mysqldb
        self.aes_crypto = aes_crypto
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

    async def coroutine_execution(self, function, loop, semaphore, kwargs, ip_port, plugin_name):
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
                    if not self.mysqldb.get_vulnerability(kwargs['username'], kwargs['target'], self.aes_crypto.encrypt(ip_port), self.aes_crypto.encrypt(plugin_name)):
                        self.mysqldb.save_vulnerability(kwargs['username'], kwargs['target'], self.aes_crypto.encrypt(plugin_name), self.aes_crypto.encrypt(ip_port), self.aes_crypto.encrypt(plugin_name), self.aes_crypto.encrypt(plugin_name))
                    else:
                        self.mysqldb.update_vulnerability(kwargs['username'], kwargs['target'], self.aes_crypto.encrypt(ip_port), self.aes_crypto.encrypt(plugin_name))
                    
                    self.mysqldb.update_target_vulnernumber(kwargs['username'], kwargs['target'])
                else:
                    pass
            except Exception as e:
                #print(e)
                pass
            
    def sub_domain(self, username, target, description, domain):
        """
        调用oneforall爆破子域名
        
        :param str username: 用户名
        :param str targer: 目标
        :param str description: 目标描述
        :param str domain: 要爆破的域名
        :return:
        """

        oneforall = OneForAll(domain)
        datas = oneforall.run()
        data_set = set()
        for domain in datas:
            data_set.add((domain['subdomain'], domain['ip']))
        for data in data_set:
            self.mysqldb.save_target_domain(username, target, description, self.aes_crypto.encrypt(data[0]), self.aes_crypto.encrypt(data[1]))
            #print(domain['alive'])
            #print(domain['port'])
            #print(domain['cdn'])
            #print(domain['title'])
            #print(domain['banner'])

    def run(self, *args, **kwargs):
        scan_set = self.mysqldb.get_scan(kwargs['username'], kwargs['target'])
        if kwargs['domain']:
            self.mysqldb.update_scan(kwargs['username'], kwargs['target'], '开始子域名检测')
            self.sub_domain(kwargs['username'], kwargs['target'], kwargs['description'], kwargs['domain'][0])
        if scan_set['scanner'] == 'nmap':
            scan_list = self.port_scan.nmap_scan(kwargs['username'], kwargs['target'], kwargs['description'], kwargs['scan_ip'], scan_set['min_port'], scan_set['max_port'])
        else:
            scan_list = self.port_scan.masscan_scan(kwargs['username'], kwargs['target'], kwargs['description'], kwargs['scan_ip'], scan_set['min_port'], scan_set['max_port'], scan_set['rate'])
        self.mysqldb.update_scan(kwargs['username'], kwargs['target'], '开始POC检测')
        # scan_list = ['127.0.0.1:7001']
        new_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_loop)
        semaphore = asyncio.Semaphore(int(scan_set['concurren_number']))
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
                                if item == 'Weblogic':
                                    future = asyncio.ensure_future(self.coroutine_execution(get_class, loop, semaphore, kwargs, ip_port, plugin_name))
                                    tasks.append(future)
                                else:
                                    pass
                            except Exception as e:
                                print(e)
                                pass
                        else:
                            continue

        loop.run_until_complete(asyncio.wait(tasks))
        self.mysqldb.update_scan(kwargs['username'], kwargs['target'], '扫描结束')

if __name__ == '__main__':
    multiply_thread = Multiply_Thread()
    data = {
        'username': '127.0.0.1',
        'target': 'http://baidu.com'
    }
    multiply_thread.async_exe(multiply_thread.run, (), data)