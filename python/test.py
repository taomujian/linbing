#/usr/bin/python3

import os
import time
import asyncio
import importlib
from concurrent.futures import ThreadPoolExecutor

class Scan:
    def __init__(self):
        self.plugin_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),"app/plugins")
        if not os.path.isdir(self.plugin_path):
            raise EnvironmentError

    async def coroutine_execution(self, function, semaphore):

        """
        多协程执行方法

        :param: str function: 待执行方法
        :param: str semaphore: 协程并发数量
        :param dict kwargs: kwargs参数,方便与数据库联动,保存到数据库
        :param: str ip_port: 目标的ip和端口,方便与数据库联动,保存到数据库
        :param: str plugin_name: 插件的名字,方便与数据库联动,保存到数据库
        :return:
        """
        
        function_list = []
        async with semaphore:
            try:
                # print('正在运行: ', function)
                function_list.append(function)
                result = await function.check()
                if result:
                    print('存在漏洞:', function, result)
                    function_list.remove(function)
                else:
                    # print('无漏洞: ', function)
                    function_list.remove(function)
            except asyncio.exceptions.TimeoutError as e:
                print('异常: ', function)
                pass

    async def poc_scan(self, concurren_number):
        
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
        # asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        # asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        asyncio.set_event_loop(loop)
        loop = asyncio.get_running_loop()
        loop.set_default_executor(executor)

        semaphore = asyncio.Semaphore(concurren_number)
        scan_list = ['http://127.0.0.1:7001', 'http://127.0.0.1:8080']
        for ip_port in scan_list:
            tasks = []
            if 'http' in ip_port:
                items = os.listdir(self.plugin_path + '/http')
                path = self.plugin_path + '/http/'
            else:
                items = os.listdir(self.plugin_path + '/port')
                path = self.plugin_path + '/port/'

            poc_path_list = []
            for item in items:
                poc_path = os.path.join(path + item)
                poc_path_list.append(poc_path)

            for poc_path in poc_path_list:
                if '.py' not in poc_path:
                    poc_items = os.listdir(poc_path)
                    for poc_item in poc_items:
                        if poc_item.endswith(".py") and not poc_item.startswith('__') and 'ajpy' not in poc_item:
                            plugin_name = poc_item[:-3]
                            # if 'Thinkphp' in plugin_name:
                            if plugin_name:
                                # print(plugin_name)
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
                                    task = asyncio.create_task(self.coroutine_execution(get_class, semaphore))
                                    tasks.append(task)
                                except Exception as e:
                                    # print(e)
                                    pass
                        else:
                            continue
            
            await asyncio.gather(*tasks, return_exceptions = True)
            '''
            for task in tasks:
                try:
                    result = await asyncio.wait_for(task, timeout = 5)
                except asyncio.exceptions.TimeoutError as e:
                    print(e, 5)
            '''

    def run(self):
        time_start = time.time()  # 记录开始时间
        concurren_number = 500
        asyncio.run(self.poc_scan(concurren_number))
        time_end = time.time()  # 记录结束时间
        time_sum = time_end - time_start  # 计算的时间差为程序的执行时间，单位为秒/s
        print(time_sum)

if __name__ == '__main__':
    scan = Scan()
    scan.run()