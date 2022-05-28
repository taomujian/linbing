#!/usr/bin/env python3

import os
import time
import sqlite3
import pymysql
import importlib

class Mysql_db:
    def __init__(self, host, port, user, passwd, charset = "utf8"):
        self.host, self.port, self.user, self.passwd, self.charset = host, int(port), user, passwd, charset

    def get_conn(self):
        
        """
        获取一个mysql连接

        :param: str 
        :return conn conn: 获取到的连接
        """
        try:
            conn = pymysql.connect(host = self.host, port = self.port, user = self.user, passwd = self.passwd, db = 'linbing', charset = self.charset)
            conn.autocommit(True)
            return conn
        except Exception as e:
            print(e)
            pass

    def create_database(self, database):
        
        """
        创建数据库

        :param str database: 要创建的数据库名

        :return:
        
        """
    
        sql = "create database if not exists %s character set utf8 collate utf8_general_ci" %(database)
        try:
            conn = pymysql.connect(host = self.host, port = self.port, user = self.user, passwd = self.passwd, charset = self.charset)
            cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
            cursor.execute(sql)
        except Exception as e:
            print(e)
        finally:
            cursor.close()
            conn.close()
    
    def create_cms_finger(self):

        """
        创建保存指纹信息的表

        :param:

        :return:
        
        """
        
        sql = "create table if not exists cms_finger (id integer auto_increment primary key, username varchar(255), cms_type varchar(255), path varchar(255), match_pattern varchar(255), options varchar(255), finger_type varchar(255), time datetime) engine = innodb default charset = utf8;"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
        except Exception as e:
            print(e)
        finally:
            cursor.close()
            self.close_conn
    
    def create_fofa_cms_finger(self):

        """
        创建保存指纹信息的表

        :param:

        :return:
        
        """
        
        sql = "create table if not exists fofa_cms_finger (id integer auto_increment primary key, username varchar(255), fofa_cms_type varchar(255), key_str varchar(255), finger_type varchar(255), time datetime) engine = innodb default charset = utf8;"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
        except Exception as e:
            print(e)
        finally:
            cursor.close()
            self.close_conn
    
    def save_cms_finger(self, username, cms_type, path, match_pattern, options, finger_type):

        """
        保存指纹

        :param: str username: 用户名
        :param: str cms_type: cms类型
        :param: str path: 文件路径
        :param: str match_pattern: 要匹配的字符串
        :param: str options: 匹配模式
        :param: str finger_type: 指纹类型
        
        :return: 'LXXXXX': 状态码
        """

        datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sql =  "insert cms_finger (username, cms_type, path, match_pattern, options, finger_type, time) values (%s, %s, %s, %s, %s, %s, %s)"
        values = [username, cms_type, path, match_pattern, options, finger_type, datetime]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'J1000'
        except Exception as e:
            print(e)
            return 'J1001'
        finally:
            cursor.close()
            self.close_conn
    
    def save_fofa_cms_finger(self, username, fofa_cms_type, key, finger_type):

        """
        保存指纹

        :param: str username: 用户名
        :param: str fofa_cms_type: cms类型
        :param: str key: fofa指纹规则
        :param: str finger_type: 指纹类型
        
        :return: 'LXXXXX': 状态码
        """

        datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sql =  "insert fofa_cms_finger (username, fofa_cms_type, key_str, finger_type, time) values (%s, %s, %s, %s, %s)"
        values = [username, fofa_cms_type, key, finger_type, datetime]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'J1000'
        except Exception as e:
            print(e)
            return 'J1001'
        finally:
            cursor.close()
            self.close_conn

    def init_finger(self, filename):

        """
        从其他指纹库初始化指纹库

        :param: filename:cdn json文件路径
        
        :return: 'LXXXXX': 状态码
        """

        cms_sql =  "select count(0) from cms_finger"
        fofa_sql = "select count(0) from fofa_cms_finger"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(cms_sql)
            count_result = cursor.fetchone()['count(0)']
            if count_result == 0:
                print('start init cms_finger table')
                sqlconn = sqlite3.connect(filename)
                sqlcursor = sqlconn.cursor()
                sqlcursor.execute('select * from cms')
                cms_list = sqlcursor.fetchall()
                sqlcursor.close()
                sqlconn.close()
                for cms in cms_list:
                    self.save_cms_finger('common', cms[1], cms[2], cms[3], cms[4], '通用指纹')
                print('finish init cms_finger table!')

            cursor.execute(fofa_sql)
            count_result = cursor.fetchone()['count(0)']
            if count_result == 0:
                print('start init fofa_cms_finger table')
                sqlconn = sqlite3.connect(filename)
                sqlcursor = sqlconn.cursor()
                sqlcursor.execute('select * from fofa_cms')
                cms_list = sqlcursor.fetchall()
                sqlcursor.close()
                sqlconn.close()
                for cms in cms_list:
                    self.save_fofa_cms_finger('common', cms[1], cms[2], '通用指纹')
                print('finish init fofa_cms_finger table!')
            return 'J1000'
        except Exception as e:
            print(e)
            return 'J1001'
        finally:
            cursor.close()
            self.close_conn
    
    def init_poc(self):
    
        """
        从初始化poc库

        :param:
        
        :return: 'LXXXXX': 状态码
        """

        count_sql =  "select count(0) from poc"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(count_sql)
            count_result = cursor.fetchone()['count(0)']
            if count_result == 0:
                print('start init poc table')
                for item in os.listdir('app/plugins/http'):
                    file_names = os.listdir('app/plugins/http/' + item)
                    for file_name in file_names:
                        if file_name.endswith(".py") and not file_name.startswith('__') and 'ajpy' not in file_name:
                            file_name = file_name[:-3]
                            module = importlib.import_module('app.plugins.' + 'http' + '.' + item + '.' + file_name)
                            class_name = file_name + '_BaseVerify'
                            info = getattr(module, class_name)('http://127.0.0.1').info
                            self.save_poc('admin', info['name'], info['description'], info['date'], info['type'])

                for item in os.listdir('app/plugins/port'):
                    file_names = os.listdir('app/plugins/port/' + item)
                    for file_name in file_names:
                        if file_name.endswith(".py") and not file_name.startswith('__') and 'ajpy' not in file_name:
                            file_name = file_name[:-3]
                            module = importlib.import_module('app.plugins.' + 'port' + '.' + item + '.' + file_name)
                            class_name = file_name + '_BaseVerify'
                            info = getattr(module, class_name)('').info
                            self.save_poc('admin', info['name'], info['description'], info['date'], info['type'])

                print('finish init poc table!')
            return 'J1000'
        except Exception as e:
            print(e)
            return 'J1001'
        finally:
            cursor.close()
            self.close_conn
    
    def all_finger(self, username):
        
        """
        获取所有指纹的信息,无数量限制

        :param: str username: 用户名

        :return: 'LXXXXX': 状态码
        """
        
        cms_sql = "select id, cms_type, path, match_pattern, options, finger_type from cms_finger where (username = %s or username = 'common')"
        fofa_sql = "select id, fofa_cms_type, key_str, finger_type from fofa_cms_finger where (username = %s or username = 'common')"
        values = [username]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(cms_sql, values)
            cms_result = cursor.fetchall()

            cursor.execute(fofa_sql, values)
            fofa_result = cursor.fetchall()
            datas = {
                'cms': cms_result, 
                'fofa_cms': fofa_result 
            }
            return datas
        except Exception as e:
            print(e)
            return 'J1001'
        finally:
            cursor.close()
            self.close_conn

    def create_user(self):
        
        """
        创建用户表

        :param:

        :return:
        
        """

        sql = "create table if not exists user (id integer auto_increment primary key, username varchar(128) unique, description varchar(128), token varchar(128) unique, password varchar(128), role varchar(128), avatar varchar(128), create_time varchar(255)) engine = innodb default charset = utf8;"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
        except Exception as e:
            print(e)
        finally:
            cursor.close()
            self.close_conn
    
    def create_port(self):
        
        """
        创建保存端口信息的表,这个表格只保存最新扫描的端口,而不是保存所有的端口

        :param:

        :return:
        
        """

        sql = "create table if not exists port (id integer auto_increment primary key, username varchar(255), target varchar(255), ip_port varchar(255), scan_time varchar(255), scan_ip varchar(255), port varchar(255), finger varchar(255), product varchar(255), protocol varchar(255), version varchar(255), title varchar(255), banner varchar(255), unique key thekey (username, target, ip_port)) engine = innodb default charset = utf8;"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
        except Exception as e:
            print(e)
        finally:
            cursor.close()
            self.close_conn
    
    def create_vulner(self):
        
        """
        创建保存漏洞信息的表,这个表格只保存最新扫描出的而不是,而不是保存所有的漏洞

        :param:

        :return:
        
        """

        sql = "create table if not exists vulner (id integer auto_increment primary key, username varchar(255), target varchar(255), ip_port_vulner varchar(255) unique key, ip_port varchar(255), vulner_name varchar(255), vulner_descrip longtext, scan_time varchar(255)) engine = innodb default charset = utf8;"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
        except Exception as e:
            print(e)
        finally:
            cursor.close()
            self.close_conn

    def create_target(self):
        
        """
        创建目标表

        :param:

        :return:
        
        """
        sql = "create table if not exists target (id integer auto_increment primary key, username varchar(255), target varchar(255) unique key, description varchar(10000) default '', finger varchar(255) default '', target_ip varchar(255) default '', create_time varchar(255) default '', scan_time varchar(255) default '', scan_status varchar(255) default '未开始', scan_schedule varchar(255) default '未开始', vulner_number varchar(255) default '0', scanner varchar(255) default 'massan', nmap_cmd varchar(255) default '-sS -sV -Pn -T4 --open', masscan_cmd varchar(255) default '-sS -Pn -n --randomize-hosts -v --send-eth --open', port varchar(255) default '1-65535', rate varchar(255) default '5000', concurren_number varchar(255) default '50') engine = innodb default charset = utf8;"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
        except Exception as e:
            print(e)
        finally:
            cursor.close()
            self.close_conn
    
    def create_target_scan(self):
        
        """
        创建目标扫描任务的表

        :param:

        :return:

        """

        sql = "create table if not exists target_scan (id integer auto_increment primary key, username varchar(255), target varchar(255), target_ip varchar(255) default '', scan_id varchar(255) default '', scan_time varchar(255) default '', scan_status varchar(255) default '', scan_schedule varchar(255) default '', scan_option longtext, vulner_number varchar(255) default '0') engine = innodb default charset = utf8;"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
        except Exception as e:
            print(e)
        finally:
            cursor.close()
            self.close_conn

    def create_target_port(self):
        
        """
        创建保存目标、端口等信息的表

        :param:

        :return:
        
        """

        sql = "create table if not exists target_port (id integer auto_increment primary key, username varchar(255), target varchar(255), scan_id varchar(255), scan_ip varchar(255), scan_time varchar(255), port varchar(255), finger varchar(255), product varchar(255), protocol varchar(255), version varchar(255), title varchar(255), banner varchar(255)) engine = innodb default charset = utf8;"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
        except Exception as e:
            print(e)
        finally:
            cursor.close()
            self.close_conn

    def create_target_domain(self):
        
        """
        创建保存目标、域名等信息的表

        :param:

        :return:
        
        """

        sql = "create table if not exists target_domain (id integer auto_increment primary key, username varchar(255), target varchar(255), scan_id varchar(255), scan_time varchar(255), domain varchar(255), domain_ip varchar(255)) engine = innodb default charset = utf8;"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
        except Exception as e:
            print(e)
        finally:
            cursor.close()
            self.close_conn

    def create_target_vulner(self):
        
        """
        创建保存漏洞信息的表

        :param:

        :return:
        
        """

        sql = "create table if not exists target_vulner (id integer auto_increment primary key, username varchar(255), target varchar(255), scan_id varchar(255), ip_port varchar(255), vulner_name varchar(255), vulner_descrip longtext, scan_time varchar(255)) engine = innodb default charset = utf8;"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
        except Exception as e:
            print(e)
        finally:
            cursor.close()
            self.close_conn
    
    def create_target_path(self):
        
        """
        创建保存目标目录信息的表

        :param:

        :return:
        
        """

        sql = "create table if not exists target_path (id integer auto_increment primary key, username varchar(255), target varchar(255), scan_id varchar(255), scan_time varchar(255), path varchar(255), status_code varchar(255)) engine = innodb default charset = utf8;"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
        except Exception as e:
            print(e)
        finally:
            cursor.close()
            self.close_conn
    
    def create_poc(self):
        
        """
        创建保存poc信息的表

        :param:

        :return:
        
        """

        sql = "create table if not exists poc (id integer auto_increment primary key, username varchar(255), poc_name varchar(255), poc_description longtext, time varchar(255), type varchar(255)) engine = innodb default charset = utf8;"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
        except Exception as e:
            print(e)
        finally:
            cursor.close()
            self.close_conn
    
    def create_xss_log(self):
        
        """
        创建保存xss log信息的表

        :param:

        :return:
        
        """

        sql = "create table if not exists xss_log (id integer auto_increment primary key, username varchar(255), url varchar(255), ua varchar(255), data longtext, time varchar(255), ip varchar(255)) engine = innodb default charset = utf8;"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
        except Exception as e:
            print(e)
        finally:
            cursor.close()
            self.close_conn
    
    def create_dns_log(self):
        
        """
        创建保存dns_log信息的表

        :param:

        :return:
        
        """

        sql = "create table if not exists dns_log (id integer auto_increment primary key, username varchar(255), dns_log varchar(255), ip varchar(255), time varchar(255)) engine = innodb default charset = utf8;"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
        except Exception as e:
            print(e)
        finally:
            cursor.close()
            self.close_conn
    
    def create_xss_auth(self):
        
        """
        创建保存xss auth信息的表

        :param:

        :return:
        
        """

        sql = "create table if not exists xss_auth (id integer auto_increment primary key, username varchar(255), token varchar(255), url varchar(255), time varchar(255), token_status varchar(255)) engine = innodb default charset = utf8;"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
        except Exception as e:
            print(e)
        finally:
            cursor.close()
            self.close_conn
    
    def query_account(self, username):
        
        """
        查询用户是否已存在

        :param: str username: 查询的用户名

        :return: str 'LXXXXX': 状态码
        """

        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            # 获取已注册的用户名
            sql = "select * from user where username = %s"
            values = [username]
            cursor.execute(sql, values)
            result = cursor.fetchone()
            if result:
                return 'L1005'
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def query_target(self, username, target):
        
        """
        查询目标是否已存在

        :param: str username: 用户名
        :param: str target: 查询的目标

        :return: str 'LXXXXX': 状态码
        """

        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            target_list = target.split(';')
            for target in target_list:
                sql = "select * from target where username = %s  and target = %s"
                values =  [username, target]
                cursor.execute(sql, values)
                result = cursor.fetchone()
                if result:
                    return 'L1005', target
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def query_password(self, username, password):
        
        """
        查询用户名和密码是否匹配

        :param: str username: 查询字符串
        :param: str password: 查询的密码

        :return: str 'LXXXXX': 状态码
        """

        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            sql = "select * from user where username = %s and password = %s"
            values =  [username, password]
            cursor.execute(sql, values)
            result = cursor.fetchone()
            if not result:
                return 'L1009'
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def login(self, username):
        
        """
        获取用户的密码

        :param: str username: 用户名
        :return: str result: 用户的密码
        """

        sql = "select password, token from user where username = %s"
        values = [username]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values) 
            result = cursor.fetchone()
            return result
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def update_token(self, username, token):
        
        """
        更新用户的token

        :param: str username: 用户名
        :param: str token: 用户凭证
        :return: str 'LXXXXX': 状态码
        """

        sql =  "update user set token = %s where username = %s"
        values = [token, username]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def userinfo(self, token):
        
        """
        获取用户的信息

        :param: str token: 用户凭证
        :return: str result: 用户的信息
        """

        sql = "select username, role, avatar from user where token = %s"
        values = [token]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values) 
            result = cursor.fetchone()
            return result
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def changps(self, username, token, password):
        
        """
        修改用户密码

        :param: str username: 用户名
        :param: str token: 新的token
        :param: str password: 新密码
        
        :return: str 'LXXXXX': 状态码
        """

        sql = "update user set password = %s, token = %s where username = %s" 
        values = [password, token, username]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values) 
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def username(self, query_str):
        
        """
        根据条件选取用户名

        :param: str query_str: 条件字段名和条件字段值
        :return: str result:查询的结果 or 'LXXXXX': 状态码
        """

        sql = "select username, role from user where token = %s" 
        values = [query_str['data']]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values) 
            result = cursor.fetchone()
            return result
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def xss_username(self, token):
        
        """
        根据接收日志中的token选取用户名

        :param: str token: xss token
        :return: str result:查询的结果 or 'LXXXXX': 状态码
        """

        sql = "select username from xss_auth where token = %s" 
        values = [token]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values) 
            result = cursor.fetchone()
            if result:
                return result['username']
            else:
                return None
        except Exception as e:
            print(e)
            return None
        finally:
            cursor.close()
            self.close_conn
    
    def save_account(self, username, description, token, password, role, avatar):
        
        """
        添加用户

        :param: str username: 用户名
        :param: str token: 用户凭证
        :param: str password: 用户密码
        :param: str role: 用户权限
        :param: str avatar: 用户头像初始值

        :return: str 'LXXXXX': 状态码
        """

        datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sql = "insert ignore into user (username, description, token, password, role, avatar, create_time) values (%s, %s, %s, %s, %s, %s, %s)"
        values = [username, description, token, password, role, avatar, datetime]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def save_target(self, username, target, description, port, scanner, rate, concurren_number, masscan_cmd, nmap_cmd, target_ip):
        
        """
        保存目标

        :param: str username: 用户名
        :param: str target: 目标
        :param: str description: 描述字符串
        :param str port: 默认端口
        :param str scanner: 扫描器
        :param str rate: 扫描速率
        :param str concurren_number: POC并发数
        :param str masscan_cmd: masscan扫描参数
        :param str nmap_cmd: nmap扫描参数
        :param: str target_ip: 目标ip
    
        :return: str 'LXXXXX': 状态码
        """

        datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        if masscan_cmd:
            sql =  "insert target (username, target, description, port, scanner, rate, concurren_number, masscan_cmd, target_ip, create_time) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) on duplicate key update target = %s, description = %s, port = %s, scanner = %s, rate = %s, concurren_number = %s, masscan_cmd = %s, target_ip = %s"
            values = [username, target, description, port, scanner, rate, concurren_number, masscan_cmd, target_ip, datetime, target, description, port, scanner, rate, concurren_number, masscan_cmd, target_ip]
        elif nmap_cmd:
            sql =  "insert target (username, target, description, port, scanner, rate, concurren_number, nmap_cmd, target_ip, create_time) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) on duplicate key update target = %s, description = %s, port = %s, scanner = %s, rate = %s, concurren_number = %s, nmap_cmd = %s, target_ip = %s"
            values = [username, target, description, port, scanner, rate, concurren_number, nmap_cmd, target_ip, datetime, target, description, port, scanner, rate, concurren_number, nmap_cmd, target_ip]
        else:
            sql =  "insert target (username, target, description, port, scanner, rate, concurren_number, target_ip, create_time) values (%s, %s, %s, %s, %s, %s, %s, %s, %s) on duplicate key update target = %s, description = %s, port = %s, scanner = %s, rate = %s, concurren_number = %s, target_ip = %s"
            values = [username, target, description, port, scanner, rate, concurren_number, target_ip, datetime, target, description, port, scanner, rate, concurren_number, target_ip]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
 
    def save_target_scan(self, username, target, target_ip, scan_id, scan_time, scan_status, scan_schedule):

        """
        保存目标扫描任务

        :param: str username: 用户名
        :param: str target: 目标
        :param: str scan_id: 扫描任务id
        :param: str scan_time: 扫描时间
        :param: str scan_status: 扫描状态
        :param: str scan_schedule: 扫描进度
        
        :return: str 'LXXXXX': 状态码
        """
        
        sql =  "insert target_scan (username, target, target_ip, scan_id, scan_time, scan_status, scan_schedule) values (%s, %s, %s, %s, %s, %s, %s)"
        values = [username, target, target_ip, scan_id, scan_time, scan_status, scan_schedule]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def save_target_domain(self, username, target, scan_id, domain, domain_ip):
        
        """
        保存目标域名的信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str scan_id: 扫描id
        :param: str domain: 域名
        :param: str domain_ip: 域名的ip

        :return: str 'LXXXXX': 状态码
        """

        datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sql =  "insert target_domain (username, target, scan_id, scan_time, domain, domain_ip) values (%s, %s, %s, %s, %s, %s)"
        values = [username, target, scan_id, datetime, domain, domain_ip]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
   
    def save_port(self, username, target, ip_port, scan_ip, port, finger, protocol, product, version, title, banner):
        
        """
        保存端口信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str ip_port: ip和端口
        :param: str scan_ip: ip地址
        :param: str port: 端口
        :param: str finger: 端口web指纹
        :param: str protocol: 端口的协议
        :param: str product: 端口的产品
        :param: str version: 产品版本
        :param: str title: 端口的标题
        :param: str banner: 端口的banner

        :return: str 'LXXXXX': 状态码
        """

        datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sql =  "insert port (username, target, ip_port, scan_time, scan_ip, port, finger, protocol, product, version, title, banner) \
            values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) on duplicate key update scan_time = %s, \
                finger = %s, protocol = %s, product = %s, version = %s, title = %s, banner = %s"
        values = [username, target, ip_port, datetime, scan_ip, port, finger, protocol, product, version, title, banner, datetime, finger, protocol, product, version, title, banner]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def save_target_port(self, username, target, scan_id, scan_ip, port, finger, protocol, product, version, title, banner):
        
        """
        保存目标端口的信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str scan_id: 扫描id
        :param: str port: 端口
        :param: str finger: 端口web指纹
        :param: str protocol: 端口的协议
        :param: str product: 端口的产品
        :param: str version: 产品版本
        :param: str title: 端口的标题
        :param: str banner: 端口的banner

        :return: str 'LXXXXX': 状态码
        """
        
        datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sql =  "insert target_port (username, target, scan_id, scan_time, scan_ip, port, finger, protocol, product, version, title, banner) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        values = [username, target, scan_id, datetime, scan_ip, port, finger, protocol, product, version, title, banner]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def save_target_path(self, username, target, scan_id, path, status_code):
        
        """
        保存目标域名的信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str scan_id: 扫描id
        :param: str domain: 域名
        :param: str domain_ip: 域名的ip

        :return: str 'LXXXXX': 状态码
        """

        datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sql =  "insert target_path (username, target, scan_id, scan_time, path, status_code) values (%s, %s, %s, %s, %s, %s)"
        values = [username, target, scan_id, datetime, path, status_code]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def save_vulner(self, username, target, ip_port, vulner_name, vulner_descrip):
        
        """
        保存漏洞信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str ip_port: 存在漏洞的ip和端口
        :param: str vulner_name: 漏洞名字
        :param: str vulner_descrip: 漏洞的描述信息

        :return: str 'LXXXXX': 状态码
        """

        datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sql = "insert vulner (username, target, ip_port, vulner_name, vulner_descrip, scan_time) values (%s, %s, %s, %s, %s, %s) \
            on duplicate key update vulner_name = %s, vulner_descrip = %s, scan_time = %s "
        values = [username, target, ip_port, vulner_name, vulner_descrip, datetime, vulner_name, vulner_descrip, datetime]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def save_poc(self, username, poc_name, poc_description, time, type_str):
        
        """
        保存漏洞信息

        :param: str username: 用户名
        :param: str poc_name: poc名字
        :param: str poc_description: poc描述
        :param: str time: 漏洞出现日期
        :param: str type_str: 漏洞类型

        :return: str 'LXXXXX': 状态码
        """

        sql = "insert poc (username, poc_name, poc_description, time, type) values (%s, %s, %s, %s, %s)"
        values = [username, poc_name, poc_description, time, type_str]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def save_target_vulner(self, username, target, scan_id, ip_port, vulner_name, vulner_descrip):
        
        """
        保存漏洞信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str scan_id: 扫描id
        :param: str ip_port: 存在漏洞的ip和端口
        :param: str vulner_name: 漏洞名字
        :param: str vulner_descrip: 漏洞的描述信息

        :return: str 'LXXXXX': 状态码
        """

        datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sql = "insert target_vulner (username, target, scan_id, ip_port, vulner_name, vulner_descrip, scan_time) values (%s, %s, %s, %s, %s, %s, %s)"
        values = [username, target, scan_id, ip_port, vulner_name, vulner_descrip, datetime]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def save_xss_auth(self, username, token, url):
        
        """
        保存漏洞信息

        :param: str username: 用户名
        :param: str token: 生成的xss token
        :param: str token: 访问的url

        :return: str 'LXXXXX': 状态码
        """

        datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sql = "insert xss_auth (username, token, url, token_status, time) values (%s, %s, %s, %s, %s)"
        values = [username, token, url, '生效', datetime]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def save_xss_log(self, username, url, data, ua, ip):
        
        """
        保存xsslog信息

        :param: str username: 用户名
        :param: str data: 获取到的data
        :param: str ip: 来源ip

        :return: str 'LXXXXX': 状态码
        """

        datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sql = "insert xss_log (username, url, data, ua, ip, time) values (%s, %s, %s, %s, %s, %s)"
        values = [username, url, data, ua, ip, datetime]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def get_dns_log(self, username, dns_log, ip, time):
        
        """
        查看数据库中是否已有dnslog信息

        :param: str username: 用户名
        :param: str dns_log: dns log
        :param: str ip: 来源ip
        :param: str time: 时间

        :return: str 'LXXXXX': 状态码
        """
        
        sql = "select * from dns_log where username = %s and dns_log = %s and ip = %s and time = %s"
        values = [username, dns_log, ip, time]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            result = cursor.execute(sql, values)
            return result
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def save_dns_log(self, username, dns_log, ip, time):
        
        """
        保存dnslog信息

        :param: str username: 用户名
        :param: str dns_log: dns log
        :param: str ip: 来源ip

        :return: str 'LXXXXX': 状态码
        """
        
        sql = "insert dns_log (username, dns_log, ip, time) values (%s, %s, %s, %s)"
        values = [username, dns_log, ip, time]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def update_account_role(self, username, role):
        
        """
        更新用户的权限

        :param: str username: 用户名
        :param: str role: 用户权限

        :return: 'LXXXXX': 状态码
        """

        sql =  "update user set role = %s where username = %s"
        values = [role, username]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def update_account_password(self, username, password):
        
        """
        更新用户的权限

        :param: str username: 用户名
        :param: str password: 用户的新密码

        :return: 'LXXXXX': 状态码
        """

        sql =  "update user set password = %s where username = %s"
        values = [password, username]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def update_account_description(self, username, description):
        
        """
        更新用户的描述

        :param: str username: 用户名
        :param: str description: 用户描述

        :return: 'LXXXXX': 状态码
        """

        sql =  "update user set description = %s where username = %s"
        values = [description, username]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def update_target_ip(self, username, target, ip):

        """
        更新目标的ip

        :param: str username: 用户名
        :param: str target: 目标
        :param: str ip: 目标的最新ip

        :return:

        """

        sql =  "update target set target_ip = %s where username = %s and target = %s"
        values = [ip, username, target]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def update_target_finger(self, username, target, finger):
        
        """
        更新目标的指纹

        :param: str username: 用户名
        :param: str target: 目标
        :param: str finger: 指纹

        :return:
        
        """

        sql =  "update target set finger = %s where username = %s and target = %s"
        values = [finger, username, target]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def update_target_description(self, username, target, description):
        
        """
        更新目标表中的描述信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str description: 描述信息

        :return: 'LXXXXX': 状态码
        """

        sql =  "update target set description = %s where username = %s and target = %s"
        values = [description, username, target]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def update_target_scan_status(self, username, target, scan_status):
        
        """
        更新目标表中的扫描状态信息,以最新的扫描任务的状态为准

        :param: str username: 用户名
        :param: str target: 目标
        :param: str scan_status: 扫描的状态

        :return: 'LXXXXX': 状态码
        """

        sql =  "update target set scan_status = %s where username = %s and target = %s"
        values = [scan_status, username, target]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def update_target_scan_schedule(self, username, target, scan_schedule):
        
        """
        更新目标表中的扫描进度信息,以最新的扫描任务的进度为准

        :param: str username: 用户名
        :param: str target: 目标
        :param: str scan_schedule: 扫描的进度

        :return: 'LXXXXX': 状态码
        """

        sql =  "update target set scan_schedule = %s where username = %s and target = %s"
        values = [scan_schedule, username, target]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def update_scan_status(self, username, scan_id, scan_status):

        """
        更新扫描状态信息

        :param: str username: 用户名
        :param: str scan_id: 扫描任务id
        :param: str scan_status: 扫描的状态

        :return: 'LXXXXX': 状态码
        """

        sql =  "update target_scan set scan_status = %s where username = %s and scan_id = %s"
        values = [scan_status, username, scan_id]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def update_scan_schedule(self, username, scan_id, scan_schedule):

        """
        更新扫描进度

        :param: str username: 用户名
        :param: str scan_id: 扫描任务id
        :param: str scan_schedule: 扫描进度

        :return: 'LXXXXX': 状态码
        """

        sql =  "update target_scan set scan_schedule = %s where username = %s and scan_id = %s"
        values = [scan_schedule, username, scan_id]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn 
    
    def update_scan_option(self, username, scan_id, scan_option):

        """
        更新扫描选项

        :param: str username: 用户名
        :param: str scan_id: 扫描任务id
        :param: str scan_schedule: 扫描选项

        :return: 'LXXXXX': 状态码
        """

        sql =  "update target_scan set scan_option = %s where username = %s and scan_id = %s"
        values = [scan_option, username, scan_id]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def account_list(self, list_query):
        
        """
        获取所有用户的信息

        :param:

        :return: str result:查询到的信息 or 'LXXXXX': 状态码
        """

        sql = "select id, username, description, role, create_time from user where if (%s = '', 0 = 0, username like %s) and if (%s = '', 0 = 0, description like %s) and if (%s = '', 0 = 0, role = %s)"
        values = [list_query['username'], '%' + list_query['username'] + '%', list_query['description'], '%' + list_query['description'] + '%', list_query['role'], list_query['role']]
        total_sql = "select count(0) from user where if (%s = '', 0 = 0, username like %s) and if (%s = '', 0 = 0, description like %s) and if (%s = '', 0 = 0, role = %s)"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(total_sql, values)
            total_result = cursor.fetchone()['count(0)']
            cursor.execute(sql, values)
            result = cursor.fetchall()
            data = {}
            data['total'] = total_result
            data ['result'] = result
            return data
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def get_target(self, username):
        
        """
        获取用户目标的信息

        :param: str username: 用户名

        :return: str result:查询到的信息 or 'LXXXXX': 状态码
        """

        sql = "select * from target where username = %s"
        values = [username]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            result = cursor.fetchone()
            return result
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def get_target_ip(self, username, target):
        
        """
        获取目标的IP

        :param: str username: 用户名
        :param: str target: 目标

        :return: str result:查询到的信息 or 'LXXXXX': 状态码
        """

        sql = "select * from target where username = %s and target = %s"
        values = [username, target]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            result = cursor.fetchone()
            if result:
                return result['target_ip']
            else:
                return ''
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def get_target_status(self, username, target):
        
        """
        获取用户扫描状态

        :param: str username: 用户名
        :param: str target: 扫描状态

        :return: str result:查询到的信息 or 'LXXXXX': 状态码
        """

        sql = "select scan_status from target_scan where username = %s and target = %s"
        values = [username, target]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            result = cursor.fetchone()
            if result:
                return result['scan_status']
            else:
                return ''
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def get_scan_target(self, username):
        
        """
        获取所有未开始扫描的目标

        :param: str username: 用户名
        :return: 'LXXXXX': 状态码
        """

        sql = "select target from target where username = %s and scan_status = '未开始'"
        values = [username]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            result = cursor.fetchall()
            return result
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def get_scan_id(self, username):
        
        """
        获取一个扫描id

        :param: str username: 用户名
        
        :return: 'LXXXXX': 状态码
        """

        scan_total_sql = "select count(0) from target_scan where username = %s"
        values = [username]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(scan_total_sql, values)
            total_result = cursor.fetchone()['count(0)']
            scan_id = str(int(total_result) + 1)
            return scan_id
        except Exception as e:
            print(e)
            return False
        finally:
            cursor.close()
            self.close_conn
    
    def get_target_scan_id(self, username, target):
        
        """
        获取一个扫描id

        :param: str username: 用户名
        :param: str target: 目标
        
        :return: 'LXXXXX': 状态码
        """

        sql = "select scan_id from target_scan where username = %s and target = %s order by scan_id + 0 desc"
        values = [username, target]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            result = cursor.fetchone()
            if result:
                return result['scan_id']
            else:
                return '0'
        except Exception as e:
            print(e)
            return False
        finally:
            cursor.close()
            self.close_conn
    
    def get_target_port(self, username, target, port):

        """
        获取目标端口的信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str port: 端口号
        
        :return: 'LXXXXX': 状态码
        """

        sql = "select protocol, finger from port where username = %s and target = %s and port = %s"
        values = [username, target, port]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            result = cursor.fetchone()
            return result
        except Exception as e:
            print(e)
            return False
        finally:
            cursor.close()
            self.close_conn

    def scan_set(self, username, target, scanner, masscan_cmd, nmap_cmd, port, rate, concurren_number):
        
        """
        设置扫描选项

        :param: str username: 用户名
        :param: str target: 目标
        :param: str scanner: 选择的端口扫描器
        :param: str masscan_cmd: masscan运行参数
        :param: str nmap_cmd: nmap运行参数
        :param: str port: 扫描范围的最大端口
        
        :return: str 'LXXXXX': 状态码
        """
        
        if masscan_cmd:
            sql =  "update target set scanner = %s, masscan_cmd = %s, port = %s, rate = %s, concurren_number = %s where username = %s and target = %s"
            values = [scanner, masscan_cmd, port, rate, concurren_number, username, target]
        
        elif nmap_cmd:
            sql =  "update target set scanner = %s, nmap_cmd = %s, port = %s, rate = %s, concurren_number = %s where username = %s and target = %s"
            values = [scanner, nmap_cmd, port, rate, concurren_number, username, target]
        else:
            sql =  "update target set scanner = %s, port = %s, rate = %s, concurren_number = %s where username = %s and target = %s"
            values = [scanner, port, rate, concurren_number, username, target]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def get_scan(self, username, target):
        
        """
        获取扫描选项信息

        :param: str username: 用户名
        :param: str target: 目标
        :return: str 'LXXXXX': 状态码
        """
        sql = "select scanner, port, rate, masscan_cmd, nmap_cmd, concurren_number from target where username = %s and target = %s"
        values = [username, target]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values) 
            result = cursor.fetchone()
            return result
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def get_scan_status(self, username, scan_id):

        """
        获取扫描状态

        :param: str username: 用户名
        :param: str scan_id: 扫描id

        :return: str 'LXXXXX': 状态码
        """

        sql = "select scan_status from target_scan where username = %s and scan_id = %s"
        values = [username, scan_id]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values) 
            result = cursor.fetchone()
            if result:
                return result['scan_status']
            else:
                return ''
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def get_scan_option(self, username, scan_id):

        """
        获取扫描选项

        :param: str username: 用户名
        :param: str scan_id: 扫描id

        :return: str 'LXXXXX': 状态码
        """

        sql = "select scan_option from target_scan where username = %s and scan_id = %s"
        values = [username, scan_id]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values) 
            result = cursor.fetchone()
            if result:
                return result['scan_option']
            else:
                return ''
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def start_scan(self, username, target):
        
        """
        开始扫描选项

        :param: str username: 用户名
        :param: str target: 目标
        :return: str 'LXXXXX': 状态码
        """
        datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sql =  "update target set scan_time = %s, scan_status = %s, scan_schedule = %s where username = %s and target = %s"
        values = [datetime, '1', '准备开始扫描', username, target]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def target_list(self, username, pagenum, pagesize, list_query):
        
        """
        获取所有目标的信息

        :param: str username: 用户名
        :param: str pagenum: 每页显示的数据数量
        :param: str pagesize: 显示的第几页
        :param: dict list_query: 筛选目标的条件

        :return: str 'LXXXXX': 状态码
        """
        
        start = (int(pagenum)-1) * int(pagesize)
        pagesize = int (pagesize)
        sql = "select id, target, description, finger, create_time, scan_status, scan_schedule, vulner_number from target where username = %s and if (%s = '', 0 = 0, target like %s) and if (%s = '', 0 = 0, description like %s) and if (%s = '', 0 = 0, scan_status = %s) and if (%s = '', 0 = 0, scan_schedule = %s) order by id desc limit %s, %s"
        values = [username, list_query['target'], '%' + list_query['target'] + '%', list_query['description'], '%' + list_query['description'] + '%', list_query['scan_status'], list_query['scan_status'], list_query['scan_schedule'], list_query['scan_schedule'], start, pagesize]
        total_sql = "select count(0) from target where username = %s and if (%s = '', 0 = 0, target like %s) and if (%s = '', 0 = 0, description like %s) and if (%s = '', 0 = 0, scan_status = %s) and if (%s = '', 0 = 0, scan_schedule = %s)"
        total_values = [username, list_query['target'], '%' + list_query['target'] + '%', list_query['description'], '%' + list_query['description'] + '%', list_query['scan_status'], list_query['scan_status'], list_query['scan_schedule'], list_query['scan_schedule']]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(total_sql, total_values)
            total_result = cursor.fetchone()['count(0)']
            cursor.execute(sql, values)
            result = cursor.fetchall()
            data = {}
            data['total'] = total_result
            data ['result'] = result
            return data
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def poc_list(self, username, pagenum, pagesize, list_query):
        
        """
        获取所有poc的信息

        :param: str username: 用户名
        :param: str pagenum: 每页显示的数据数量
        :param: str pagesize: 显示的第几页
        :param: dict list_query: 筛选目标的条件

        :return: str 'LXXXXX': 状态码
        """
        start = (int(pagenum)-1) * int(pagesize)
        pagesize = int (pagesize)
        sql = "select id, poc_name, poc_description, time, type from poc where username = %s and if (%s = '', 0 = 0, poc_name like %s) and if (%s = '', 0 = 0, poc_description like %s) and if (%s = '', 0 = 0, type = %s) order by id asc limit %s, %s"
        values = [username, list_query['poc_name'], '%' + list_query['poc_name'] + '%', list_query['poc_description'], '%' + list_query['poc_description'] + '%', list_query['type'], list_query['type'], start, pagesize]
        total_sql = "select count(0) from poc where username = %s and if (%s = '', 0 = 0, poc_name like %s) and if (%s = '', 0 = 0, poc_description like %s) and if (%s = '', 0 = 0, type = %s)"
        total_values = [username, list_query['poc_name'], '%' + list_query['poc_name'] + '%', list_query['poc_description'], '%' + list_query['poc_description'] + '%', list_query['type'], list_query['type']]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(total_sql, total_values)
            total_result = cursor.fetchone()['count(0)']
            cursor.execute(sql, values)
            result = cursor.fetchall()
            data = {}
            data['total'] = total_result
            data ['result'] = result
            return data
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def get_target_detail(self, username, target, pagenum, pagesize):

        """
        获取目标子域名、目录等信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str pagenum: 每页显示的数据数量
        :param: str pagesize: 显示的第几页
    
        :return: str result: 获取到的信息 or 'LXXXXX': 状态码
        """

        start = (int(pagenum)-1) * int(pagesize)
        pagesize = int (pagesize)
        target_sql = "select target, finger, scan_status, scan_schedule, vulner_number from target where username = %s and target = %s"
        domain_sql = "select scan_id, scan_time, domain, domain_ip from target_domain where username = %s and target = %s order by scan_id + 0  desc limit %s, %s"
        port_sql = "select scan_id, target, scan_ip, scan_time, port, finger, product, protocol, version, title, banner from target_port where username = %s and target = %s order by scan_id + 0 desc limit %s, %s"
        path_sql = "select scan_id, scan_time, path, status_code from target_path where username = %s and target = %s order by scan_id + 0  desc limit %s, %s"
        vulner_sql = "select scan_id, scan_time, vulner_name, vulner_descrip from target_vulner where username = %s and target = %s order by scan_id + 0 desc limit %s, %s"
        
        domain_total_sql = "select count(0) from target_domain where username = %s and target = %s"
        port_total_sql = "select count(0) from target_port where username = %s and target = %s"
        path_total_sql = "select count(0) from target_path where username = %s and target = %s"
        vulner_total_sql = "select count(0) from target_vulner where username = %s and target = %s"

        scan_id = self.get_target_scan_id(username, target)
        domain_label_total_sql = "select count(0) from target_domain where username = %s and target = %s and scan_id = %s"
        port_label_total_sql = "select count(0) from target_port where username = %s and target = %s and scan_id = %s"
        path_label_total_sql = "select count(0) from target_path where username = %s and target = %s and scan_id = %s"
        vulner_label_total_sql = "select count(0) from target_vulner where username = %s and target = %s and scan_id = %s"

        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            result = {}
            target_values = [username, target]
            cursor.execute(target_sql, target_values)
            target_result = cursor.fetchall()

            values = [username, target, start, pagesize]
            total_values = [username, target]
            label_values = [username, target, scan_id]
            
            cursor.execute(domain_sql, values)
            domain_result = cursor.fetchall()
            
            cursor.execute(domain_total_sql, total_values)
            domain_total_result = cursor.fetchone()['count(0)']
            cursor.execute(domain_label_total_sql, label_values)
            domain_label_total_result = cursor.fetchone()['count(0)']
           
            if not domain_result:
                domain_result = list(domain_result)

            cursor.execute(port_sql, values)
            port_result = cursor.fetchall()
            cursor.execute(port_total_sql, total_values)
            port_total_result = cursor.fetchone()['count(0)']
            cursor.execute(port_label_total_sql, label_values)
            port_label_total_result = cursor.fetchone()['count(0)']

            if not port_result:
                port_result = list(port_result)

            cursor.execute(path_sql, values)
            path_result = cursor.fetchall()
            cursor.execute(path_total_sql, total_values)
            path_total_result = cursor.fetchone()['count(0)']
            cursor.execute(path_label_total_sql, label_values)
            path_label_total_result = cursor.fetchone()['count(0)']

            if not path_result:
                path_result = list(path_result)
                
            cursor.execute(vulner_sql, values)
            vulner_result = cursor.fetchall()
            cursor.execute(vulner_total_sql, total_values)
            vulner_total_result = cursor.fetchone()['count(0)']
            cursor.execute(vulner_label_total_sql, label_values)
            vulner_label_total_result = cursor.fetchone()['count(0)']
            if not vulner_result:
                vulner_result = list(vulner_result)


            result['target'] = {
                'result': target_result,
                'total': len(target_result)
            }

            result['domain'] = {
                'result': domain_result,
                'total': domain_total_result,
                'label_toal': domain_label_total_result
            }

            result['port'] = {
                'result': port_result,
                'total': port_total_result,
                'label_toal': port_label_total_result
            }

            result['path'] = {
                'result': path_result,
                'total': path_total_result,
                'label_toal': path_label_total_result
            }

            result['vulner'] = {
                'result': vulner_result,
                'total': vulner_total_result,
                'label_toal': vulner_label_total_result
            }

            return result
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def get_card_count(self, username):
        
        """
        获取目标、扫描任务、指纹的数量

        :param: str username: 用户名
    
        :return: str result: 获取到的信息 or 'LXXXXX': 状态码
        """
        
        total_sql = "select count(0) a from target where username = %s union all select count(0) b from target_scan where username = %s \
            union all select count(0) b from port where username = %s union all select count(0) b from vulner where username = %s"
        values = [username, username, username, username]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            result = []
            cursor.execute(total_sql, values)
            total_result = cursor.fetchall()
            for item in total_result:
                result.append(item['a'])
            return result
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def data_sort(self, item):
        
        """
        数据排序

        :param: str item: 数据
    
        :return: str result: 按照的排序关键字
        """
        return item['click_date']

    def get_7day_count(self, username):
        
        """
        获取7天内目标子域名、端口、目录等信息的数量

        :param: str username: 用户名
    
        :return: str result: 获取到的信息 or 'LXXXXX': 状态码
        """

        target_total_sql = "select a.click_date,ifnull(b.count,0) as count from (select curdate() as click_date union all select date_sub(curdate(), \
        interval 1 day) as click_date union all select date_sub(curdate(), interval 2 day) as click_date union all select date_sub(curdate(), interval 3 day) \
            as click_date union all select date_sub(curdate(), interval 4 day) as click_date union all select date_sub(curdate(), interval 5 day) as click_date \
                union all select date_sub(curdate(), interval 6 day) as click_date) a left join (select date(create_time) as datetime, count(0) as count from target \
                    where username = %s group by date(create_time)) b on a.click_date = b.datetime"

        scan_total_sql = "select a.click_date,ifnull(b.count,0) as count from (select curdate() as click_date union all select date_sub(curdate(), \
        interval 1 day) as click_date union all select date_sub(curdate(), interval 2 day) as click_date union all select date_sub(curdate(), interval 3 day) \
            as click_date union all select date_sub(curdate(), interval 4 day) as click_date union all select date_sub(curdate(), interval 5 day) as click_date \
                union all select date_sub(curdate(), interval 6 day) as click_date) a left join (select date(scan_time) as datetime, count(0) as count from target_scan \
                    where username = %s group by date(scan_time)) b on a.click_date = b.datetime"
        
        port_total_sql = "select a.click_date,ifnull(b.count,0) as count from (select curdate() as click_date union all select date_sub(curdate(), \
        interval 1 day) as click_date union all select date_sub(curdate(), interval 2 day) as click_date union all select date_sub(curdate(), interval 3 day) \
            as click_date union all select date_sub(curdate(), interval 4 day) as click_date union all select date_sub(curdate(), interval 5 day) as click_date \
                union all select date_sub(curdate(), interval 6 day) as click_date) a left join (select date(scan_time) as datetime, count(0) as count from port \
                    where username = %s group by date(scan_time)) b on a.click_date = b.datetime"

        vulner_total_sql = "select a.click_date,ifnull(b.count,0) as count from (select curdate() as click_date union all select date_sub(curdate(), \
        interval 1 day) as click_date union all select date_sub(curdate(), interval 2 day) as click_date union all select date_sub(curdate(), interval 3 day) \
            as click_date union all select date_sub(curdate(), interval 4 day) as click_date union all select date_sub(curdate(), interval 5 day) as click_date \
                union all select date_sub(curdate(), interval 6 day) as click_date) a left join (select date(scan_time) as datetime, count(0) as count from vulner \
                    where username = %s group by date(scan_time)) b on a.click_date = b.datetime"

        values = [username]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            result = {}

            temp_list = []
            cursor.execute(target_total_sql, values)
            target_total_result = cursor.fetchall()
            target_total_result.sort(key = self.data_sort)
            for item in target_total_result:
                temp_list.append(item['count'])
            result['target'] = temp_list

            temp_list = []
            cursor.execute(scan_total_sql, values)
            scan_total_result = cursor.fetchall()
            scan_total_result.sort(key = self.data_sort)
            for item in scan_total_result:
                temp_list.append(item['count'])
            result['scan'] = temp_list

            temp_list = []
            cursor.execute(port_total_sql, values)
            port_total_result = cursor.fetchall()
            port_total_result.sort(key = self.data_sort)
            for item in port_total_result:
                temp_list.append(item['count'])
            result['port'] = temp_list

            temp_list = []
            cursor.execute(vulner_total_sql, values)
            cert_total_result = cursor.fetchall()
            cert_total_result.sort(key = self.data_sort)
            for item in cert_total_result:
                temp_list.append(item['count'])
            result['vulner'] = temp_list
            return result
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def scan_list(self, username, pagenum, pagesize, list_query):
        
        """
        获取所有扫描任务的信息

        :param: str username: 用户名
        :param: str pagenum: 每页显示的数据数量
        :param: str pagesize: 显示的第几页
        :param: dict list_query: 筛选扫描任务的条件

        :return: str 'LXXXXX': 状态码
        """
        start = (int(pagenum)-1) * int(pagesize)
        pagesize = int (pagesize)
        sql = "select id, target, target_ip, scan_id, scan_time, scan_status, scan_schedule, vulner_number from target_scan where username = %s and if (%s = '', 0 = 0, target like %s) and if (%s = '', 0 = 0, scan_status = %s) and if (%s = '', 0 = 0, scan_schedule = %s) order by id desc limit %s, %s"
        values = [username, list_query['target'], '%' + list_query['target'] + '%', list_query['scan_status'], list_query['scan_status'], list_query['scan_schedule'], list_query['scan_schedule'], start, pagesize]
        total_sql = "select count(0) from target_scan where username = %s and if (%s = '', 0 = 0, target like %s) and if (%s = '', 0 = 0, scan_status = %s) and if (%s = '', 0 = 0, scan_schedule = %s)"
        total_values = [username, list_query['target'], '%' + list_query['target'] + '%', list_query['scan_status'], list_query['scan_status'], list_query['scan_schedule'], list_query['scan_schedule']]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(total_sql, total_values)
            total_result = cursor.fetchone()['count(0)']
            cursor.execute(sql, values)
            result = cursor.fetchall()
            data = {}
            data['total'] = total_result
            data ['result'] = result
            return data
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def port_list(self, username, pagenum, pagesize, list_query):
        
        """
        获取所有端口的信息

        :param: str username: 用户名
        :param: str pagenum: 每页显示的数据数量
        :param: str pagesize: 显示的第几页
        :param: dict list_query: 筛选扫描任务的条件

        :return: str 'LXXXXX': 状态码
        """

        start = (int(pagenum)-1) * int(pagesize)
        pagesize = int (pagesize)
        sql = "select id, target, scan_time, scan_ip, port, finger, protocol, product, version, title, banner from port \
            where username = %s and if (%s = '', 0 = 0, target like %s) and if (%s = '', 0 = 0, scan_ip like %s) \
                and if (%s = '', 0 = 0, port like %s) and if (%s = '', 0 = 0, finger like %s) and if (%s = '', 0 = 0, product like %s) and if (%s = '', 0 = 0, title like %s) order by id desc limit %s, %s"
        values = [username, list_query['target'], '%' + list_query['target'] + '%', list_query['scan_ip'], '%' + list_query['scan_ip'] + '%', list_query['port'], '%' + list_query['port'] + '%', list_query['finger'], '%' + list_query['finger'] + '%', list_query['product'], '%' + list_query['product'] + '%', list_query['title'], '%' + list_query['title'] + '%', start, pagesize]
        total_sql = "select count(0) from port where username = %s and if (%s = '', 0 = 0, target like %s) and if (%s = '', 0 = 0, scan_ip like %s) \
                and if (%s = '', 0 = 0, port like %s) and if (%s = '', 0 = 0, finger like %s) and if (%s = '', 0 = 0, product like %s) and if (%s = '', 0 = 0, title like %s)"
        total_values = [username, list_query['target'], '%' + list_query['target'] + '%', list_query['scan_ip'], '%' + list_query['scan_ip'] + '%', list_query['port'], '%' + list_query['port'] + '%', list_query['finger'], '%' + list_query['finger'] + '%', list_query['product'], '%' + list_query['product'] + '%', list_query['title'], '%' + list_query['title'] + '%']
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(total_sql, total_values)
            total_result = cursor.fetchone()['count(0)']
            cursor.execute(sql, values)
            result = cursor.fetchall()
            data = {}
            data['total'] = total_result
            data ['result'] = result
            return data
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def port_download(self, username, list_query):
        
        """
        下载所有端口的信息

        :param: str username: 用户名
        :param: dict list_query: 筛选扫描任务的条件

        :return: str 'LXXXXX': 状态码
        """

        sql = "select id, target, scan_time, scan_ip, port, ip_port, finger, protocol, product, version, title, banner from port \
            where username = %s and if (%s = '', 0 = 0, target like %s) and if (%s = '', 0 = 0, scan_ip like %s) \
                and if (%s = '', 0 = 0, port like %s) and if (%s = '', 0 = 0, finger like %s) and if (%s = '', 0 = 0, product like %s) and if (%s = '', 0 = 0, title like %s) order by id asc"
        values = [username, list_query['target'], '%' + list_query['target'] + '%', list_query['scan_ip'], '%' + list_query['scan_ip'] + '%', list_query['port'], '%' + list_query['port'] + '%', list_query['finger'], '%' + list_query['finger'] + '%', list_query['product'], '%' + list_query['product'] + '%', list_query['title'], '%' + list_query['title'] + '%']
        total_sql = "select count(0) from port where username = %s and if (%s = '', 0 = 0, target like %s) and if (%s = '', 0 = 0, scan_ip like %s) \
                and if (%s = '', 0 = 0, port like %s) and if (%s = '', 0 = 0, finger like %s) and if (%s = '', 0 = 0, product like %s) and if (%s = '', 0 = 0, title like %s)"
        total_values = [username, list_query['target'], '%' + list_query['target'] + '%', list_query['scan_ip'], '%' + list_query['scan_ip'] + '%', list_query['port'], '%' + list_query['port'] + '%', list_query['finger'], '%' + list_query['finger'] + '%', list_query['product'], '%' + list_query['product'] + '%', list_query['title'], '%' + list_query['title'] + '%']
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(total_sql, total_values)
            total_result = cursor.fetchone()['count(0)']
            cursor.execute(sql, values)
            result = cursor.fetchall()
            data = {}
            data['total'] = total_result
            data ['result'] = result
            return data
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def vulner_list(self, username, pagenum, pagesize, list_query):
        
        """
        获取所有漏洞的信息

        :param: str username: 用户名
        :param: str pagenum: 每页显示的数据数量
        :param: str pagesize: 显示的第几页
        :param: dict list_query: 筛选扫描任务的条件

        :return: str 'LXXXXX': 状态码
        """
        start = (int(pagenum)-1) * int(pagesize)
        pagesize = int (pagesize)
        sql = "select id, target, scan_time, ip_port, vulner_name, vulner_descrip from vulner \
            where username = %s and if (%s = '', 0 = 0, target like %s) and if (%s = '', 0 = 0, ip_port like %s) \
                and if (%s = '', 0 = 0, vulner_name like %s) and if (%s = '', 0 = 0, vulner_descrip like %s) order by id desc limit %s, %s"
        values = [username, list_query['target'], '%' + list_query['target'] + '%', list_query['ip_port'], '%' + list_query['ip_port'] + '%', list_query['vulner_name'], '%' + list_query['vulner_name'] + '%', list_query['vulner_descrip'], '%' + list_query['vulner_descrip'] + '%', start, pagesize]
        total_sql = "select count(0) from vulner where username = %s and if (%s = '', 0 = 0, target like %s) \
            and if (%s = '', 0 = 0, ip_port like %s) and if (%s = '', 0 = 0, vulner_name like %s) and if (%s = '', 0 = 0, vulner_descrip like %s)"
        total_values = [username, list_query['target'], '%' + list_query['target'] + '%', list_query['ip_port'], '%' + list_query['ip_port'] + '%', list_query['vulner_name'], '%' + list_query['vulner_name'] + '%', list_query['vulner_descrip'], '%' + list_query['vulner_descrip'] + '%']
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(total_sql, total_values)
            total_result = cursor.fetchone()['count(0)']
            cursor.execute(sql, values)
            result = cursor.fetchall()
            data = {}
            data['total'] = total_result
            data ['result'] = result
            return data
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def target_port_list(self, username, target, pagenum, pagesize):

        """
        获取目标端口扫描后的信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str pagenum: 每页显示的数据数量
        :param: str pagesize: 显示的第几页

        :return: str 'LXXXXX': 状态码
        """
        start = (int(pagenum)-1) * int(pagesize)
        pagesize = int (pagesize)
        sql = "select scan_id, target, scan_time, port, finger, product, protocol, version, title, banner from target_port where username = %s and target = %s order by scan_id + 0 desc limit %s, %s"
        values = [username, target, start, pagesize]
        total_sql = "select count(0) from target_port where username = %s and target = %s"
        total_values = [username, target]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(total_sql, total_values)
            total_result = cursor.fetchone()['count(0)']
            cursor.execute(sql, values)
            result = cursor.fetchall()
            data = {}
            data['total'] = total_result
            data ['result'] = result
            return data
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def target_domain_list(self, username, target, pagenum, pagesize):
        
        """
        获取目标和域名对应关系信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str pagenum: 每页显示的数据数量
        :param: str pagesize: 显示的第几页

        :return: str 'LXXXXX': 状态码
        """
        start = (int(pagenum)-1) * int(pagesize)
        pagesize = int (pagesize)
        sql = "select scan_id, target, scan_time, domain, domain_ip from target_domain where username = %s and target = %s order by scan_id + 0 desc limit %s, %s"
        values = [username, target, start, pagesize]
        total_sql = "select count(0) from target_domain where username = %s and target = %s"
        total_values = [username, target]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(total_sql, total_values)
            total_result = cursor.fetchone()['count(0)']
            cursor.execute(sql, values)
            result = cursor.fetchall()
            data = {}
            data['total'] = total_result
            data ['result'] = result
            return data
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def target_scan_list(self, username, pagenum, pagesize):
        
        """
        获取所有扫描任务的信息

        :param: str username: 用户名
        :param: str pagenum: 每页显示的数据数量
        :param: str pagesize: 显示的第几页

        :return: str 'LXXXXX': 状态码
        """

        start = (int(pagenum)-1) * int(pagesize)
        pagesize = int (pagesize)
        sql = "select scan_id, target, scan_time, scan_status, scan_schedule, vulner_number from target_scan where username = %s order by scan_id + 0 desc limit %s, %s"
        values = [username, start, pagesize]
        total_sql = "select count(0) from target_scan where username = %s"
        total_values = [username]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(total_sql, total_values)
            total_result = cursor.fetchone()['count(0)']
            cursor.execute(sql, values)
            result = cursor.fetchall()
            data = {}
            data['total'] = total_result
            data ['result'] = result
            return data
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def target_vulner_list(self, username, target, pagenum, pagesize):
        
        """
        获取目标所有漏洞的信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str pagenum: 每页显示的数据数量
        :param: str pagesize: 显示的第几页
        
        :return: str 'LXXXXX': 状态码
        """
        start = (int(pagenum)-1) * int(pagesize)
        pagesize = int (pagesize)
        sql = "select scan_id, target, description, ip_port, scan_time, vulner_name, vulner_descrip, scan_time from target_vulner where username = '0' and target = %s order by scan_id + 0 desc limit %s, %s"
        values = [username, target, start, pagesize]
        total_sql = "select count(0) from target_vulner where username = %s and target = %s" 
        total_values = [username, target]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(total_sql, total_values)
            total_result = cursor.fetchone()['count(0)']
            cursor.execute(sql, values)
            result = cursor.fetchall()
            data = {}
            data['total'] = total_result
            data ['result'] = result
            return data
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def dns_log_list(self, username, pagenum, pagesize, list_query):
        
        """
        获取dns log的信息

        :param: str username: 用户名
        :param: str pagenum: 每页显示的数据数量
        :param: str pagesize: 显示的第几页
        :param: dict list_query: 筛选目标的条件

        :return: str result:查询到的信息 or 'LXXXXX': 状态码
        """

        start = (int(pagenum)-1) * int(pagesize)
        pagesize = int (pagesize)
        sql = "select id, dns_log, ip, time from dns_log where username = %s and if (%s = '', 0 = 0, dns_log = %s) order by id desc limit %s, %s"
        values = [username,  list_query['dns_log'], '%' + list_query['dns_log'] + '%',  start, pagesize]
        total_sql = "select count(0) from dns_log where username = %s and if (%s = '', 0 = 0, dns_log = %s)"
        total_values = [username, list_query['dns_log'], '%' + list_query['dns_log'] + '%']
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(total_sql, total_values)
            total_result = cursor.fetchone()['count(0)']
            cursor.execute(sql, values)
            result = cursor.fetchall()
            data = {}
            data['total'] = total_result
            data ['result'] = result
            return data
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def xss_log_list(self, username, pagenum, pagesize, list_query):
        
        """
        获取xss log的信息

        :param: str username: 用户名
        :param: str pagenum: 每页显示的数据数量
        :param: str pagesize: 显示的第几页
        :param: dict list_query: 筛选目标的条件

        :return: str result:查询到的信息 or 'LXXXXX': 状态码
        """

        start = (int(pagenum)-1) * int(pagesize)
        pagesize = int (pagesize)
        sql = "select id, url, data, ua, ip, time from xss_log where username = %s and if (%s = '', 0 = 0, url like %s) and if (%s = '', 0 = 0, data like %s) and if (%s = '', 0 = 0, ua = %s) and if (%s = '', 0 = 0, ip = %s) order by id desc limit %s, %s"
        values = [username,  list_query['url'], '%' + list_query['url'] + '%', list_query['data'], '%' + list_query['data'] + '%', list_query['ua'], list_query['ua'], list_query['ip'], list_query['ip'], start, pagesize]
        total_sql = "select count(0) from xss_log where username = %s and if (%s = '', 0 = 0, url like %s) and if (%s = '', 0 = 0, data like %s) and if (%s = '', 0 = 0, ua = %s) and if (%s = '', 0 = 0, ip = %s)"
        total_values = [username, list_query['url'], '%' + list_query['url'] + '%', list_query['data'], '%' + list_query['data'] + '%', list_query['ua'], list_query['ua'], list_query['ip'], list_query['ip']]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(total_sql, total_values)
            total_result = cursor.fetchone()['count(0)']
            cursor.execute(sql, values)
            result = cursor.fetchall()
            data = {}
            data['total'] = total_result
            data ['result'] = result
            return data
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def xss_auth_list(self, username, pagenum, pagesize, list_query):
        
        """
        获取xss auth的信息

        :param: str username: 用户名
        :param: str pagenum: 每页显示的数据数量
        :param: str pagesize: 显示的第几页
        :param: dict list_query: 筛选目标的条件

        :return: str result:查询到的信息 or 'LXXXXX': 状态码
        """
        
        start = (int(pagenum)-1) * int(pagesize)
        pagesize = int (pagesize)
        sql = "select id, token, url, token_status from xss_auth where username = %s and if (%s = '', 0 = 0, token like %s) and if (%s = '', 0 = 0, url like %s) and if (%s = '', 0 = 0, token_status = %s) order by id desc limit %s, %s"
        values = [username, list_query['token'], '%' + list_query['token'] + '%', list_query['url'], '%' + list_query['url'] + '%', list_query['token_status'], list_query['token_status'], start, pagesize]
        total_sql = "select count(0) from xss_auth where username = %s and if (%s = '', 0 = 0, token like %s) and if (%s = '', 0 = 0, url like %s) and if (%s = '', 0 = 0, token_status = %s)"
        total_values = [username, list_query['token'], '%' + list_query['token'] + '%', list_query['url'], '%' + list_query['url'] + '%', list_query['token_status'], list_query['token_status']]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(total_sql, total_values)
            total_result = cursor.fetchone()['count(0)']
            cursor.execute(sql, values)
            result = cursor.fetchall()
            data = {}
            data['total'] = total_result
            data ['result'] = result
            return data
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def update_xss_auth(self, username, token, token_status):
        
        """
        设置目标标志位

        :param: str username: 用户名
        :param: str token: token
        :param: str token_status: token的状态

        :return: str 'LXXXXX': 状态码
        """
        
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            sql = "update xss_auth set token_status =%s where username = %s and token = %s"
            values = [token_status, username, token]
            cursor.execute(sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def change_avatar(self, username, imagename):

        """
        修改用户头像

        :param: str username: 用户名
        :param: str imagename: 图片名字
        :return: str 'LXXXXX': 状态码
        """
        sql = "update user set avatar =%s where username = %s"
        values = [imagename, username]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql, values) 
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def delete_account(self, username):
        
        """
        用来删除用户

        :param: str username: 用户名
        
        :return: 'LXXXXX': 状态码
        """

        del_sql = "delete from user where username = %s"
        values = [username]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(del_sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def delete_target(self, username, target):
        
        """
        用来删除目标

        :param: str username: 用户名
        :param: str target: 目标

        :return: 'LXXXXX': 状态码
        """
        
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            del_target_sql = "delete from target where username = %s and target = %s"
            del_vulner_sql = "delete from target_vulner where username = %s and target = %s"
            del_target_scan_sql = "delete from target_scan where username = %s and target = %s"
            del_target_domain_sql = "delete from target_domain where username = %s and target = %s"
            del_target_port_sql = "delete from target_port where username = %s and target = %s"
            del_target_path_sql = "delete from target_path where username = %s and target = %s"
            values = [username, target]
            cursor.execute(del_target_sql, values)
            cursor.execute(del_vulner_sql, values)
            cursor.execute(del_target_scan_sql, values)
            cursor.execute(del_target_domain_sql, values)
            cursor.execute(del_target_port_sql, values)
            cursor.execute(del_target_path_sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def delete_port(self, username, target, scan_ip, port):
        
        """
        用来删除端口

        :param: str username: 用户名
        :param: str target: 目标
        :param: str scan_ip: 目标ip
        :param: str port: 端口

        :return: 'LXXXXX': 状态码
        """
        
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            del_port_sql = "delete from port where username = %s and target = %s and scan_ip = %s and port = %s"
            values = [username, target, scan_ip, port]
            cursor.execute(del_port_sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def delete_vulner(self, username, target, ip_port, vulner_name):
        
        """
        用来删除目标或者漏洞

        :param: str username: 用户名
        :param: str target: 目标
        :param: str ip_port: ip和端口
        :param: str vulner_name: 漏洞名字

        :return: 'LXXXXX': 状态码
        """
        
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            del_vulner_sql = "delete from vulner where username = %s and target = %s and ip_port = %s and vulner_name = %s"
            del_target_vulner_sql = "delete from target_vulner where username = %s and target = %s and ip_port = %s and vulner_name = %s"
            values = [username, target, ip_port, vulner_name]
            cursor.execute(del_vulner_sql, values)
            cursor.execute(del_target_vulner_sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
    
    def delete_dns_log(self, username, id):
        
        """
        用来删除dns log

        :param: str username: 用户名
        :param: str id: id
        
        :return: 'LXXXXX': 状态码
        """

        del_sql = "delete from dns_log where username = %s and id = %s"
        values = [username, id]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(del_sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn

    def delete_xss_log(self, username, id):
        
        """
        用来删除xss log

        :param: str username: 用户名
        :param: str id: id
        
        :return: 'LXXXXX': 状态码
        """

        del_sql = "delete from xss_log where username = %s and id = %s"
        values = [username, id]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(del_sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
            
    def delete_xss_auth(self, username, token):
        
        """
        用来删除auth

        :param: str username: 用户名
        :param: str token: token
        
        :return: 'LXXXXX': 状态码
        """

        del_sql = "delete from xss_auth where username = %s and token = %s"
        values = [username, token]
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(del_sql, values)
            return 'L1000'
        except Exception as e:
            print(e)
            return 'L1001'
        finally:
            cursor.close()
            self.close_conn
            
    def close_conn(self, conn):
        
        """
        关闭连接

        :param: str conn: 要关闭的连接

        :return:
        
        """
        try:
            conn.close()
        except Exception as e:
            print(e)
            pass

if __name__ == '__main__':
    mysqldb = Mysql_db('192.168.202.128', '3306', 'root', '123456')
    