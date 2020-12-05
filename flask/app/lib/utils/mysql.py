#!/usr/bin/env python3

import time
import pymysql

class Mysql_db():

    __v=None

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
        flag = 0
        sql = "create database %s character set utf8 collate utf8_general_ci" %(database)
        try:
            conn = pymysql.connect(host = self.host, port = self.port, user = self.user, passwd = self.passwd, charset = self.charset)
            cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
            cursor.execute("show databases") 
            result = cursor.fetchall()
            for i in range(len(result)):
                if database == result[i]['Database']:
                    flag = 1
            if flag == 0:
                cursor.execute(sql)
        except Exception as e:
            print(e)
            return None
        finally:
            cursor.close()
            conn.close()

    def create_user(self):
        """
        创建用户表

        :param:
        :return:
        """
        flag = 0
        sql = "create table user (id integer auto_increment primary key, username varchar(128) unique, token varchar(128) unique, email varchar(128) unique, password varchar(128), user_id varchar(128), access varchar(128), avatar varchar(128)) engine = innodb default  charset = utf8;"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute("show tables")
            result = cursor.fetchall()
            for i in range(len(result)):
                if 'user' == result[i]['Tables_in_linbing']:
                    flag = 1
            if flag == 0:
                try:
                    cursor.execute(sql)
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)
            return None
        finally:
            cursor.close()
            self.close_conn

    def create_target(self):
        """
        创建目标表

        :param:
        :return:
        """
        flag = 0
        sql = "create table target (id integer auto_increment primary key, username varchar(255), target varchar(255), description varchar(255), target_ip varchar(255), create_time varchar(255), scan_time varchar(255), scan_schedule varchar(255), vulner_number varchar(255), scan_status varchar(255), trash_flag varchar(255), scanner varchar(255), min_port varchar(255), max_port varchar(255), rate varchar(255), concurren_number varchar(255)) engine = innodb default charset = utf8;"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute("show tables")
            result = cursor.fetchall()
            for i in range(len(result)):
                if 'target'  == result[i]['Tables_in_linbing']:
                    flag = 1
            if flag == 0:
                cursor.execute(sql)
            return 1
        except Exception as e:
            pass
            return 0
        finally:
            cursor.close()
            self.close_conn

    def create_target_port(self):
        """
        创建保存目标、端口等信息的表

        :param:
        :return:
        """
        flag = 0
        sql = "create table target_port (id integer auto_increment primary key, username varchar(255), target varchar(255), description varchar(255), create_time varchar(255), scan_time varchar(255), port varchar(255), product varchar(255), protocol varchar(255), version varchar(255)) engine = innodb default charset = utf8;"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute("show tables")
            result = cursor.fetchall()
            for i in range(len(result)):
                if 'target_port'  == result[i]['Tables_in_linbing']:
                    flag = 1
            if flag == 0:
                cursor.execute(sql)
            return 1
        except Exception as e:
            pass
            return 0
        finally:
            cursor.close()
            self.close_conn

    def create_target_domain(self):
        """
        创建保存目标、域名等信息的表

        :param:
        :return:
        """
        flag = 0
        sql = "create table target_domain (id integer auto_increment primary key, username varchar(255), target varchar(255), description varchar(255), create_time varchar(255), scan_time varchar(255), domain varchar(255), domain_ip varchar(255)) engine = innodb default charset = utf8;"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute("show tables")
            result = cursor.fetchall()
            for i in range(len(result)):
                if 'target_domain' == result[i]['Tables_in_linbing']:
                    flag = 1
            if flag == 0:
                cursor.execute(sql)
            return 1
        except Exception as e:
            pass
            return 0
        finally:
            cursor.close()
            self.close_conn

    def create_vulnerability(self):
        """
        创建保存漏洞信息的表

        :param:
        :return:
        """
        flag = 0
        sql = "create table vulnerability (id integer auto_increment primary key, username varchar(255), target varchar(255), description varchar(255), ip_port varchar(255), vulner_name varchar(255), vulner_descrip varchar(255), trash_flag varchar(255), time varchar(255)) engine = innodb default  charset = utf8;"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute("show tables")
            result = cursor.fetchall()
            for i in range(len(result)):
                if 'vulnerability'  == result[i]['Tables_in_linbing']:
                    flag = 1
            if flag == 0:
                cursor.execute(sql)
            return 1
        except Exception as e:
            pass
            return 0
        finally:
            cursor.close()
            self.close_conn

    def create_delete_vulnerability(self):
        """
        创建保存已删除漏洞信息的表

        :param:
        :return:
        """
        flag = 0
        sql = "create table delete_vulnerability (id integer auto_increment primary key, username varchar(255), target varchar(255), description varchar(255), ip_port varchar(255), vulner_name varchar(255), vulner_descrip varchar(255), trash_flag varchar(255), time varchar(255)) engine = innodb default  charset = utf8;"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute("show tables")
            result = cursor.fetchall()
            for i in range(len(result)):
                if 'delete_vulnerability'  == result[i]['Tables_in_linbing']:
                    flag = 1
            if flag == 0:
                cursor.execute(sql)
            return 1
        except Exception as e:
            pass
            return 0
        finally:
            cursor.close()
            self.close_conn

    def create_delete_target(self):
        """
        创建保存已删除目标信息的表

        :param:
        :return:
        """
        flag = 0
        sql = "create table delete_target (id integer auto_increment primary key, username varchar(255), target varchar(255), description varchar(255), create_time varchar(255), vulner_number varchar(255), scan_status varchar(255), scanner varchar(255), min_port varchar(255), max_port varchar(255), rate varchar(255)) engine = innodb default  charset = utf8;"
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute("show tables")
            result = cursor.fetchall()
            for i in range(len(result)):
                if 'delete_target'  == result[i]['Tables_in_linbing']:
                    flag = 1
            if flag == 0:
                cursor.execute(sql)
            return 1
        except Exception as e:
            print(e)
            pass
            return 0
        finally:
            cursor.close()
            self.close_conn

    def query(self, query_str):
        """
        查询一些信息

        :param: str query_str: 查询字符串
        :return: str 'ZXXXXX': 状态码
        """
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            if query_str['type'] == 'username':
                # 获取已注册的用户名
                sql = "select username from user "
            elif query_str['type'] == 'email':
                # 获取已注册的邮箱
                sql = "select email from user "
            else:
                # 获取用户下的目标
                sql = "select target from target where username = '%s' and  (trash_flag = 0 or trash_flag = 1)" % (query_str['username'])
            cursor.execute(sql)
            result = cursor.fetchall()
            query_list = []
            for item in result:
                query_list.append(item[query_str['type']])
            '''
            判断目标是否以添加
            '''
            if query_str['type'] == 'target':
                if query_str['data'] in query_list:
                    return 'Z10010'
            else:
                '''
                判断用户名是否已注册
                '''
                if query_str['data'] in query_list:
                    if query_str['type'] == 'username':
                        return 'Z1006'
                    else:
                        return 'Z1007'
            return 'Z1000'
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def register(self, username, token, email, password, user_id, access, avatar):
        """
        注册用户

        :param: str username: 用户名
        :param: str token: 用户凭证
        :param: str email: 注册的邮箱
        :param: str password: 用户密码
        :param: str user_id: 用户id
        :param: str access: 用户权限
        :param: str avatar: 用户头像初始值
        :return: str 'ZXXXXX': 状态码
        """
        sql = "insert into user (username, token, email, password, user_id, access, avatar) values ('%s', '%s', '%s', '%s', '%s', '%s', '%s')" %  (username, token, email, password, user_id, access, avatar)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
            return 'Z1000'
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def login(self, username):
        """
        获取用户的密码

        :param: str username: 用户名
        :return: str result: 用户的密码
        """
        sql = "select password, token from user where username = '%s' " % (username)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql) 
            result = cursor.fetchone()
            return result
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def update_token(self, username, token):
        """
        更新用户的token

        :param: str username: 用户名
        :param: str token: 用户凭证
        :return: str 'ZXXXXX': 状态码
        """
        sql =  "update user set token = '%s' where username = '%s'" % (token, username)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
            return 'Z1000'
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def userinfo(self, token):
        """
        获取用户的信息

        :param: str token: 用户凭证
        :return: str result: 用户的信息
        """
        sql = "select username, email, user_id, access, avatar from user where token = '%s' " % (token)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql) 
            result = cursor.fetchone()
            return result
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def changps(self, data):
        """
        修改用户密码

        :param: str data: 修改用户所需的数据,有所需要修改的新密码,条件字段名和条件字段值
        :return: str 'ZXXXXX': 状态码
        """
        sql = "update user set password = '%s' where %s = '%s'" % (data['password'], data['type'], data['type_data'])
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql) 
            return 'Z1000'
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def username(self, query_str):
        """
        根据条件选取用户名

        :param: str query_str: 条件字段名和条件字段值
        :return: str result:查询的结果 or 'ZXXXXX': 状态码
        """
        sql = "select username from user where %s = '%s' " % (query_str['type'],query_str['data'])
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql) 
            result = cursor.fetchone()
            return result
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def save_target(self, username, target, description, target_ip):
        """
        保存目标

        :param: str username: 用户名
        :param: str target: 目标
        :param: str description: 描述字符串
        :param: str target_ip: 目标ip
        :return: str 'ZXXXXX': 状态码
        """
        datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sql =  "insert target (username, target, description, target_ip, create_time, scan_time, scan_schedule, vulner_number, scan_status, trash_flag, scanner, min_port, max_port, rate, concurren_number) values ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')" % (username, target, description, target_ip, datetime, '0', '未开始', '0', '0', '0', 'nmap', '1', '65535', '1000', '50')
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
            return 'Z1000'
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def get_target_port(self, username, target, port):
        """
        获取目标端口的信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str port: 端口
        :return: str result: 获取到的信息 or 'ZXXXXX': 状态码
        """
        sql = "select * from target_port where username = '%s' and target = '%s' and port = '%s'" % (username, target, port)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
            result = cursor.fetchone()
            return result
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def save_target_port(self, username, target, description, port, protocol, product, version):
        """
        保存目标端口的信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str port: 端口
        :param: str protocol: 端口的协议
        :param: str product: 端口的产品
        :param: str version: 产品版本
        :return: str 'ZXXXXX': 状态码
        """
        datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sql =  "insert target_port (username, target, description, create_time, scan_time, port, protocol, product, version) values ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')" % (username, target, description, datetime, datetime, port, protocol, product, version)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
            return 'Z1000'
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def update_target_port(self, username, target, description, port, protocol, product, version):
        """
        更新目标端口的信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str port: 端口
        :param: str protocol: 端口的协议
        :param: str product: 端口的产品
        :param: str version: 产品版本
        :return: str 'ZXXXXX': 状态码
        """
        datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sql = "update target_port set description = '%s', scan_time = '%s', port = '%s', protocol = '%s', product = '%s', version = '%s' where username = '%s' and target = '%s'" % (description, datetime, port, protocol, product, version, username, target)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
            return 'Z1000'
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def get_target_domain(self, username, target, domain):
        """
        获取目标域名的的信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str domain: 域名
        :return: str result 查询到的信息 or 'ZXXXXX': 状态码
        """
        sql = "select * from target_domain where username = '%s' and target = '%s' and domain = '%s'" % (username, target, domain)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
            result = cursor.fetchone()
            return result
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def save_target_domain(self, username, target, description, domain, domain_ip):
        """
        保存目标域名的信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str domain: 域名
        :param: str domain_ip: 域名的ip
        :return: str 'ZXXXXX': 状态码
        """
        datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sql =  "insert target_domain (username, target, description, create_time, scan_time, domain, domain_ip) values ('%s', '%s', '%s', '%s', '%s', '%s', '%s')" % (username, target, description, datetime, datetime, domain, domain_ip)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
            return 'Z1000'
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def update_target_domain(self, username, target, domain, domain_ip):
        """
        更新目标域名的信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str domain: 域名
        :param: str domain_ip: 域名的ip
        :return: str 'ZXXXXX': 状态码
        """
        datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sql = "update target_domain set scan_time = '%s', domain = '%s', domain_ip = '%s' where username = '%s' and target = '%s'" % (datetime, domain, domain_ip, username, target)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
            return 'Z1000'
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def get_target(self, username):
        """
        获取用户目标的信息

        :param: str username: 用户名
        :return: str result:查询到的信息 or 'ZXXXXX': 状态码
        """
        sql = "select * from target where username = '%s' " % (username)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
            result = cursor.fetchone()
            return result
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn
    
    def update_target_vulnernumber(self, username, target):
        """
        更新目标的漏洞数量

        :param: str username: 用户名
        :param: str target: 目标
        :return: str result:查询到的信息 or 'ZXXXXX': 状态码
        """
        
        total_sql = "select count(0) from vulnerability where username = '%s' and target = '%s' and trash_flag = '0' " % (username, target)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(total_sql)
            total_result = cursor.fetchone()['count(0)']
            sql =  "update target set vulner_number = '%s' where username = '%s' and target = '%s'" % (total_result, username, target)
            cursor.execute(sql)
            return 'Z1000'
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def scan_set(self, username, target, scanner, min_port, max_port, rate, concurren_number):
        """
        设置扫描选项

        :param: str username: 用户名
        :param: str target: 目标
        :param: str scanner: 选择的端口扫描器
        :param: str min_port: 扫描范围的最小端口
        :param: str max_port: 扫描范围的最大端口
        :return: str 'ZXXXXX': 状态码
        """
        sql =  "update target set scanner = '%s', min_port = '%s', max_port = '%s', rate = '%s', concurren_number = '%s' where username = '%s' and target = '%s'" % (scanner, min_port, max_port, rate, concurren_number, username, target)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
            return 'Z1000'
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def get_scan(self, username, target):
        """
        获取扫描选项信息

        :param: str username: 用户名
        :param: str target: 目标
        :return: str 'ZXXXXX': 状态码
        """
        sql = "select scanner, min_port, max_port, rate, concurren_number from target where username = '%s' and target = '%s' " % (username, target)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql) 
            result = cursor.fetchone()
            return result
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def start_scan(self, username, target):
        """
        开始扫描选项

        :param: str username: 用户名
        :param: str target: 目标
        :return: str 'ZXXXXX': 状态码
        """
        datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sql =  "update target set scan_time = '%s', scan_status = '%s', scan_schedule = '%s' where username = '%s' and target = '%s'" % (datetime, '1', '准备开始扫描', username, target)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
            return 'Z1000'
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def update_scan(self, username, target, scan_schedule):
        """
        更新扫描选项信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str scan_schedule: 扫描的状态
        :return: str 'ZXXXXX': 状态码
        """
        sql =  "update target set scan_schedule = '%s' where username = '%s' and target = '%s'" % (scan_schedule, username, target)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
            return 'Z1000'
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def save_vulnerability(self, username, target, description, ip_port, vulner_name, vulner_descrip):
        """
        保存漏洞信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str description: 目标的描述信息
        :param: str ip_port: 存在漏洞的ip和端口
        :param: str vulner_name: 漏洞名字
        :param: str vulner_descrip: 漏洞的描述信息
        :return: str 'ZXXXXX': 状态码
        """
        datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sql = "insert vulnerability (username, target, description, ip_port, vulner_name, vulner_descrip, trash_flag, time) values ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')" % (username, target, description, ip_port, vulner_name, vulner_descrip, '0', datetime)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
            return 'Z1000'
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def update_vulnerability(self, username, target, ip_port, vulner_name):
        """
        更新漏洞信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str ip_port: 存在漏洞的ip和端口
        :param: str vulner_name: 漏洞名字
        :return: str 'ZXXXXX': 状态码
        """
        datetime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        sql = "update vulnerability set time = '%s' where username = '%s' and target = '%s' and ip_port = '%s' and vulner_name = '%s'" % (datetime, username, target, ip_port, vulner_name)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
            return 'Z1000'
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def get_vulnerability(self, username, target, ip_port, vulner_name):
        """
        获取漏洞的相关信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str ip_port: 存在漏洞的ip和端口
        :param: str vulner_name: 漏洞名字
        :return: str 'ZXXXXX': 状态码
        """
        sql = "select * from vulnerability where username = '%s' and target = '%s' and ip_port = '%s' and vulner_name = '%s' " % (username, target, ip_port, vulner_name)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql)
            result = cursor.fetchone()
            return result
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def target_list(self, username, pagenum, pagesize, flag):
        """
        获取所有目标的信息

        :param: str username: 用户名
        :param: str pagenum: 每页显示的数据数量
        :param: str pagesize: 显示的第几页
        :param: str flag: 筛选目标的标识位
        :return: str 'ZXXXXX': 状态码
        """
        start = (int(pagenum)-1) * int(pagesize)
        pagesize = int (pagesize)
        sql = "select target, description, create_time, scan_time, vulner_number, scan_schedule from target where username = '%s' and trash_flag = '%s' limit %s, %s" % (username, flag, start, pagesize)
        total_sql = "select count(0) from target where username = '%s' and trash_flag = '%s' " % (username, flag)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(total_sql)
            total_result = cursor.fetchone()['count(0)']
            cursor.execute(sql)
            result = cursor.fetchall()
            data = {}
            data['total'] = total_result
            data ['result'] = result
            return data
        except Exception as e:
            print(e)
            return 'Z1001'
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
        :return: str 'ZXXXXX': 状态码
        """
        start = (int(pagenum)-1) * int(pagesize)
        pagesize = int (pagesize)
        sql = "select target, description, create_time, scan_time, port, product, protocol, version from target_port where username = '%s' and target = '%s' limit %s, %s" % (username, target, start, pagesize)
        total_sql = "select count(0) from target_port where username = '%s' and target = '%s' " % (username, target)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(total_sql)
            total_result = cursor.fetchone()['count(0)']
            cursor.execute(sql)
            result = cursor.fetchall()
            data = {}
            data['total'] = total_result
            data ['result'] = result
            return data
        except Exception as e:
            print(e)
            return 'Z1001'
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
        :return: str 'ZXXXXX': 状态码
        """
        start = (int(pagenum)-1) * int(pagesize)
        pagesize = int (pagesize)
        sql = "select target, description, scan_time, domain, domain_ip from target_domain where username = '%s' and target = '%s' limit %s, %s" % (username, target, start, pagesize)
        total_sql = "select count(0) from target_domain where username = '%s' and target = '%s'" % (username, target)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(total_sql)
            total_result = cursor.fetchone()['count(0)']
            cursor.execute(sql)
            result = cursor.fetchall()
            data = {}
            data['total'] = total_result
            data ['result'] = result
            return data
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def scan_list(self, username, pagenum, pagesize, flag):
        """
        获取所有扫描任务的信息

        :param: str username: 用户名
        :param: str pagenum: 每页显示的数据数量
        :param: str pagesize: 显示的第几页
        :param: str flag: 筛选目标的标识位
        :return: str 'ZXXXXX': 状态码
        """
        start = (int(pagenum)-1) * int(pagesize)
        pagesize = int (pagesize)
        scan_sql = "select target, description, create_time, scan_time, vulner_number, scan_schedule from target where username = '%s' and trash_flag = '%s' and scan_status = '%s' limit %s, %s" % (username, flag, '1', start, pagesize)
        scan_total_sql = "select count(0) from target where username = '%s' and trash_flag = '%s' and scan_status = '%s' " % (username, flag, '1')
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(scan_total_sql)
            total_result = cursor.fetchone()['count(0)']
            cursor.execute(scan_sql)
            result = cursor.fetchall()
            data = {}
            data['total'] = total_result
            data ['result'] = result
            return data
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def vulner_list(self, username, target, pagenum, pagesize):
        """
        获取目标所有漏洞的信息

        :param: str username: 用户名
        :param: str target: 目标
        :param: str pagenum: 每页显示的数据数量
        :param: str pagesize: 显示的第几页
        
        :return: str 'ZXXXXX': 状态码
        """
        start = (int(pagenum)-1) * int(pagesize)
        pagesize = int (pagesize)
        sql = "select id, target, description, ip_port, vulner_name, vulner_descrip, time from vulnerability where username = '%s' and target = '%s' and trash_flag = '%s' limit %s, %s" % (username, target, '0', start, pagesize)
        total_sql = "select count(0) from vulnerability where username = '%s' and target = '%s' and trash_flag = '%s' " % (username, target, '0')
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(total_sql)
            total_result = cursor.fetchone()['count(0)']
            cursor.execute(sql)
            result = cursor.fetchall()
            data = {}
            data['total'] = total_result
            data ['result'] = result
            return data
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def all_vulner_list(self, username, pagenum, pagesize, flag):
        """
        获取所有漏洞的信息

        :param: str username: 用户名
        :param: str pagenum: 每页显示的数据数量
        :param: str pagesize: 显示的第几页
        :param: str flag: 筛选目标的标识位
        :return: str 'ZXXXXX': 状态码
        """
        start = (int(pagenum)-1) * int(pagesize)
        pagesize = int (pagesize)
        sql = "select id, target, description, ip_port, vulner_name, vulner_descrip, time from vulnerability where username = '%s' and trash_flag = '%s' limit %s, %s" % (username, flag['data'], start, pagesize)
        total_sql = "select count(0) from vulnerability where username = '%s' and trash_flag = '%s' " % (username, flag['data'])
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(total_sql)
            total_result = cursor.fetchone()['count(0)']
            cursor.execute(sql)
            result = cursor.fetchall()
            data = {}
            data['total'] = total_result
            data ['result'] = result
            return data
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def set_flag(self, username, target, flag):
        """
        设置目标选项标志位

        :param: str username: 用户名
        :param: str target: 目标
        :param: str flag: 筛选目标的标识位
        :return: str 'ZXXXXX': 状态码
        """
        if flag['type'] == 'target':
            sql = "update target set trash_flag ='%s'  where username = '%s' and target = '%s'" % (flag['data'], username, target)
            vuln_sql = "update vulnerability set trash_flag ='%s' where username = '%s' and target = '%s'" % (flag['data'], username, target)
        else:
            vuln_sql = "update vulnerability set trash_flag ='%s' where id = '%s'" % (flag['data'], flag['id'])
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            if flag['type'] == 'target':
                cursor.execute(sql)
                cursor.execute(vuln_sql)
            else:
                cursor.execute(vuln_sql)
            return 'Z1000'
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def change_avatar(self, username, imagename):
        """
        修改用户头像

        :param: str username: 用户名
        :param: str imagename: 图片名字
        :return: str 'ZXXXXX': 状态码
        """
        sql = "update user set avatar ='%s' where username = '%s' " % (imagename, username,)
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(sql) 
            return 'Z1000'
        except Exception as e:
            print(e)
            return 'Z1001'
        finally:
            cursor.close()
            self.close_conn

    def delete(self, username, target, flag):
        """
        用来删除目标或者漏洞

        :param: str username: 用户名
        :param: str target: 目标
        :param: str flag: 筛选目标的标志位
        :return: 'ZXXXXX': 状态码
        """
        if flag['type'] == 'target':
            query_sql = "select * from target where username = '%s' and target = '%s'" % (username, target)
            del_target_sql = "delete from target where username = '%s' and target = '%s'" % (username, target)
            del_vulner_sql = "delete from vulnerability where username = '%s' and target = '%s'" % (username, target)
            del_target_port_sql = "delete from target_port where username = '%s' and target = '%s'" % (username, target)
            del_target_domain_sql = "delete from target_domain where username = '%s' and target = '%s'" % (username, target)
        else:
            query_sql = "select * from vulnerability where id = '%s'" % (flag['id'])
            del_target_sql = "delete from vulnerability where id = '%s'" % (flag['id'])
        conn = self.get_conn()
        cursor = conn.cursor(cursor = pymysql.cursors.DictCursor)
        try:
            cursor.execute(query_sql)
            result = cursor.fetchall()
            if flag['type'] == 'target':
                save_sql = "insert delete_target (username, target, description, create_time, vulner_number, scan_status, scanner, min_port, max_port, rate) values ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')" % (result[0]['username'], result[0]['target'], result[0]['description'], result[0]['create_time'], result[0]['vulner_number'], result[0]['scan_status'], result[0]['scanner'], result[0]['min_port'], result[0]['max_port'], result[0]['rate'])
                cursor.execute(del_vulner_sql)
                cursor.execute(del_target_port_sql)
                cursor.execute(del_target_domain_sql)
            else:
                save_sql = "insert delete_vulnerability (username, target, description, ip_port, vulner_name, vulner_descrip, time) values ('%s', '%s', '%s', '%s', '%s', '%s', '%s')" % (result[0]['username'], result[0]['target'], result[0]['description'], result[0]['ip_port'], result[0]['vulner_name'], result[0]['vulner_descrip'], result[0]['time'])
            cursor.execute(save_sql)
            cursor.execute(del_target_sql)
            return 'Z1000'
        except Exception as e:
            print(e)
            return 'Z1001'
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
    mysqldb = Mysql_db()
    mysqldb.create_database('linbing')
    mysqldb.create_user()
    mysqldb.create_target()
    mysqldb.create_target_port()
    mysqldb.create_target_domain()
    mysqldb.create_vulnerability()
    mysqldb.create_delete_vulnerability()
    mysqldb.create_delete_target()