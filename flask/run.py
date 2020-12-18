#!/usr/bin/env python3

import os
import re
import sys
import json
import time
import random
import string 
import socket
import hashlib
import configparser
from IPy import IP
from urllib.parse import urlparse
from flask_cors import *
from flask import Flask, request, redirect,url_for, send_from_directory
#from werkzeug import SharedDataMiddleware
from werkzeug.middleware.shared_data import SharedDataMiddleware
from werkzeug.utils import secure_filename
from app.lib.utils.mysql import Mysql_db
from app.lib.utils.sendmail import MailSender
from app.lib.crypto.rsa import Rsa_Crypto
from app.lib.crypto.aes import Aes_Crypto
from app.multiplythread import Multiply_Thread

UPLOAD_FOLDER = 'images'  #文件存放路径
if not os.path.exists("images"):
    os.mkdir("images")
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif']) #限制上传文件格式

DATABASE = sys.path[0]+'/mydb.db'
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
CORS(app, supports_credentials=True)
config = configparser.ConfigParser()
config.read('conf.ini')
sender = MailSender('linbing@xip.io', '127.0.0.1')
mysqldb = Mysql_db(config.get('mysql', 'ip'), config.get('mysql', 'port'), config.get('mysql', 'username'), config.get('mysql', 'password'))
mysqldb.create_database('linbing')
mysqldb.create_user()
mysqldb.create_target()
mysqldb.create_target_port()
mysqldb.create_target_domain()
mysqldb.create_vulnerability()
mysqldb.create_delete_target()
mysqldb.create_delete_vulnerability()
aes_crypto = Aes_Crypto(config.get('Aes', 'key'), config.get('Aes', 'iv'))
rsa_crypto = Rsa_Crypto()

def parse_target(target):
    """
    解析目标为ip格式

    :param str target: 待解析的目标
    :return: str scan_ip: 解析后的ip和域名
    """
    scan_ip = ''
    domain_result = ''
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
                    net = IP(target)
                    #print(net.len())
                    scan_ip = net
            else:
                scan_ip = ip_result[0]
        else:
            url_parse = urlparse(target)
            domain_regex = re.compile(r'(?:[A-Z0-9_](?:[A-Z0-9-_]{0,247}[A-Z0-9])?\.)+(?:[A-Z]{2,6}|[A-Z0-9-]{2,}(?<!-))\Z', re.IGNORECASE)
            domain_result = domain_regex.findall(url_parse.netloc)
            scan_ip = url_parse.hostname
    except Exception as e:
        print(e)
    finally:
        pass
    return scan_ip, domain_result

def allowed_file(filename):
    """
    设置允许上传的文件名后缀

    :param str filename: 上传的文件名
    :return:
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/query', methods = ['POST'])
def query():
    """
    查询的接口,用来查询用户名或者邮箱是否已注册

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            if  request_data['type'] == 'target':
                token = request_data['data']['token']
                query_str = {
                    'type': 'token',
                    'data': token
                }
                username_result = mysqldb.username(query_str)
                if username_result == 'Z1001':
                    response_data['code'] = 'Z1001'
                    response_data['message'] = '系统异常'
                    return str(response_data)
                elif username_result == None:
                    response_data['code'] = 'Z1004'
                    response_data['message'] = '认证失败'
                    return str(response_data)
                request_data = {
                    'type': 'target',
                    'username': username_result['username'],
                    'data': aes_crypto.encrypt(request_data ['data']['data'])
                }
                query_result = mysqldb.query(request_data)
                response_data['code'] = query_result
                if response_data['code'] == 'Z1000':
                    response_data['message'] = '请求成功'
                elif response_data['code'] == 'Z1001':
                    response_data['message'] = '系统异常'
                elif response_data['code'] == 'Z10010':
                    response_data['message'] = '目标已存在'
                return str(response_data)
            query_result = mysqldb.query(request_data)
            response_data['code'] = query_result
            if response_data['code'] == 'Z1000':
                response_data['message'] = '请求成功'
            elif response_data['code'] == 'Z1001':
                response_data['message'] = '系统异常'
            elif response_data['code'] == 'Z1007':
                response_data['message'] = '邮箱已注册'
            elif response_data['code'] == 'Z10010':
                response_data['message'] = '目标已存在'
            elif response_data['code'] == 'Z1006':
                response_data['message'] = '用户名已注册'
            return str(response_data)
        else:
            response_data['code'] = 'Z1002'
            response_data['message'] = '请求方法异常'
            return str(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'Z1001'
        response_data['message'] = '系统异常'
        return str(response_data)

@app.route('/api/getchecknum', methods = ['POST'])
def getchecknum ():
    """
    获取邮箱验证码

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            email = request_data['data']
            send_result = sender.sendMail(email)
            if send_result[0] == 'Z1003':
                response_data['code'] = send_result[0]
                response_data['message'] = '发送邮件异常'
                return str(response_data)
            else:
                response_data['code'] = send_result[0]
                response_data['message'] = '请求成功'
                response_data['data'] = aes_crypto.encrypt(send_result[1])
                return str(response_data)
        else:
            response_data['code'] = 'Z1002'
            response_data['message'] = '请求方法异常'
            return str(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'Z1001'
        response_data['message'] = '系统异常'
        return str(response_data)

@app.route('/api/register', methods = ['POST'])
def register():
    """
    注册的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            username = aes_crypto.encrypt(request_data['username'])
            email = aes_crypto.encrypt(request_data['email'])
            password = aes_crypto.encrypt(request_data['password'])
            user_id = '1'
            access = 'super_admin'
            avatar  = 'default.png'
            random_str = ''
            words = ''.join((string.ascii_letters,string.digits))
            for i in range(8):
                random_str = random_str + random.choice(words)
            token = aes_crypto.encrypt(username + random_str)
            register_result = mysqldb.register(username, token, email, password, user_id, access, avatar)
            response_data['code'] = register_result
            if response_data['code'] == 'Z1000':
                response_data['message'] = '请求成功'
            else:
                response_data['message'] = '系统异常'
            return str(response_data)
        else:
            response_data['code'] = 'Z1002'
            response_data['message'] = '请求方法异常'
            return str(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'Z1001'
        response_data['message'] = '系统异常'
        return str(response_data)

@app.route('/api/findpassword', methods = ['POST'])
def findpassword():
    """
    找回密码的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            username = aes_crypto.encrypt(request_data['username'])
            password = aes_crypto.encrypt(request_data['password'])
            email = aes_crypto.encrypt(request_data['email'])
            query_str = {
                'type': 'email',
                'data': email
            }
            query_result = mysqldb.username(query_str)['username']
            if query_result == 'Z1001':
                response_data['code'] = 'Z1001'
                response_data['message'] = '系统异常'
                return str(response_data)
            else:
                if username != query_result:
                    # print(username,query_result)
                    response_data['code'] = 'Z1004'
                    response_data['message'] = '认证失败'
                    return str(response_data)
                else:
                    data = {
                        'type': 'email',
                        'type_data': email,
                        'password': password
                   }
                    result = mysqldb.changps(data)
                    if result == 'Z1000':
                        response_data['code'] = 'Z1000'
                        response_data['message'] = '请求成功'
                        return str(response_data)
                    else:
                        response_data['code'] = 'Z1001'
                        response_data['message'] = '系统异常'
                        return str(response_data)
            return str(response_data)
        else:
            response_data['code'] = 'Z1002'
            response_data['message'] = '请求方法异常'
            return str(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'Z1001'
        response_data['message'] = '系统异常'
        return str(response_data)

@app.route('/api/login', methods = ['POST'])
def login():
    """
    登陆的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            username = aes_crypto.encrypt(request_data['username'])
            password = aes_crypto.encrypt(request_data['password'])
            login_result = mysqldb.login(username)
            if login_result == 'Z1001':
                response_data['code'] = 'Z1001'
                response_data['message'] = '系统异常'
                return  str(response_data)
            elif login_result == None:
                response_data['code'] = 'Z1005'
                response_data['message'] = '用户未注册'
                return  str(response_data)
            elif login_result['password'] != password:
                response_data['code'] = 'Z1008'
                response_data['message'] = '密码错误'
                return  str(response_data)
            else:
                response_data['code'] = 'Z1000'
                response_data['message'] = '请求成功'
                response_data['data'] = {'token': login_result['token']}
                return  str(response_data)
        else:
            response_data['code'] = 'Z1002'
            response_data['message'] = '请求方法异常'
            return str(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'Z1001'
        response_data['message'] = '系统异常'
        return str(response_data)

@app.route('/api/getuserinfo', methods = ['POST'])
def getuserinfo():
    """
    获取用户信息的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            token = request_data['token']
            userinfo_result = mysqldb.userinfo(token)
            if userinfo_result == 'Z1001':
                response_data['code'] = 'Z1001'
                response_data['message'] = '系统异常'
                return str(response_data)
            elif userinfo_result == None:
                response_data['code'] = 'Z1004'
                response_data['message'] = '认证失败'
                return str(response_data)
            else:
                response_data['code'] = 'Z1000'
                response_data['message'] = '请求成功'
                response_data['data'] = {
                    'username': userinfo_result['username'],
                    'email': userinfo_result['email'],
                    'user_id': userinfo_result['user_id'],
                    'access': userinfo_result['access'],
                    'avatar': userinfo_result['avatar']
                    }
                return  str(response_data)
        else:
            response_data['code'] = 'Z1002'
            response_data['message'] = '请求方法异常'
            return str(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'Z1001'
        response_data['message'] = '系统异常'
        return str(response_data)

@app.route('/api/changepassword', methods = ['POST'])
def changpassword():
    """
    修改用户密码的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            old_password = aes_crypto.encrypt(request_data['oldpassword'])
            new_password = aes_crypto.encrypt(request_data['newpassword'])
            token = request_data['token']
            query_str = {
                    'type': 'token',
                    'data': token
                }
            username_result = mysqldb.username(query_str)
            if username_result == 'Z1001':
                response_data['code'] = 'Z1001'
                response_data['message'] = '系统异常'
                return str(response_data)
            elif username_result == None:
                response_data['code'] = 'Z1004'
                response_data['message'] = '认证失败'
                return str(response_data)
            else:
                username = username_result['username']
                password_result = mysqldb.login(username)['password']
                data = {
                    'type': 'token',
                    'type_data': token,
                    'password': new_password
                }
                changps_result = mysqldb.changps(data)
                if password_result != old_password:
                    response_data['code'] = 'Z1008'
                    response_data['message'] = '密码错误'
                    return  str(response_data)
                else:
                    if changps_result == 'Z1000':
                        response_data['code'] = 'Z1000'
                        response_data['message'] = '请求成功'
                        return str(response_data)
                    else:
                        response_data['code'] = 'Z1001'
                        response_data['message'] = '系统异常'
                        return str(response_data)
        else:
            response_data['code'] = 'Z1002'
            response_data['message'] = '请求方法异常'
            return str(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'Z1001'
        response_data['message'] = '系统异常'
        return str(response_data)

@app.route('/api/save', methods = ['POST'])
def save_target():
    """
    保存目标的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            target_data = request_data['target']
            target_list = target_data.split(';')
            token = request_data['token']
            query_str = {
                    'type': 'token',
                    'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'Z1001':
                response_data['code'] = 'Z1001'
                response_data['message'] = '系统异常'
                return str(response_data)
            elif username_result == None:
                response_data['code'] = 'Z1004'
                response_data['message'] = '认证失败'
                return str(response_data)
            else:
                for target in target_list:
                    target = target.strip()
                    scan_ip = parse_target(target)[0]
                    if not scan_ip:
                        scan_ip = target
                    target = aes_crypto.encrypt(target)
                    description = aes_crypto.encrypt(request_data['description'])
                    save_result = mysqldb.save_target(username_result['username'], target, description, scan_ip)
                    if save_result == 'Z1000':
                        pass
                    else :
                        response_data['code'] = 'Z1001'
                        response_data['message'] = '系统异常'
                        return str(response_data)
                response_data['code'] = 'Z1000'
                response_data['message'] = '请求正常'
                return str(response_data)
        else:
            response_data['code'] = 'Z1002'
            response_data['message'] = '请求方法异常'
            return str(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'Z1001'
        response_data['message'] = '系统异常'
        return str(response_data)

@app.route('/api/scan_set', methods = ['POST'])
def scan_set():
    """
    设置扫描选项的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            target = aes_crypto.encrypt(request_data['target'])
            token = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'Z1001':
                response_data['code'] = 'Z1001'
                response_data['message'] = '系统异常'
                return str(response_data)
            elif username_result == None:
                response_data['code'] = 'Z1004'
                response_data['message'] = '认证失败'
                return str(response_data)
            else:
                save_result = mysqldb.scan_set(username_result['username'], target, request_data['scanner'], request_data['min_port'], request_data['max_port'], request_data['rate'], request_data['concurren_number'])
                if save_result == 'Z1000':
                    response_data['code'] = 'Z1000'
                    response_data['message'] = '请求正常'
                    return str(response_data)
                else :
                    response_data['code'] = 'Z1001'
                    response_data['message'] = '系统异常'
                    return str(response_data)
        else:
            response_data['code'] = 'Z1002'
            response_data['message'] = '请求方法异常'
            return str(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'Z1001'
        response_data['message'] = '系统异常'
        return str(response_data)

@app.route('/api/scan', methods = ['POST'])
def start_scan():
    """
    开始扫描的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            target = aes_crypto.encrypt(request_data['target'])
            description = aes_crypto.encrypt(request_data['description'])
            token = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'Z1001':
                response_data['code'] = 'Z1001'
                response_data['message'] = '系统异常'
                return str(response_data)
            elif username_result == None:
                response_data['code'] = 'Z1004'
                response_data['message'] = '认证失败'
                return str(response_data)
            else:
                target = aes_crypto.decrypt(target)
                scan_ip = parse_target(target)[0]
                domain = parse_target(target)[1]
                if not scan_ip:
                    response_data['code'] = 'Z1020'
                    response_data['message'] = '添加的目标无法解析,请重新输入'
                    return str(response_data)
                save_result = mysqldb.start_scan(username_result['username'], aes_crypto.encrypt(target))
                multiply_thread = Multiply_Thread(mysqldb, aes_crypto)
                scan_data = {
                    'username': username_result['username'],
                    'target': aes_crypto.encrypt(target),
                    'description': description,
                    'scan_ip': scan_ip,
                    'domain': domain
                }
                multiply_thread.async_exe(multiply_thread.run, (), scan_data)
                if save_result == 'Z1000':
                    response_data['code'] = 'Z1000'
                    response_data['message'] = '请求正常'
                    return str(response_data)
                else :
                    response_data['code'] = 'Z1001'
                    response_data['message'] = '系统异常'
                    return str(response_data)
        else:
            response_data['code'] = 'Z1002'
            response_data['message'] = '请求方法异常'
            return str(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'Z1001'
        response_data['message'] = '系统异常'
        return str(response_data)

@app.route('/api/targetlist', methods = ['POST'])
def target_list():
    """
    获取所有目标的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': '', 'total': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            pagenum = request_data['pagenum']
            pagesize = request_data['pagesize']
            flag = request_data['flag']
            token  = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'Z1001':
                response_data['code'] = 'Z1001'
                response_data['message'] = '系统异常'
                return str(response_data)
            elif username_result == None:
                response_data['code'] = 'Z1004'
                response_data['message'] = '认证失败'
                return str(response_data)
            else:
                sql_result = mysqldb.target_list(username_result['username'], pagenum, pagesize, flag)
                target_list = sql_result['result']
                total = sql_result['total']
                if target_list == None:
                    response_data['code'] = 'Z1009'
                    response_data['message'] = '数据为空'
                elif target_list == 'Z1001':
                    response_data['code'] = 'Z1001'
                    response_data['message'] = '系统异常'
                else :
                    response_data['code'] = 'Z1000'
                    response_data['message'] = '请求成功'
                    for target in target_list:
                        target['target'] = aes_crypto.decrypt(target['target'])
                        target['description'] = aes_crypto.decrypt(target['description'])
                    response_data['total'] = total
                    if total == 0:
                        response_data['data'] = ''
                    else:
                        response_data['data'] = sql_result
                    return str(response_data)
        else:
            response_data['code'] = 'Z1002'
            response_data['message'] = '请求方法异常'
            return str(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'Z1001'
        response_data['message'] = '系统异常'
        return str(response_data)

@app.route('/api/scanlist', methods = ['POST'])
def scan_list():
    """
    获取所有扫描信息的接口

    :param:
    :return str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': '', 'total': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            pagenum = request_data['pagenum']
            pagesize = request_data['pagesize']
            flag = request_data['flag']
            token  = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'Z1001':
                response_data['code'] = 'Z1001'
                response_data['message'] = '系统异常'
                return str(response_data)
            elif username_result == None:
                response_data['code'] = 'Z1004'
                response_data['message'] = '认证失败'
                return str(response_data)
            else:
                sql_result = mysqldb.scan_list(username_result['username'], pagenum, pagesize, flag)
                scan_list = sql_result['result']
                total = sql_result['total']
                if scan_list == None:
                    response_data['code'] = 'Z1009'
                    response_data['message'] = '数据为空'
                elif scan_list == 'Z1001':
                    response_data['code'] = 'Z1001'
                    response_data['message'] = '系统异常'
                else :
                    response_data['code'] = 'Z1000'
                    response_data['message'] = '请求成功'
                    for scan in scan_list:
                        scan['target'] = aes_crypto.decrypt(scan['target'])
                        scan['description'] = aes_crypto.decrypt(scan['description'])
                    response_data['total'] = total
                    if total == 0:
                        response_data['data'] = ''
                    else:
                        response_data['data'] = sql_result
                    return str(response_data)
        else:
            response_data['code'] = 'Z1002'
            response_data['message'] = '请求方法异常'
            return str(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'Z1001'
        response_data['message'] = '系统异常'
        return str(response_data)

@app.route('/api/vulnerlist', methods = ['POST'])
def vuln_list():
    """
    获取所有漏洞信息的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': '', 'total': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            pagenum = request_data['pagenum']
            pagesize = request_data['pagesize']
            flag = request_data['flag']
            token  = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'Z1001':
                response_data['code'] = 'Z1001'
                response_data['message'] = '系统异常'
                return str(response_data)
            elif username_result == None:
                response_data['code'] = 'Z1004'
                response_data['message'] = '认证失败'
                return str(response_data)
            else:
                sql_result = mysqldb.all_vulner_list(username_result['username'], pagenum, pagesize, flag)
                vulner_list = sql_result['result']
                total = sql_result['total']
                if vulner_list == None:
                    response_data['code'] = 'Z1009'
                    response_data['message'] = '数据为空'
                elif vulner_list == 'Z1001':
                    response_data['code'] = 'Z1001'
                    response_data['message'] = '系统异常'
                else :
                    response_data['code'] = 'Z1000'
                    response_data['message'] = '请求成功'
                    for vulner in vulner_list:
                        vulner['target'] = aes_crypto.decrypt(vulner['target'])
                        vulner['description'] = aes_crypto.decrypt(vulner['description'])
                        vulner['ip_port'] = aes_crypto.decrypt(vulner['ip_port'])
                        vulner['vulner_name'] = aes_crypto.decrypt(vulner['vulner_name'])
                        vulner['vulner_descrip'] = aes_crypto.decrypt(vulner['vulner_descrip'])
                    response_data['total'] = total
                    if total == 0:
                        response_data['data'] = ''
                    else:
                        response_data['data'] = sql_result
                    return str(response_data)
        else:
            response_data['code'] = 'Z1002'
            response_data['message'] = '请求方法异常'
            return str(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'Z1001'
        response_data['message'] = '系统异常'
        return str(response_data)

@app.route('/api/domaindetail', methods = ['POST'])
def doamin_detail():
    """
    获取域名详情的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            pagenum = request_data['pagenum']
            pagesize = request_data['pagesize']
            target = request_data['target']
            target = aes_crypto.encrypt(target)
            token  = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'Z1001':
                response_data['code'] = 'Z1001'
                response_data['message'] = '系统异常'
                return str(response_data)
            elif username_result == None:
                response_data['code'] = 'Z1004'
                response_data['message'] = '认证失败'
                return str(response_data)
            else:
                sql_result = mysqldb.target_domain_list(username_result['username'], target, pagenum, pagesize)
                domain_list = sql_result['result']
                total = sql_result['total']
                if domain_list == None:
                    response_data['code'] = 'Z1009'
                    response_data['message'] = '数据为空'
                elif domain_list == 'Z1001':
                    response_data['code'] = 'Z1001'
                    response_data['message'] = '系统异常'
                else:
                    response_data['code'] = 'Z1000'
                    response_data['message'] = '请求成功'
                    for domain in domain_list:
                        domain['target'] = aes_crypto.decrypt(domain['target'])
                        domain['description'] = aes_crypto.decrypt(domain['description'])
                        domain['scan_time'] = domain['scan_time']
                        domain['domain'] = aes_crypto.decrypt(domain['domain'])
                        domain['domain_ip'] = aes_crypto.decrypt(domain['domain_ip'])
                    response_data['total'] = total
                    if total == 0:
                        response_data['data'] = ''
                    else:
                        response_data['data'] = sql_result
                    return str(response_data)
        else:
            response_data['code'] = 'Z1002'
            response_data['message'] = '请求方法异常'
            return str(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'Z1001'
        response_data['message'] = '系统异常'
        return str(response_data)

@app.route('/api/portdetail', methods = ['POST'])
def port_detail():
    """
    获取端口详情的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            pagenum = request_data['pagenum']
            pagesize = request_data['pagesize']
            target = request_data['target']
            target = aes_crypto.encrypt(target)
            token  = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'Z1001':
                response_data['code'] = 'Z1001'
                response_data['message'] = '系统异常'
                return str(response_data)
            elif username_result == None:
                response_data['code'] = 'Z1004'
                response_data['message'] = '认证失败'
                return str(response_data)
            else:
                sql_result = mysqldb.target_port_list(username_result['username'], target, pagenum, pagesize)
                port_list = sql_result['result']
                total = sql_result['total']
                if port_list == None:
                    response_data['code'] = 'Z1009'
                    response_data['message'] = '数据为空'
                elif port_list == 'Z1001':
                    response_data['code'] = 'Z1001'
                    response_data['message'] = '系统异常'
                else:
                    response_data['code'] = 'Z1000'
                    response_data['message'] = '请求成功'
                    for port in port_list:
                        port['target'] = aes_crypto.decrypt(port['target'])
                        port['description'] = aes_crypto.decrypt(port['description'])
                        port['scan_time'] = port['scan_time']
                        port['port'] = aes_crypto.decrypt(port['port'])
                        port['product'] = aes_crypto.decrypt(port['product'])
                        port['protocol'] = aes_crypto.decrypt(port['protocol'])
                        port['version'] = aes_crypto.decrypt(port['version'])
                    response_data['total'] = total
                    if total == 0:
                        response_data['data'] = ''
                    else:
                        response_data['data'] = sql_result
                    return str(response_data)
        else:
            response_data['code'] = 'Z1002'
            response_data['message'] = '请求方法异常'
            return str(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'Z1001'
        response_data['message'] = '系统异常'
        return str(response_data)

@app.route('/api/vulndetail', methods = ['POST'])
def vuln_detail():
    """
    获取漏洞详情的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            pagenum = request_data['pagenum']
            pagesize = request_data['pagesize']
            target = request_data['target']
            target = aes_crypto.encrypt(target)
            token  = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'Z1001':
                response_data['code'] = 'Z1001'
                response_data['message'] = '系统异常'
                return str(response_data)
            elif username_result == None:
                response_data['code'] = 'Z1004'
                response_data['message'] = '认证失败'
                return str(response_data)
            else:
                sql_result = mysqldb.vulner_list(username_result['username'], target, pagenum, pagesize)
                vulner_list = sql_result['result']
                total = sql_result['total']
                if vulner_list == None:
                    response_data['code'] = 'Z1009'
                    response_data['message'] = '数据为空'
                elif vulner_list == 'Z1001':
                    response_data['code'] = 'Z1001'
                    response_data['message'] = '系统异常'
                else:
                    response_data['code'] = 'Z1000'
                    response_data['message'] = '请求成功'
                    for vulner in vulner_list:
                        vulner['target'] = aes_crypto.decrypt(vulner['target'])
                        vulner['description'] = aes_crypto.decrypt(vulner['description'])
                        vulner['ip_port'] = aes_crypto.decrypt(vulner['ip_port'])
                        vulner['vulner_name'] = aes_crypto.decrypt(vulner['vulner_name'])
                        vulner['vulner_descrip'] = aes_crypto.decrypt(vulner['vulner_descrip'])
                    response_data['total'] = total
                    if total == 0:
                        response_data['data'] = ''
                    else:
                        response_data['data'] = sql_result
                    return str(response_data)
        else:
            response_data['code'] = 'Z1002'
            response_data['message'] = '请求方法异常'
            return str(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'Z1001'
        response_data['message'] = '系统异常'
        return str(response_data)

@app.route('/api/setflag', methods = ['POST'])
def set_flag():
    """
    设置标识位的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            target = aes_crypto.encrypt(request_data['target'])
            flag = request_data['flag']
            token = request_data['token']
            query_str = {
                    'type': 'token',
                    'data': token
                }
            username_result = mysqldb.username(query_str)
            if username_result == 'Z1001':
                response_data['code'] = 'Z1001'
                response_data['message'] = '系统异常'
                return str(response_data)
            elif username_result == None:
                response_data['code'] = 'Z1004'
                response_data['message'] = '认证失败'
                return str(response_data)
            else:
                set_result = mysqldb.set_flag(username_result['username'], target, flag)
                if set_result == 'Z1000':
                    response_data['code'] = 'Z1000'
                    response_data['message'] = '请求成功'
                    return str(response_data)
                elif set_result == 'Z1001':
                    response_data['code'] = 'Z1001'
                    response_data['message'] = '系统异常'
        else:
            response_data['code'] = 'Z1002'
            response_data['message'] = '请求方法异常'
            return str(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'Z1001'
        response_data['message'] = '系统异常'
        return str(response_data)

@app.route('/api/delete', methods = ['POST'])
def delete():
    """
    删除信息的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            target = request_data['target']
            flag = request_data['flag']
            target = aes_crypto.encrypt(target)
            token = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'Z1001':
                response_data['code'] = 'Z1001'
                response_data['message'] = '系统异常'
                return str(response_data)
            elif username_result == None:
                response_data['code'] = 'Z1004'
                response_data['message'] = '认证失败'
                return str(response_data)
            else:
                delete_result = mysqldb.delete(username_result['username'], target, flag)
                print(delete_result)
                if delete_result == 'Z1000':
                    response_data['code'] = 'Z1000'
                    response_data['message'] = '请求成功'
                    return str(response_data)
                elif delete_result == 'Z1001':
                    response_data['code'] = 'Z1001'
                    response_data['message'] = '系统异常'
        else:
            response_data['code'] = 'Z1002'
            response_data['message'] = '请求方法异常'
            return str(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'Z1001'
        response_data['message'] = '系统异常'
        return str(response_data)

@app.route('/api/system', methods = ['POST'])
def system():
    """
    进行系统设置的接口

    :param:
    :return str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            token = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'Z1001':
                response_data['code'] = 'Z1001'
                response_data['message'] = '系统异常'
                return str(response_data)
            elif username_result == None:
                response_data['code'] = 'Z1004'
                response_data['message'] = '认证失败'
                return str(response_data)
            else:
                data = {
                    'proxy': config.get('request', 'proxy'),
                    'timeout': config.get('request', 'timeout')
                }
                data_list = []
                data_list.append(data)
                response_data['code'] = 'Z1000'
                response_data['message'] = '请求成功'
                response_data['total'] = 1
                response_data['data'] = data_list
                return str(response_data)
        else:
            response_data['code'] = 'Z1002'
            response_data['message'] = '请求方法异常'
            return str(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'Z1001'
        response_data['message'] = '系统异常'
        return str(response_data)

@app.route('/api/system_set', methods = ['POST'])
def system_set():
    """
    进行系统设置的接口

    :param:
    :return str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            proxytype = request_data['proxytype']
            proxyip = request_data['proxyip']
            timeout = request_data['timeout']
            token = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'Z1001':
                response_data['code'] = 'Z1001'
                response_data['message'] = '系统异常'
                return str(response_data)
            elif username_result == None:
                response_data['code'] = 'Z1004'
                response_data['message'] = '认证失败'
                return str(response_data)
            else:
                if not proxytype and not proxyip:
                    config.set('request', 'proxy', '')
                elif not proxytype and proxyip:
                    config.set('request', 'proxy', '未设置代理协议类型,将无法正常使用')
                elif proxytype and not proxyip:
                    config.set('request', 'proxy', '')
                else:
                    config.set('request', 'proxy', proxytype + '://' + proxyip)
                config.set('request', 'timeout', timeout)
                config.write(open('conf.ini','w',encoding='utf-8'))
                response_data['code'] = 'Z1000'
                response_data['message'] = '请求成功'
                return str(response_data)
        else:
            response_data['code'] = 'Z1002'
            response_data['message'] = '请求方法异常'
            return str(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'Z1001'
        response_data['message'] = '系统异常'
        return str(response_data)

@app.route('/api/upload', methods = ['GET', 'POST'])
def upload_file():
    """
    上传文件的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            token = request.form['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'Z1001':
                response_data['code'] = 'Z1001'
                response_data['message'] = '系统异常'
                return str(response_data)
            elif username_result == None:
                response_data['code'] = 'Z1004'
                response_data['message'] = '认证失败'
                return str(response_data)
            else:
                if 'file' not in request.files:
                    response_data['code'] = 'Z10011'
                    response_data['message'] = '上传文件失败！'
                    return str(response_data)
                file = request.files['file']
                # if user does not select file, browser also
                # submit an empty part without filename
                if file.filename == '':
                    response_data['code'] = 'Z10012'
                    response_data['message'] = '上传文件名为空！'
                    return str(response_data)
                if not allowed_file(file.filename):
                    response_data['code'] = 'Z10013'
                    response_data['message'] = '上传文件格式不正确！'
                    return str(response_data)
                if allowed_file(file.filename):
                    ticks = time.time()
                    time_flag = aes_crypto.encrypt(str(ticks))
                    file.filename = time_flag + '.' + file.filename.split('.')[1]
                    filename = secure_filename(file.filename)
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    response_data['code'] = 'Z10010'
                    response_data['message'] = '上传文件成功！'
                    #response_data['data'] = '../../static/images/' + filename
                    response_data['data'] = '/api/images/' + filename
                    return str(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'Z1001'
        response_data['message'] = '系统异常'
        return str(response_data)

@app.route('/api/images/<filename>', methods = ['GET', 'POST'])
def get_image(filename):
    """
    获取用户头像内容的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/api/changeavatar', methods = ['POST'])
def change_avatar():
    """
    修改用户头像的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            imagename = request_data['imagename']
            token = request_data['token']
            query_str = {
                    'type': 'token',
                    'data': token
                }
            username_result = mysqldb.username(query_str)
            if username_result == 'Z1001':
                response_data['code'] = 'Z1001'
                response_data['message'] = '系统异常'
                return str(response_data)
            elif username_result == None:
                response_data['code'] = 'Z1004'
                response_data['message'] = '认证失败'
                return str(response_data)
            else:
                set_result = mysqldb.change_avatar(username_result['username'], imagename)
                if set_result == 'Z1000':
                    response_data['code'] = 'Z1000'
                    response_data['message'] = '请求成功'
                    return str(response_data)
                elif set_result == 'Z1001':
                    response_data['code'] = 'Z1001'
                    response_data['message'] = '系统异常'
        else:
            response_data['code'] = 'Z1002'
            response_data['message'] = '请求方法异常'
            return str(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'Z1001'
        response_data['message'] = '系统异常'
        return str(response_data)

if __name__ == '__main__':
    # app.run(debug = True, port= 8800)
    app.run(host='0.0.0.0', port= 8000)
