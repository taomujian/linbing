#!/usr/bin/env python3

import os
import sys
import json
import time
import base64
import configparser
from rq import Queue
from redis import Redis
from app.lib.utils.encode import md5
from app.lib.utils.mysql import Mysql_db
from app.lib.utils.queue import queue_scan
from app.lib.utils.common import get_capta, parse_target, check
from app.lib.crypto.rsa import Rsa_Crypto
from app.lib.crypto.aes import Aes_Crypto
from flask_cors import *
from flask import Flask, request, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash

UPLOAD_FOLDER = 'images'  #文件存放路径
if not os.path.exists("images"):
    os.mkdir("images")

DATABASE = sys.path[0]+'/mydb.db'
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
CORS(app, supports_credentials=True)
config = configparser.ConfigParser()
config.read('conf.ini')
mysqldb = Mysql_db(config.get('mysql', 'ip'), config.get('mysql', 'port'), config.get('mysql', 'username'), config.get('mysql', 'password'))
mysqldb.create_database('linbing')
mysqldb.create_user()
mysqldb.create_port()
mysqldb.create_vulner()
mysqldb.create_target()
mysqldb.create_target_scan()
mysqldb.create_target_domain()
mysqldb.create_target_port()
mysqldb.create_target_path()
mysqldb.create_target_vulner()
mysqldb.create_cms_finger()
mysqldb.create_fofa_cms_finger()
mysqldb.init_finger('cms_finger.db')

aes_crypto = Aes_Crypto(config.get('Aes', 'key'), config.get('Aes', 'iv'))
rsa_crypto = Rsa_Crypto()

random_str = get_capta()
token = aes_crypto.encrypt('admin' + random_str)
mysqldb.save_account('admin', '系统内置管理员,不可删除,不可修改', token, generate_password_hash('X!ru0#M&%V'), 'admin', 'avatar.png')

redis_conn = Redis(host = '127.0.0.1', password = config.get('redis', 'password'), port = 6379)
high_queue = Queue("high", connection = redis_conn)

check('worker.py')
check('multiprocessing-fork')
os.popen('nohup python3 worker.py > log.log 2>&1 &')

@app.route('/api/query/account', methods = ['POST'])
def query_account():
    """
    查询的接口,用来查询用户否已存在

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
            username = request_data['username']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            query_result = mysqldb.query_account(username)
            if query_result == 'L1000':
                response_data['code'] = 'L1000'
                response_data['message'] = '请求成功'
            elif query_result == 'L10001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
            elif query_result == 'L1005':
                response_data['code'] = 'L1005'
                response_data['message'] = '用户已存在'
            return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/query/target', methods = ['POST'])
def query_target():
    """
    用来查询目标是否已存在

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
            target = request_data['target']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            query_result = mysqldb.query_target(username_result['username'], target)
            if isinstance(query_result, tuple):
                response_data['code'] = 'L1006'
                response_data['message'] = '目标%s已存在' %(query_result[1])
            elif query_result == 'L1000':
                response_data['code'] = 'L1000'
                response_data['message'] = '请求成功'
            elif query_result == 'L10001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
            return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/query/password', methods = ['POST'])
def query_password():
    """
    查询的接口,用来查询用或者目标是否已存在

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
            password = generate_password_hash(request_data['password'])
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            query_result = mysqldb.query_password(username_result['username'], password)
            if query_result == 'L1000':
                response_data['code'] = 'L1000'
                response_data['message'] = '请求成功'
            elif query_result == 'L10001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
            elif query_result == 'L1009':
                response_data['code'] = 'L1009'
                response_data['message'] = '旧密码错误'
            return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

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
            username = request_data['username']
            password = request_data['password']
            login_result = mysqldb.login(username)
            if login_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif login_result == None:
                response_data['code'] = 'L1004'
                response_data['message'] = '用户未注册'
                return json.dumps(response_data)
            elif not check_password_hash(login_result['password'], password):
                response_data['code'] = 'L1007'
                response_data['message'] = '密码错误'
                return json.dumps(response_data)
            else:
                response_data['code'] = 'L1000'
                response_data['message'] = '请求成功'
                response_data['data'] = {'token': login_result['token']}
                return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/userinfo', methods = ['POST'])
def userinfo():
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
            if userinfo_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif userinfo_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                response_data['code'] = 'L1000'
                response_data['message'] = '请求成功'
                response_data['data'] = {
                    'username': userinfo_result['username'],
                    'roles': userinfo_result['role'],
                    'avatar': userinfo_result['avatar']
                }
                return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/logout', methods = ['POST'])
def logout():
    """
    退出登陆的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            response_data['code'] = 'L1000'
            response_data['message'] = '请求成功'
            response_data['data'] = ''
            return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/change/password', methods = ['POST'])
def changp_assword():
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
            old_password = request_data['oldpassword']
            new_password = request_data['newpassword']
            token = request_data['token']
            query_str = {
                    'type': 'token',
                    'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                username = username_result['username']
                password_result = mysqldb.login(username)['password']
                if not check_password_hash(password_result, old_password):
                    response_data['code'] = 'L1009'
                    response_data['message'] = '密码错误'
                    return json.dumps(response_data)
                else:
                    changps_result = mysqldb.changps(token, generate_password_hash(new_password))
                    if changps_result == 'L1000':
                        response_data['code'] = 'L1000'
                        response_data['message'] = '请求成功'
                        return json.dumps(response_data)
                    else:
                        response_data['code'] = 'L1001'
                        response_data['message'] = '系统异常'
                        return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/home/card', methods = ['POST'])
def home_card():
    """
    获取首页卡片上数据的接口

    :param:
    :return str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            token  = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1004'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                sql_result = mysqldb.get_card_count(username_result['username'])
                if sql_result == 'L1001':
                    response_data['code'] = 'L1001'
                    response_data['message'] = '系统异常'
                else:
                    response_data['code'] = 'L1000'
                    response_data['message'] = '请求成功'
                    response_data['data'] = sql_result
                return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/home/7day', methods = ['POST'])
def home_7day():
    """
    获取首页卡片上曲线图上数据的接口

    :param:
    :return str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            token  = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1004'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                sql_result = mysqldb.get_7day_count(username_result['username'])
                if sql_result == 'L1001':
                    response_data['code'] = 'L1001'
                    response_data['message'] = '系统异常'
                else:
                    response_data['code'] = 'L1000'
                    response_data['message'] = '请求成功'
                    response_data['data'] = sql_result
                return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/target/new', methods = ['POST'])
def target_new():
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
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                for target in target_list:
                    target = target.strip()
                    scan_ip = parse_target(target)[0]
                    if not scan_ip:
                        scan_ip = target
                    target = target
                    description = request_data['description']
                    save_result = mysqldb.save_target(username_result['username'], target, description, scan_ip)
                    if save_result == 'L1000':
                        pass
                    else:
                        response_data['code'] = 'L1001'
                        response_data['message'] = '系统异常'
                        return json.dumps(response_data)
                response_data['code'] = 'L1000'
                response_data['message'] = '请求成功'
                return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/target/edit', methods = ['POST'])
def target_edit():
    """
    修改目标描述的接口

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
            description = request_data['description']
            token = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                result = mysqldb.update_target_description(username_result['username'], target, description)
                if result == 'L1000':
                    response_data['code'] = 'L1000'
                    response_data['message'] = '请求成功'
                    return json.dumps(response_data)
                else:
                    response_data['code'] = 'L1001'
                    response_data['message'] = '系统异常'
                    return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/target/detail', methods = ['POST'])
def target_detail():
    """
    获取目标详情的接口

    :param:
    :return str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            target = request_data['target']
            pagenum = request_data['pagenum']
            pagesize = request_data['pagesize']
            token  = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1004'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                sql_result = mysqldb.get_target_detail(username_result['username'], target, pagenum, pagesize)
                if sql_result == 'L1001':
                    response_data['code'] = 'L1001'
                    response_data['message'] = '系统异常'
                else:
                    response_data['code'] = 'L1000'
                    response_data['message'] = '请求成功'
                    response_data['data'] = sql_result
                return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/scan/set', methods = ['POST'])
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
            target = request_data['target']
            token = request_data['token']
            scan_data = json.loads(request_data['scan_data'])
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                result = mysqldb.scan_set(username_result['username'], target, scan_data['scanner'], scan_data['min_port'], scan_data['max_port'], scan_data['rate'], scan_data['concurren_number'])
                if result == 'L1000':
                    response_data['code'] = 'L1000'
                    response_data['message'] = '请求成功'
                    return json.dumps(response_data)
                else :
                    response_data['code'] = 'L1001'
                    response_data['message'] = '系统异常'
                    return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/scan/start', methods = ['POST'])
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
            target = request_data['target']
            token = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                target_list = []
                if request_data['target'] == 'all':
                    target_list = mysqldb.get_scan_target(username_result['username'])['result']
                else:
                    target_list.append({'target': request_data['target'], 'description': request_data['description']})
                
                scan_id = mysqldb.get_scan_id(username_result['username'])
                for item in target_list:
                    target = item['target']
                    description = item['description']
                    parse_result = parse_target(target)
                    scan_ip = parse_result[0]
                    main_domain = parse_result[1]
                    domain = parse_result[2]
                    scan_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    
                    if not scan_ip:
                        # mysqldb.update_target_live_status(username_result['username'], target, '失活')
                        mysqldb.save_target_scan(username_result['username'], target, description, scan_ip, scan_id, scan_time, '扫描失败', '扫描失败')
                        mysqldb.update_target_scan_status(username_result['username'], target, '扫描失败')                                
                        mysqldb.update_target_scan_schedule(username_result['username'], target, '扫描失败')                               
                        mysqldb.update_scan_status(username_result['username'], target, scan_id, '扫描失败')                               
                        mysqldb.update_scan_schedule(username_result['username'], target, scan_id, '扫描失败')                            

                    else:
                        mysqldb.save_target_scan(username_result['username'], target, description, scan_ip, scan_id, scan_time, '扫描中', '正在排队')
                        mysqldb.update_target_scan_status(username_result['username'], target, '扫描中')
                        mysqldb.update_target_scan_schedule(username_result['username'], target, '正在排队')                             
                        high_queue.enqueue_call(queue_scan, args = (username_result['username'], target, scan_id, scan_ip, main_domain, domain, mysqldb,), timeout = 720000000)
                        scan_id = str(int(scan_id) + 1)

                response_data['code'] = 'L1000'
                response_data['message'] = '请求成功'
                return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/target/list', methods = ['POST'])
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
            list_query = json.loads(request_data['listQuery'])
            if list_query['scan_status'] == '全部':
                list_query['scan_status'] = ''
            if list_query['scan_schedule'] == '全部':
                list_query['scan_schedule'] = ''

            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                sql_result = mysqldb.target_list(username_result['username'], pagenum, pagesize, flag, list_query)
                target_list = sql_result['result']
                total = sql_result['total']
                if target_list == 'L1001':
                    response_data['code'] = 'L1001'
                    response_data['message'] = '系统异常'
                else :
                    response_data['code'] = 'L1000'
                    response_data['message'] = '请求成功'
                    if total == 0:
                        response_data['data'] = ''
                    else:
                        response_data['data'] = sql_result
                    return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/scan/list', methods = ['POST'])
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
            list_query = json.loads(request_data['listQuery'])
            if list_query['scan_status'] == '全部':
                list_query['scan_status'] = ''
            if list_query['scan_schedule'] == '全部':
                list_query['scan_schedule'] = ''

            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                sql_result = mysqldb.scan_list(username_result['username'], pagenum, pagesize, flag, list_query)
                scan_list = sql_result['result']
                total = sql_result['total']
                if scan_list == 'L1001':
                    response_data['code'] = 'L1001'
                    response_data['message'] = '系统异常'
                else :
                    response_data['code'] = 'L1000'
                    response_data['message'] = '请求成功'
                    response_data['total'] = total
                    if total == 0:
                        response_data['data'] = ''
                    else:
                        response_data['data'] = sql_result
                    return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/port/list', methods = ['POST'])
def port_list():
    """
    获取所有端口信息的接口

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
            list_query = json.loads(request_data['listQuery'])
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                sql_result = mysqldb.port_list(username_result['username'], pagenum, pagesize, flag, list_query)
                port_list = sql_result['result']
                total = sql_result['total']
                if port_list == 'L1001':
                    response_data['code'] = 'L1001'
                    response_data['message'] = '系统异常'
                else :
                    response_data['code'] = 'L1000'
                    response_data['message'] = '请求成功'
                    response_data['total'] = total
                    if total == 0:
                        response_data['data'] = ''
                    else:
                        response_data['data'] = sql_result
                    return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/vulner/list', methods = ['POST'])
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
            list_query = json.loads(request_data['listQuery'])
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                sql_result = mysqldb.vulner_list(username_result['username'], pagenum, pagesize, flag, list_query)
                vulner_list = sql_result['result']
                total = sql_result['total']
                if vulner_list == 'L1001':
                    response_data['code'] = 'L1001'
                    response_data['message'] = '系统异常'
                else :
                    response_data['code'] = 'L1000'
                    response_data['message'] = '请求成功'
                    response_data['total'] = total
                    if total == 0:
                        response_data['data'] = ''
                    else:
                        response_data['data'] = sql_result
                    return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/account/add', methods = ['POST'])
def account_add():
    """
    添加用户的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            username = request_data['username']
            description = request_data['description']
            password =  generate_password_hash(request_data['password'])
            role = request_data['role']
            random_str = get_capta()
            user_token = aes_crypto.encrypt(username + random_str)
            
            token  = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            elif username_result['role'] != 'admin':
                response_data['code'] = 'L10010'
                response_data['message'] = '权限不足,无法进行操作'
                return json.dumps(response_data)
            else:
                result = mysqldb.save_account(username, description, user_token, password, role, 'avatar.png')
                response_data['code'] = result
                if response_data['code'] == 'L1000':
                    response_data['message'] = '请求成功'
                else:
                    response_data['message'] = '系统异常'
            return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/account/role', methods = ['POST'])
def account_role():
    """
    修改用户权限的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            username = request_data['username']
            role = request_data['role']
            
            token  = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            elif username_result['role'] != 'admin':
                response_data['code'] = 'L10010'
                response_data['message'] = '权限不足,无法进行操作'
                return json.dumps(response_data)
            else:
                result = mysqldb.update_account_role(username, role)
                response_data['code'] = result
                if response_data['code'] == 'L1000':
                    response_data['message'] = '请求成功'
                else:
                    response_data['message'] = '系统异常'
            return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/account/password', methods = ['POST'])
def account_password():
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
            username = request_data['username']
            password = generate_password_hash(request_data['password'])
            token  = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            elif username_result['role'] != 'admin':
                response_data['code'] = 'L10010'
                response_data['message'] = '权限不足,无法进行操作'
                return json.dumps(response_data)
            else:
                data = {
                    'type': 'username',
                    'type_data': username,
                    'password': password
                }
                changps_result = mysqldb.update_account_password(username, password)
                if changps_result == 'L1000':
                    response_data['message'] = '请求成功'
                else:
                    response_data['message'] = '系统异常'
            return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/account/description', methods = ['POST'])
def account_description():
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
            username = request_data['username']
            description = request_data['description']
            token  = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            elif username_result['role'] != 'admin':
                response_data['code'] = 'L10010'
                response_data['message'] = '权限不足,无法进行操作'
                return json.dumps(response_data)
            else:
                changps_result = mysqldb.update_account_description(username, description)
                if changps_result == 'L1000':
                    response_data['message'] = '请求成功'
                else:
                    response_data['message'] = '系统异常'
            return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/delete/account', methods = ['POST'])
def delete_account():
    """
    删除用户的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            username = request_data['username']
            token  = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            elif username_result['role'] != 'admin':
                response_data['code'] = 'L10010'
                response_data['message'] = '权限不足,无法进行操作'
                return json.dumps(response_data)
            else:
                result = mysqldb.delete_account(username)
                response_data['code'] = result
                if response_data['code'] == 'L1000':
                    response_data['message'] = '请求成功'
                else:
                    response_data['message'] = '系统异常'
            return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/account/list', methods = ['POST'])
def account_list():
    """
    获取所有用户信息的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': '', 'total': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            token  = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            list_query = json.loads(request_data['listQuery'])
            if list_query['role'] == '全部':
                list_query['role'] = ''
            if list_query['role'] == '全部':
                list_query['role'] = ''

            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                sql_result = mysqldb.account_list(list_query)
                user_list = sql_result['result']
                total = sql_result['total']
                if user_list == 'L1001':
                    response_data['code'] = 'L1001'
                    response_data['message'] = '系统异常'
                else:
                    response_data['code'] = 'L1000'
                    response_data['message'] = '请求成功'
                    if total == 0:
                        response_data['data'] = ''
                    else:
                        response_data['data'] = sql_result
                    return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/set/target', methods = ['POST'])
def set_target():
    """
    设置目标标识位的接口

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
            token = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                set_result = mysqldb.set_target(username_result['username'], target, flag)
                if set_result == 'L1000':
                    response_data['code'] = 'L1000'
                    response_data['message'] = '请求成功'
                    return json.dumps(response_data)
                elif set_result == 'L1001':
                    response_data['code'] = 'L1001'
                    response_data['message'] = '系统异常'
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/set/port', methods = ['POST'])
def set_port():
    """
    设置端口标识位的接口

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
            scan_ip = request_data['scan_ip']
            port = request_data['port']
            flag = request_data['flag']
            token = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                set_result = mysqldb.set_port(username_result['username'], flag, target, scan_ip, port)
                if set_result == 'L1000':
                    response_data['code'] = 'L1000'
                    response_data['message'] = '请求成功'
                    return json.dumps(response_data)
                elif set_result == 'L1001':
                    response_data['code'] = 'L1001'
                    response_data['message'] = '系统异常'
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/set/vulner', methods = ['POST'])
def set_vulner():
    """
    设置漏洞标识位的接口

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
            ip_port = request_data['ip_port']
            vulner_name = request_data['vulner_name']
            flag = request_data['flag']
            token = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                set_result = mysqldb.set_vulner(username_result['username'], flag, target, ip_port, vulner_name)
                if set_result == 'L1000':
                    response_data['code'] = 'L1000'
                    response_data['message'] = '请求成功'
                elif set_result == 'L1001':
                    response_data['code'] = 'L1001'
                    response_data['message'] = '系统异常'
                return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/delete/target', methods = ['POST'])
def delete_target():
    """
    删除目标的接口

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
            token = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                delete_result = mysqldb.delete_target(username_result['username'], target)
                if delete_result == 'L1000':
                    response_data['code'] = 'L1000'
                    response_data['message'] = '请求成功'
                    return json.dumps(response_data)
                elif delete_result == 'L1001':
                    response_data['code'] = 'L1001'
                    response_data['message'] = '系统异常'
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/delete/port', methods = ['POST'])
def delete_port():
    """
    删除端口的接口

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
            scan_ip = request_data['scan_ip']
            port = request_data['port']
            token = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                delete_result = mysqldb.delete_port(username_result['username'], target, scan_ip, port)
                if delete_result == 'L1000':
                    response_data['code'] = 'L1000'
                    response_data['message'] = '请求成功'
                    return json.dumps(response_data)
                elif delete_result == 'L1001':
                    response_data['code'] = 'L1001'
                    response_data['message'] = '系统异常'
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/delete/vulner', methods = ['POST'])
def delete_vulner():
    """
    删除漏洞的接口

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
            ip_port = request_data['ip_port']
            vulner_name = request_data['vulner_name']
            token = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                delete_result = mysqldb.delete_vulner(username_result['username'], target, ip_port, vulner_name)
                if delete_result == 'L1000':
                    response_data['code'] = 'L1000'
                    response_data['message'] = '请求成功'
                    return json.dumps(response_data)
                elif delete_result == 'L1001':
                    response_data['code'] = 'L1001'
                    response_data['message'] = '系统异常'
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/system/list', methods = ['POST'])
def system_list():
    """
    查看系统设置信息的接口

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
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                data = {
                    'proxy': config.get('request', 'proxy'),
                    'timeout': config.get('request', 'timeout')
                }
                data_list = []
                data_list.append(data)
                response_data['code'] = 'L1000'
                response_data['message'] = '请求成功'
                response_data['total'] = 1
                response_data['data'] = data_list
                return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/system/set', methods = ['POST'])
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
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
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
                response_data['code'] = 'L1000'
                response_data['message'] = '请求成功'
                return json.dumps(response_data)
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/upload/image', methods = ['POST'])
def upload_image():
    """
    上传文件的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    response_data = {'code': '', 'message': '', 'data': ''}
    try:
        if request.method == 'POST':
            request_data = request.form.to_dict()
            imgdata = request_data['imgdata']
            request_data = rsa_crypto.decrypt(request_data['data'])
            request_data = json.loads(request_data)
            token = request_data['token']
            query_str = {
                'type': 'token',
                'data': token
            }
            username_result = mysqldb.username(query_str)
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                ticks = time.time()
                time_flag = md5(aes_crypto.encrypt(str(ticks)))
                filename = time_flag + '.' + 'png'
                b64_data = imgdata.split(';base64,')[1]
                data = base64.b64decode(b64_data)
                with open('images/%s' %(filename), 'wb') as writer:
                    writer.write(data)
                writer.close()
                response_data['code'] = 'L10008'
                response_data['message'] = '上传文件成功！'
                response_data['data'] = filename
                return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

@app.route('/api/images/<filename>', methods = ['GET', 'POST'])
def get_image(filename):
    """
    获取用户头像内容的接口

    :param:
    :return: str response_data: 需要返回的数据
    """
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/api/change/avatar', methods = ['POST'])
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
            if username_result == 'L1001':
                response_data['code'] = 'L1001'
                response_data['message'] = '系统异常'
                return json.dumps(response_data)
            elif username_result == None:
                response_data['code'] = 'L1003'
                response_data['message'] = '认证失败'
                return json.dumps(response_data)
            else:
                set_result = mysqldb.change_avatar(username_result['username'], imagename)
                if set_result == 'L1000':
                    response_data['code'] = 'L1000'
                    response_data['message'] = '请求成功'
                    return json.dumps(response_data)
                elif set_result == 'L1001':
                    response_data['code'] = 'L1001'
                    response_data['message'] = '系统异常'
        else:
            response_data['code'] = 'L1002'
            response_data['message'] = '请求方法异常'
            return json.dumps(response_data)
    except Exception as e:
        print(e)
        response_data['code'] = 'L1001'
        response_data['message'] = '系统异常'
        return json.dumps(response_data)

if __name__ == '__main__':
    # app.run(debug = True)
    app.run(host='0.0.0.0', port= 8000)
