#!/usr/bin/env python3

import os
import json
import time
import ctypes
import base64
import inspect
import uvicorn
import asyncio
import threading
import configparser
from rq import Queue
from redis import Redis
from pydantic import BaseModel
from typing import List
from dnslog import Dnslog
from app.lib.encode import md5
from passlib.context import CryptContext
from app.utils.mysql import Mysql_db
from app.lib.rsa import Rsa_Crypto
from app.lib.aes import Aes_Crypto
from app.lib.common import get_capta
from fastapi.responses import FileResponse
from rq.command import send_stop_job_command
from app.utils.queue import queue_target_list, queue_scan_list
from fastapi import FastAPI, WebSocket, Request, WebSocketDisconnect

UPLOAD_FOLDER = 'images'  #文件存放路径
if not os.path.exists("images"):
    os.mkdir("images")

app = FastAPI()

config = configparser.ConfigParser()
config.read('conf.ini', encoding = 'utf-8')
mysqldb = Mysql_db(config.get('mysql', 'ip'), config.get('mysql', 'port'), config.get('mysql', 'username'), config.get('mysql', 'password'))
mysqldb.create_database('linbing')
mysqldb.create_user()
mysqldb.create_port()
mysqldb.create_vulner()
mysqldb.create_poc()
mysqldb.create_target()
mysqldb.create_target_scan()
mysqldb.create_target_domain()
mysqldb.create_target_port()
mysqldb.create_target_path()
mysqldb.create_target_vulner()
mysqldb.create_cms_finger()
mysqldb.create_fofa_cms_finger()
mysqldb.create_xss_log()
mysqldb.create_dns_log()
mysqldb.create_xss_auth()
mysqldb.init_finger('cms_finger.db')
mysqldb.init_poc()

aes_crypto = Aes_Crypto(config.get('Aes', 'key'), config.get('Aes', 'iv'))
rsa_crypto = Rsa_Crypto()

random_str = get_capta()
token = aes_crypto.encrypt('admin' + random_str)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
mysqldb.save_account('admin', '系统内置管理员,不可删除,不可修改', token, pwd_context.hash('X!ru0#M&%V'), 'admin', 'avatar.png')

redis_conn = Redis(host = config.get('redis', 'ip'), password = config.get('redis', 'password'), port = config.get('redis', 'port'))
high_queue = Queue("high", connection = redis_conn)
high_queue.delete(delete_jobs=True)

dns_thread_list = []

os.popen('nohup python3 worker.py > log.log 2>&1 &')

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
            await websocket.send_json(message)

    async def broadcast(self, message: str, exclude):
        for connection in self.active_connections:
            if connection is exclude:
                continue
            await connection.send_text(message)

manager = ConnectionManager()

def stop_thread(thread):
    tid = ctypes.c_long(thread.ident)
    if not inspect.isclass(SystemExit):
        exctype = type(SystemExit)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, ctypes.py_object(exctype))
    if res == 0:
        raise ValueError("invalid thread id")
    elif res != 1:
        # """if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")

def handle_dns_log(username):
    dnslog = Dnslog()
    domain = dnslog.domain
    config.set('Domain', 'domain', domain)
    config.write(open('conf.ini','w',encoding='utf-8'))
    
    while True:
        try:
            log_list = dnslog.get_logs()
            for log in log_list:
                if not mysqldb.get_dns_log(username, log[0], log[1], log[2]):
                    mysqldb.save_dns_log(username, log[0], log[1], log[2])
        except Exception as e:
            print(e)

        time.sleep(10)

class VueRequest(BaseModel):
    data: str = None

@app.post('/api/query/account')
async def query_account(request : VueRequest):
    
    """
    查询的接口,用来查询用户否已存在

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        token = request['token']
        username = request['username']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        query_result = mysqldb.query_account(username)
        if query_result == 'L1000':
            response['code'] = 'L1000'
            response['message'] = '请求成功'
        elif query_result == 'L10001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
        elif query_result == 'L1005':
            response['code'] = 'L1005'
            response['message'] = '用户已存在'
        return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/query/target')
async def query_target(request : VueRequest):
    
    """
    用来查询目标是否已存在

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        token = request['token']
        target = request['target']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        query_result = mysqldb.query_target(username_result['username'], target)
        if isinstance(query_result, tuple):
            response['code'] = 'L1006'
            response['message'] = '目标%s已存在' %(query_result[1])
        elif query_result == 'L1000':
            response['code'] = 'L1000'
            response['message'] = '请求成功'
        elif query_result == 'L10001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
        return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/query/password')
async def query_password(request : VueRequest):
    
    """
    查询的接口,用来查询用或者目标是否已存在

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        token = request['token']
        password = pwd_context.hash(request['password'])
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        query_result = mysqldb.query_password(username_result['username'], password)
        if query_result == 'L1000':
            response['code'] = 'L1000'
            response['message'] = '请求成功'
        elif query_result == 'L10001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
        elif query_result == 'L1009':
            response['code'] = 'L1009'
            response['message'] = '旧密码错误'
        return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/login')
async def login(request : VueRequest):
    
    """
    登陆的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        username = request['username']
        password = request['password']
        login_result = mysqldb.login(username)
        if login_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif login_result == None:
            response['code'] = 'L1004'
            response['message'] = '用户未注册'
            return response
        elif not pwd_context.verify(password, login_result['password']):
            response['code'] = 'L1007'
            response['message'] = '密码错误'
            return response
        else:
            response['code'] = 'L1000'
            response['message'] = '请求成功'
            response['data'] = {'token': login_result['token']}
            return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/userinfo')
async def userinfo(request : VueRequest):
    
    """
    获取用户信息的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        token = request['token']
        userinfo_result = mysqldb.userinfo(token)
        if userinfo_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif userinfo_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            response['code'] = 'L1000'
            response['message'] = '请求成功'
            response['data'] = {
                'username': userinfo_result['username'],
                'roles': userinfo_result['role'],
                'avatar': userinfo_result['avatar']
            }
            return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/logout')
async def logout(request : VueRequest):
    
    """
    退出登陆的接口

    :param:
    :return: str response: 需要返回的数据
    """
    
    response = {'code': '', 'message': '', 'data': ''}
    try:
        response['code'] = 'L1000'
        response['message'] = '请求成功'
        response['data'] = ''
        return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/change/password')
async def changp_assword(request : VueRequest):
    
    """
    修改用户密码的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        old_password = request['oldpassword']
        new_password = request['newpassword']
        token = request['token']
        query_str = {
                'type': 'token',
                'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            username = username_result['username']
            password_result = mysqldb.login(username)['password']
            if not pwd_context.verify(old_password, password_result):
                response['code'] = 'L1009'
                response['message'] = '密码错误'
                return response
            else:
                random_str = get_capta()
                token = aes_crypto.encrypt('admin' + random_str)
                changps_result = mysqldb.changps(username, token, pwd_context.hash(new_password))
                if changps_result == 'L1000':
                    response['code'] = 'L1000'
                    response['message'] = '请求成功'
                    return response
                else:
                    response['code'] = 'L1001'
                    response['message'] = '系统异常'
                    return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/home/card')
async def home_card(request : VueRequest):
    
    """
    获取首页卡片上数据的接口

    :param:
    :return str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1004'
            response['message'] = '认证失败'
            return response
        else:
            sql_result = mysqldb.get_card_count(username_result['username'])
            if sql_result == 'L1001':
                response['code'] = 'L1001'
                response['message'] = '系统异常'
            else:
                response['code'] = 'L1000'
                response['message'] = '请求成功'
                response['data'] = sql_result
            return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/home/7day')
async def home_7day(request : VueRequest):
    
    """
    获取首页卡片上曲线图上数据的接口

    :param:
    :return str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1004'
            response['message'] = '认证失败'
            return response
        else:
            sql_result = mysqldb.get_7day_count(username_result['username'])
            if sql_result == 'L1001':
                response['code'] = 'L1001'
                response['message'] = '系统异常'
            else:
                response['code'] = 'L1000'
                response['message'] = '请求成功'
                response['data'] = sql_result
            return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/target/new')
async def target_new(request : VueRequest):
    
    """
    保存目标的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        target_data = request['target']
        target_list = target_data.split(';')
        port = request['port']
        token = request['token']
        rate = request['rate']
        concurren_number = request['concurren_number']
        masscan_cmd = request['masscan_cmd']
        nmap_cmd = request['nmap_cmd']
        scanner = request['scanner']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            high_queue.enqueue_call(queue_target_list, args = (username_result['username'], target_list, request['description'], port, scanner, rate, concurren_number, masscan_cmd, nmap_cmd, mysqldb,), timeout = 7200000)
            response['code'] = 'L1000'
            response['message'] = '请求成功'
            return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/target/edit')
async def target_edit(request : VueRequest):
    
    """
    修改目标描述的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        target = request['target']
        description = request['description']
        token = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            result = mysqldb.update_target_description(username_result['username'], target, description)
            if result == 'L1000':
                response['code'] = 'L1000'
                response['message'] = '请求成功'
                return response
            else:
                response['code'] = 'L1001'
                response['message'] = '系统异常'
                return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/target/detail')
async def target_detail(request : VueRequest):
    
    """
    获取目标详情的接口

    :param:
    :return str response: 需要返回的数据
    """

    try:
        
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        target = request['target']
        pagenum = request['pagenum']
        pagesize = request['pagesize']
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1004'
            response['message'] = '认证失败'
            return response
        else:
            sql_result = mysqldb.get_target_detail(username_result['username'], target, pagenum, pagesize)
            if sql_result == 'L1001':
                response['code'] = 'L1001'
                response['message'] = '系统异常'
            else:
                response['code'] = 'L1000'
                response['message'] = '请求成功'
                response['data'] = sql_result
            return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/scan/set')
async def scan_set(request : VueRequest):
    
    """
    设置扫描选项的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        target = request['target']
        token = request['token']
        scan_data = json.loads(request['scan_data'])
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            result = mysqldb.scan_set(username_result['username'], target, scan_data['scanner'], scan_data['masscan_cmd'], scan_data['nmap_cmd'], scan_data['port'], scan_data['rate'], scan_data['concurren_number'])
            if result == 'L1000':
                response['code'] = 'L1000'
                response['message'] = '请求成功'
                return response
            else:
                response['code'] = 'L1001'
                response['message'] = '系统异常'
                return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/scan/start')
async def start_scan(request : VueRequest):

    """
    开始扫描的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        target = request['target']
        token = request['token']
        scan_option = request['scan_option']
        option_list = []
        for option in scan_option:
            option = json.loads(option)
            option_list.append(str(option['id']))
            if 'children' in option.keys():
                for vul_type in option['children']:
                    option_list.append(vul_type['label'].replace('-', '_'))
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            target_list = []
            if request['target'] == 'all':
                target_list = mysqldb.get_scan_target(username_result['username'])
            else:
                target_list.append({'target': target})
            
            high_queue.enqueue_call(queue_scan_list, args = (username_result['username'], target_list, option_list, mysqldb,), timeout = 7200000)
            response['code'] = 'L1000'
            response['message'] = '请求成功'
            return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/scan/pause')
async def pause_scan(request : VueRequest):

    """
    暂停扫描的接口

    :param:
    :return str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        target = request['target']
        scan_id = request['scan_id']
        token = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            scan_status = mysqldb.get_scan_status(username_result['username'], scan_id)
            if scan_status == '扫描中':
                send_stop_job_command(redis_conn, md5(username_result['username'] + scan_id))
                mysqldb.update_scan_status(username_result['username'], scan_id, '暂停扫描')
                mysqldb.update_target_scan_status(username_result['username'], target, '暂停扫描')
                response['data'] = '请求正常'
                response['code'] = 'L1000'
                response['message'] = '请求正常'
            else:
                response['data'] = '目标不在扫描中,无法暂停扫描'
                response['code'] = 'L1000'
                response['message'] = '请求正常'
            return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/scan/resume')
async def resume_scan(request : VueRequest):

    """
    恢复扫描的接口

    :param:
    :return str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        target = request['target']
        scan_id = request['scan_id']
        token = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            scan_status = mysqldb.get_scan_status(username_result['username'], scan_id)
            if scan_status == '暂停扫描':
                registry = high_queue.failed_job_registry
                registry.requeue(md5(username_result['username'] + scan_id))
                mysqldb.update_scan_status(username_result['username'], scan_id, '正在扫描')
                mysqldb.update_target_scan_status(username_result['username'], target, '正在扫描')
                response['data'] = '请求正常'
                response['code'] = 'L1000'
                response['message'] = '请求正常'
            else:
                response['data'] = '目标不处于暂停扫描状态,无法恢复扫描'
                response['code'] = 'L1000'
                response['message'] = '请求正常'
            return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/scan/cancel')
async def cancel_scan(request : VueRequest):

    """
    取消扫描的接口

    :param:
    :return str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        target = request['target']
        scan_id = request['scan_id']
        token = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            scan_status = mysqldb.get_scan_status(username_result['username'], scan_id)
            if scan_status == '扫描结束':
                response['data'] = '扫描已结束,无法取消'
                response['code'] = 'L1000'
                response['message'] = '扫描已结束,无法取消'
            elif scan_status == '已取消扫描':
                response['data'] = '已取消扫描,无法再次取消'
                response['code'] = 'L1000'
                response['message'] = '已取消扫描,无法再次取消'
            else:
                send_stop_job_command(redis_conn, md5(username_result['username'] + scan_id))
                time.sleep(0.5)
                registry = high_queue.failed_job_registry
                try:
                    registry.remove(md5(username_result['username'] + scan_id), delete_job = True)
                    mysqldb.update_scan_status(username_result['username'], scan_id, '已取消扫描')
                    mysqldb.update_target_scan_status(username_result['username'], target, '已取消扫描')
                    response['data'] = '请求正常'
                    response['code'] = 'L1000'
                    response['message'] = '请求正常'
                except Exception as e:
                    print(e)
                    response['data'] = '系统异常'
                    response['code'] = 'L10001'
                    response['message'] = '系统异常'   
            return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/target/list')
async def target_list(request : VueRequest):
    
    """
    获取所有目标的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        pagenum = request['pagenum']
        pagesize = request['pagesize']
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        list_query = json.loads(request['listQuery'])
        if list_query['scan_status'] == '全部':
            list_query['scan_status'] = ''
        if list_query['scan_schedule'] == '全部':
            list_query['scan_schedule'] = ''

        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            sql_result = mysqldb.target_list(username_result['username'], pagenum, pagesize, list_query)
            target_list = sql_result['result']
            total = sql_result['total']
            if target_list == 'L1001':
                response['code'] = 'L1001'
                response['message'] = '系统异常'
            else:
                response['code'] = 'L1000'
                response['message'] = '请求成功'
                if total == 0:
                    response['data'] = ''
                else:
                    response['data'] = sql_result
                return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/scan/list')
async def scan_list(request : VueRequest):
    
    """
    获取所有扫描信息的接口

    :param:
    :return str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        pagenum = request['pagenum']
        pagesize = request['pagesize']
        token  = request['token']
        list_query = json.loads(request['listQuery'])
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
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            sql_result = mysqldb.scan_list(username_result['username'], pagenum, pagesize, list_query)
            scan_list = sql_result['result']
            total = sql_result['total']
            if scan_list == 'L1001':
                response['code'] = 'L1001'
                response['message'] = '系统异常'
            else:
                response['code'] = 'L1000'
                response['message'] = '请求成功'
                response['total'] = total
                if total == 0:
                    response['data'] = ''
                else:
                    response['data'] = sql_result
                return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/port/list')
async def port_list(request : VueRequest):
    
    """
    获取所有端口信息的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        pagenum = request['pagenum']
        pagesize = request['pagesize']
        
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        list_query = json.loads(request['listQuery'])
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            sql_result = mysqldb.port_list(username_result['username'], pagenum, pagesize, list_query)
            port_list = sql_result['result']
            total = sql_result['total']
            if port_list == 'L1001':
                response['code'] = 'L1001'
                response['message'] = '系统异常'
            else:
                response['code'] = 'L1000'
                response['message'] = '请求成功'
                response['total'] = total
                if total == 0:
                    response['data'] = ''
                else:
                    response['data'] = sql_result
                return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/port/download')
async def port_list(request : VueRequest):
    
    """
    下载所有端口信息的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        list_query = json.loads(request['listQuery'])
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            sql_result = mysqldb.port_download(username_result['username'], list_query)
            port_list = sql_result['result']
            total = sql_result['total']
            if port_list == 'L1001':
                response['code'] = 'L1001'
                response['message'] = '系统异常'
            else:
                response['code'] = 'L1000'
                response['message'] = '请求成功'
                response['total'] = total
                if total == 0:
                    response['data'] = ''
                else:
                    response['data'] = sql_result
                return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/poc/name')
async def poc_name(request : VueRequest):
    
    """
    获取所有漏洞名字的接口,以供前端选扫描插件

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            name_datas = []
            for item in os.listdir('app/plugins/http'):
                file_names = os.listdir('app/plugins/http/' + item)
                for file_name in file_names:
                    if file_name.endswith(".py") and not file_name.startswith('__') and 'ajpy' not in file_name:
                        file_name = file_name[:-3].replace('_', '-')
                        name_datas.append(file_name)

            for item in os.listdir('app/plugins/port'):
                file_names = os.listdir('app/plugins/port/' + item)
                for file_name in file_names:
                    if file_name.endswith(".py") and not file_name.startswith('__') and 'ajpy' not in file_name:
                        file_name = file_name[:-3].replace('_', '-')
                        name_datas.append(file_name)

            response['code'] = 'L1000'
            response['message'] = '请求成功'
            response['data'] = name_datas
            return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/poc/list')
async def poc_list(request : VueRequest):
    
    """
    获取所有漏洞信息的接口,以供前端选扫描插件

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        pagenum = request['pagenum']
        pagesize = request['pagesize']
        list_query = json.loads(request['listQuery'])
        start = (int(pagenum)-1) * int(pagesize)
        pagesize = int (pagesize)
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            sql_result = mysqldb.poc_list(username_result['username'], pagenum, pagesize, list_query)
            poc_list = sql_result['result']
            total = sql_result['total']
            if poc_list == 'L1001':
                response['code'] = 'L1001'
                response['message'] = '系统异常'
                return response
            else:
                response['code'] = 'L1000'
                response['message'] = '请求成功'
                response['total'] = total
                if total == 0:
                    response['data'] = ''
                else:
                    response['data'] = poc_list
                response['code'] = 'L1000'
                response['message'] = '请求成功'
                return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/vulner/list')
async def vuln_list(request : VueRequest):
    
    """
    获取所有漏洞信息的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        pagenum = request['pagenum']
        pagesize = request['pagesize']
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        list_query = json.loads(request['listQuery'])
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            sql_result = mysqldb.vulner_list(username_result['username'], pagenum, pagesize, list_query)
            vulner_list = sql_result['result']
            total = sql_result['total']
            if vulner_list == 'L1001':
                response['code'] = 'L1001'
                response['message'] = '系统异常'
            else:
                response['code'] = 'L1000'
                response['message'] = '请求成功'
                response['total'] = total
                if total == 0:
                    response['data'] = ''
                else:
                    response['data'] = sql_result
                return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/generate/auth')
async def generate_auth(request : VueRequest):
    
    """
    生成xss auth的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            response['code'] = 'L1000'
            response['message'] = '请求正常'
            auth_token = aes_crypto.encrypt(get_capta() + get_capta())
            url = 'http://uwsgi运行ip:port/api/log?token=' + auth_token + '&data=js语句'
            mysqldb.save_xss_auth(username_result['username'], auth_token, url)
            response['data'] = auth_token
            return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/xss/auth')
async def auth_list(request : VueRequest):
    
    """
    获取xss auth的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        pagenum = request['pagenum']
        pagesize = request['pagesize']
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        list_query = json.loads(request['listQuery'])
        if list_query['token_status'] == '全部':
            list_query['token_status'] = ''
            
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            sql_result = mysqldb.xss_auth_list(username_result['username'], pagenum, pagesize, list_query)
            target_list = sql_result['result']
            total = sql_result['total']
            if target_list == 'L1001':
                response['code'] = 'L1001'
                response['message'] = '系统异常'
            else:
                response['code'] = 'L1000'
                response['message'] = '请求成功'
                if total == 0:
                    response['data'] = ''
                else:
                    response['data'] = sql_result
                return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/generate/domain')
async def generate_domain(request : VueRequest):
    
    """
    从dnslog.cn重新获取域名

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            for thread in dns_thread_list:
                stop_thread(thread)

            t = threading.Thread(target= handle_dns_log, daemon = True, args = (username_result['username'],))
            t.start()
            time.sleep(1)
            response['code'] = 'L1000'
            response['message'] = '请求正常'
            domain = config.get('Domain', 'domain')
            response['data'] = domain
            return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/dns/log')
async def dns_log_list(request : VueRequest):
    
    """
    获取dns log的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        pagenum = request['pagenum']
        pagesize = request['pagesize']
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        list_query = json.loads(request['listQuery'])

        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            sql_result = mysqldb.dns_log_list(username_result['username'], pagenum, pagesize, list_query)
            target_list = sql_result['result']
            total = sql_result['total']
            if target_list == 'L1001':
                response['code'] = 'L1001'
                response['message'] = '系统异常'
            else:
                response['code'] = 'L1000'
                response['message'] = '请求成功'
                if total == 0:
                    response['data'] = ''
                else:
                    response['data'] = sql_result

                response['domain'] = config.get('Domain', 'domain')
                return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/xss/log')
async def xss_log_list(request : VueRequest):
    
    """
    获取xss log的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        pagenum = request['pagenum']
        pagesize = request['pagesize']
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        list_query = json.loads(request['listQuery'])

        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            sql_result = mysqldb.xss_log_list(username_result['username'], pagenum, pagesize, list_query)
            target_list = sql_result['result']
            total = sql_result['total']
            if target_list == 'L1001':
                response['code'] = 'L1001'
                response['message'] = '系统异常'
            else:
                response['code'] = 'L1000'
                response['message'] = '请求成功'
                if total == 0:
                    response['data'] = ''
                else:
                    response['data'] = sql_result
                return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/account/add')
async def account_add(request : VueRequest):
    
    """
    添加用户的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        username = request['username']
        description = request['description']
        password =  pwd_context.hash(request['password'])
        role = request['role']
        random_str = get_capta()
        user_token = aes_crypto.encrypt(username + random_str)
        
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        elif username_result['role'] != 'admin':
            response['code'] = 'L10010'
            response['message'] = '权限不足,无法进行操作'
            return response
        else:
            result = mysqldb.save_account(username, description, user_token, password, role, 'avatar.png')
            response['code'] = result
            if response['code'] == 'L1000':
                response['message'] = '请求成功'
            else:
                response['message'] = '系统异常'
        return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/account/role')
async def account_role(request : VueRequest):
    
    """
    修改用户权限的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        username = request['username']
        role = request['role']
        
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        elif username_result['role'] != 'admin':
            response['code'] = 'L10010'
            response['message'] = '权限不足,无法进行操作'
            return response
        else:
            result = mysqldb.update_account_role(username, role)
            response['code'] = result
            if response['code'] == 'L1000':
                response['message'] = '请求成功'
            else:
                response['message'] = '系统异常'
        return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/account/password')
async def account_password(request : VueRequest):
    
    """
    修改用户密码的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        username = request['username']
        password = pwd_context.hash(request['password'])
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        elif username_result['role'] != 'admin':
            response['code'] = 'L10010'
            response['message'] = '权限不足,无法进行操作'
            return response
        else:
            changps_result = mysqldb.update_account_password(username, password)
            if changps_result == 'L1000':
                response['message'] = '请求成功'
            else:
                response['message'] = '系统异常'
        return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/account/description')
async def account_description(request : VueRequest):
    
    """
    修改用户密码的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        username = request['username']
        description = request['description']
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        elif username_result['role'] != 'admin':
            response['code'] = 'L10010'
            response['message'] = '权限不足,无法进行操作'
            return response
        else:
            changps_result = mysqldb.update_account_description(username, description)
            if changps_result == 'L1000':
                response['message'] = '请求成功'
            else:
                response['message'] = '系统异常'
        return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/delete/account')
async def delete_account(request : VueRequest):
    
    """
    删除用户的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        username = request['username']
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        elif username_result['role'] != 'admin':
            response['code'] = 'L10010'
            response['message'] = '权限不足,无法进行操作'
            return response
        else:
            result = mysqldb.delete_account(username)
            response['code'] = result
            if response['code'] == 'L1000':
                response['message'] = '请求成功'
            else:
                response['message'] = '系统异常'
        return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/account/list')
async def account_list(request : VueRequest):
    
    """
    获取所有用户信息的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        list_query = json.loads(request['listQuery'])
        if list_query['role'] == '全部':
            list_query['role'] = ''
        if list_query['role'] == '全部':
            list_query['role'] = ''

        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            sql_result = mysqldb.account_list(list_query)
            user_list = sql_result['result']
            total = sql_result['total']
            if user_list == 'L1001':
                response['code'] = 'L1001'
                response['message'] = '系统异常'
            else:
                response['code'] = 'L1000'
                response['message'] = '请求成功'
                if total == 0:
                    response['data'] = ''
                else:
                    response['data'] = sql_result
                return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/update/auth')
async def update_auth(request : VueRequest):
    
    """
    更新xss auth的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        xss_token = request['xss_token']
        token_status = request['token_status']
        token = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            set_result = mysqldb.update_xss_auth(username_result['username'], xss_token, token_status)
            if set_result == 'L1000':
                response['code'] = 'L1000'
                response['message'] = '请求成功'
                return response
            elif set_result == 'L1001':
                response['code'] = 'L1001'
                response['message'] = '系统异常'
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/delete/target')
async def delete_target(request : VueRequest):
    
    """
    删除目标的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        target = request['target']
        token = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            delete_result = mysqldb.delete_target(username_result['username'], target)
            if delete_result == 'L1000':
                response['code'] = 'L1000'
                response['message'] = '请求成功'
            elif delete_result == 'L1001':
                response['code'] = 'L1001'
                response['message'] = '系统异常'
            return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/delete/port')
async def delete_port(request : VueRequest):
    
    """
    删除端口的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        target = request['target']
        scan_ip = request['scan_ip']
        port = request['port']
        token = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            delete_result = mysqldb.delete_port(username_result['username'], target, scan_ip, port)
            if delete_result == 'L1000':
                response['code'] = 'L1000'
                response['message'] = '请求成功'
            elif delete_result == 'L1001':
                response['code'] = 'L1001'
                response['message'] = '系统异常'
            return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/delete/vulner')
async def delete_vulner(request : VueRequest):
    
    """
    删除漏洞的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        target = request['target']
        ip_port = request['ip_port']
        vulner_name = request['vulner_name']
        token = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            delete_result = mysqldb.delete_vulner(username_result['username'], target, ip_port, vulner_name)
            if delete_result == 'L1000':
                response['code'] = 'L1000'
                response['message'] = '请求成功'
            elif delete_result == 'L1001':
                response['code'] = 'L1001'
                response['message'] = '系统异常'
            return response
        
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/delete/dns/log')
async def delete_dns_log(request : VueRequest):
    
    """
    删除dns log的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        id = request['id']
        token = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            delete_result = mysqldb.delete_dns_log(username_result['username'], id)
            if delete_result == 'L1000':
                response['code'] = 'L1000'
                response['message'] = '请求成功'
            elif delete_result == 'L1001':
                response['code'] = 'L1001'
                response['message'] = '系统异常'
            return response
        
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/delete/xss/log')
async def delete_xss_log(request : VueRequest):
    
    """
    删除xss log的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        id = request['id']
        token = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            delete_result = mysqldb.delete_xss_log(username_result['username'], id)
            if delete_result == 'L1000':
                response['code'] = 'L1000'
                response['message'] = '请求成功'
            elif delete_result == 'L1001':
                response['code'] = 'L1001'
                response['message'] = '系统异常'
            return response
        
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/delete/auth')
async def delete_auth(request : VueRequest):
    
    """
    删除xss auth的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        xss_token = request['xss_token']
        token = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            delete_result = mysqldb.delete_xss_auth(username_result['username'], xss_token)
            if delete_result == 'L1000':
                response['code'] = 'L1000'
                response['message'] = '请求成功'
            elif delete_result == 'L1001':
                response['code'] = 'L1001'
                response['message'] = '系统异常'
            return response
        
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/system/list')
async def system_list(request : VueRequest):
    
    """
    查看系统设置信息的接口

    :param:
    :return str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': '', 'total': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        token = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            data = {
                'proxy': config.get('request', 'proxy'),
                'timeout': config.get('request', 'timeout')
            }
            data_list = []
            data_list.append(data)
            response['code'] = 'L1000'
            response['message'] = '请求成功'
            response['total'] = 1
            response['data'] = data_list
            return response
        
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/system/set')
async def system_set(request : VueRequest):
    
    """
    进行系统设置的接口

    :param:
    :return str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        proxytype = request['proxytype']
        proxyip = request['proxyip']
        timeout = request['timeout']
        token = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
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
            response['code'] = 'L1000'
            response['message'] = '请求成功'
            return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.post('/api/upload/image')
async def upload_image(request : VueRequest):
    
    """
    上传文件的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        token = request['token']
        imgdata = request['imgdata']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            ticks = time.time()
            time_flag = md5(aes_crypto.encrypt(str(ticks)))
            filename = time_flag + '.' + 'png'
            b64_data = imgdata.split(';base64,')[1]
            data = base64.b64decode(b64_data)
            with open('images/%s' %(filename), 'wb') as writer:
                writer.write(data)
            writer.close()
            response['code'] = 'L10008'
            response['message'] = '上传文件成功！'
            response['data'] = filename
            return response
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.get('/api/images/{filename}')
async def get_image(filename):
    
    """
    获取用户头像内容的接口

    :param:
    :return: str response: 需要返回的数据
    """
    
    return FileResponse(UPLOAD_FOLDER + '/' + filename)

@app.post('/api/change/avatar')
async def change_avatar(request : VueRequest):
    
    """
    修改用户头像的接口

    :param:
    :return: str response: 需要返回的数据
    """

    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = rsa_crypto.decrypt(request.data)
        request = json.loads(request)
        imagename = request['imagename']
        token = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        username_result = mysqldb.username(query_str)
        if username_result == 'L1001':
            response['code'] = 'L1001'
            response['message'] = '系统异常'
            return response
        elif username_result == None:
            response['code'] = 'L1003'
            response['message'] = '认证失败'
            return response
        else:
            set_result = mysqldb.change_avatar(username_result['username'], imagename)
            if set_result == 'L1000':
                response['code'] = 'L1000'
                response['message'] = '请求成功'
                return response
            elif set_result == 'L1001':
                response['code'] = 'L1001'
                response['message'] = '系统异常'
    except Exception as e:
        print(e)
        response['code'] = 'L1001'
        response['message'] = '系统异常'
        return response

@app.get('/api/log')
async def log(token: str, data: str, request: Request):
    
    """
    接收xss log的接口

    :param:
    :return:
    """

    try:
        username = mysqldb.xss_username(token)
        if username:
            path = '/api/log?' + str(request.query_params)
            ip = request.client.host
            if 'user-agent' in  request.headers.keys():
                ua = request.headers['user-agent']
            mysqldb.save_xss_log(username, path, data, ua, ip)
    except Exception as e:
        print(e)

@app.websocket("/ws/target/status")
async def target_status(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = await websocket.receive_json()
        request = rsa_crypto.decrypt(request['data'])
        request = json.loads(request)
        pagenum = request['pagenum']
        pagesize = request['pagesize']
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        list_query = json.loads(request['listQuery'])
        if list_query['scan_status'] == '全部':
            list_query['scan_status'] = ''
        if list_query['scan_schedule'] == '全部':
            list_query['scan_schedule'] = ''

        username_result = mysqldb.username(query_str)

        while True:
            if username_result and username_result != 'L1001':
                sql_result = mysqldb.target_list(username_result['username'], pagenum, pagesize, list_query)
                target_list = sql_result['result']
                total = sql_result['total']
                if target_list != 'L1001' and target_list != []:
                    response['code'] = 'L1000'
                    response['message'] = '请求成功'
                    if total == 0:
                        response['data'] = ''
                    else:
                        response['data'] = sql_result
                    await manager.send_personal_message(response, websocket)

            await asyncio.sleep(5)
    except WebSocketDisconnect:
        print('Websocket连接断开')
        manager.disconnect(websocket)
    except Exception as e:
        print(e)
        pass

@app.websocket("/ws/scan/status")
async def scan_status(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = await websocket.receive_json()
        request = rsa_crypto.decrypt(request['data'])
        request = json.loads(request)
        pagenum = request['pagenum']
        pagesize = request['pagesize']
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        list_query = json.loads(request['listQuery'])
        if list_query['scan_status'] == '全部':
            list_query['scan_status'] = ''
        if list_query['scan_schedule'] == '全部':
            list_query['scan_schedule'] = ''

        username_result = mysqldb.username(query_str)

        while True:
            if username_result and username_result != 'L1001':
                sql_result = mysqldb.scan_list(username_result['username'], pagenum, pagesize, list_query)
                scan_list = sql_result['result']
                total = sql_result['total']
                if scan_list != 'L1001' and scan_list != []:
                    response['code'] = 'L1000'
                    response['message'] = '请求成功'
                    response['total'] = total
                    if total == 0:
                        response['data'] = ''
                    else:
                        response['data'] = sql_result

                    await manager.send_personal_message(response, websocket)

            await asyncio.sleep(5)
    except WebSocketDisconnect:
        print('Websocket连接断开')
        manager.disconnect(websocket)
    except Exception as e:
        print(e)
        pass

if __name__ == '__main__':
    # uvicorn.run(app = 'main:app', host = '0.0.0.0', port = 5000, reload = True, debug = True)
    uvicorn.run(app = 'main:app', host = '0.0.0.0', port = 8000, reload = False, debug = False)
