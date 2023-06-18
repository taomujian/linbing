#!/usr/bin/env python3

import os
import json
import time
import ctypes
import inspect
import threading
import configparser
from dnslog import Dnslog
from pydantic import BaseModel
from fastapi import APIRouter
from app.depend.depends import VueRequest, rsa_crypto, mysqldb

dns_thread_list = []
UPLOAD_FOLDER = 'images'  #文件存放路径
if not os.path.exists("images"):
    os.mkdir("images")

router = APIRouter(prefix = "/dns", tags = ["dns"])

config = configparser.ConfigParser()
config.read('conf.ini', encoding = 'utf-8')


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

@router.post('/generate/domain')
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

@router.post('/log')
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

@router.post('/log/delete')
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
