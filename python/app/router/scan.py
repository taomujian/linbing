#!/usr/bin/env python3

import os
import json
import time
import configparser
from rq import Queue
from redis import Redis
from pydantic import BaseModel
from passlib.context import CryptContext
from app.lib.rsa import Rsa_Crypto
from app.lib.aes import Aes_Crypto
from app.utils.mysql import Mysql_db
from fastapi import APIRouter
from app.lib.encode import md5
from rq.command import send_stop_job_command
from app.utils.queue import queue_scan_list
from app.depend.depends import VueRequest, rsa_crypto, mysqldb, high_queue, redis_conn

router = APIRouter(prefix = "/scan", tags = ["scan"])

@router.post('/set')
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

@router.post('/start')
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

@router.post('/pause')
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

@router.post('/resume')
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

@router.post('/cancel')
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


@router.post('/list')
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
