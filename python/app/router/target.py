#!/usr/bin/env python3

import json
from fastapi import APIRouter
from app.utils.queue import queue_target_list
from app.depend.depends import VueRequest, rsa_crypto, mysqldb, high_queue

router = APIRouter(prefix = "/target", tags = ["target"])

@router.post('/query')
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

@router.post('/new')
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

@router.post('/edit')
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

@router.post('/detail')
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

@router.post('/list')
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

@router.post('/delete')
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
