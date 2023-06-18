#!/usr/bin/env python3

import json
from fastapi import APIRouter
from app.depend.depends import VueRequest, rsa_crypto, mysqldb

router = APIRouter(prefix = "/vulner", tags = ["vulner"])

@router.post('/list')
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

@router.post('/delete')
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
