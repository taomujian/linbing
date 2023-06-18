#!/usr/bin/env python3

import os
import json
from fastapi import APIRouter
from app.depend.depends import VueRequest, rsa_crypto, mysqldb, config

router = APIRouter(prefix = "/system", tags = ["system"])

@router.post('/list')
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

@router.post('/set')
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