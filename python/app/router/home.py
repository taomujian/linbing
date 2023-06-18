#!/usr/bin/env python3

import json
from fastapi import APIRouter
from app.depend.depends import VueRequest, rsa_crypto, mysqldb

router = APIRouter(prefix = "/home", tags = ["home"])

@router.post('/card')
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

@router.post('/7day')
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
