#!/usr/bin/env python3

import os
import json
from fastapi import APIRouter
from app.depend.depends import VueRequest, rsa_crypto, mysqldb

router = APIRouter(prefix = "/poc", tags = ["poc"])

@router.post('/name')
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

@router.post('/list')
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
