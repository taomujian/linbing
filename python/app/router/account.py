#!/usr/bin/env python3

import os
import json
from fastapi import APIRouter
from app.lib.common import get_capta
from app.depend.depends import VueRequest, aes_crypto, rsa_crypto, mysqldb, pwd_context

router = APIRouter(prefix = "/account", tags = ["account"])

@router.post('/query')
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

@router.post('/add')
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

@router.post('/role')
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

@router.post('/password')
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

@router.post('/description')
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

@router.post('/delete')
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

@router.post('/list')
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
