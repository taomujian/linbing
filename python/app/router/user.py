#!/usr/bin/env python3

import time
import json
from fastapi import APIRouter
from fastapi.responses import FileResponse
from app.lib.common import get_capta
from app.lib.encode import md5, base64
from app.depend.depends import VueRequest, rsa_crypto, mysqldb, pwd_context, aes_crypto, UPLOAD_FOLDER

router = APIRouter()

@router.post('/query/password')
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

@router.post('/login')
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

@router.post('/userinfo')
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

@router.post('/logout')
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

@router.post('/change/password')
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

@router.post('/upload/image')
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

@router.get('/images/{filename}')
async def get_image(filename):
    
    """
    获取用户头像内容的接口

    :param:
    :return: str response: 需要返回的数据
    """
    
    return FileResponse(UPLOAD_FOLDER + '/' + filename)

@router.post('/change/avatar')
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
