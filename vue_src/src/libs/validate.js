import http  from '@/libs/http'
import RSA  from '@/libs/crypto'
import {getToken} from '@/libs/util'

/* 是否是邮箱 */
export function isemail (rule, value, callback) {
    const reg = /^[a-z0-9](?:[-_.+]?[a-z0-9]+)*@.*?\.com$/
    if (!reg.test(value.trim())) {
        return callback(new Error('请输入合法邮箱'));   
    }
    else {
        let data = {
            'type': 'email',
            'data': value
        }
        data = JSON.stringify(data)
        let params = {'data': RSA.Encrypt(data)}
        http.post('/api/query', params).then((res) => {
            res.data = eval('(' + res.data + ')')
            switch(res.data.code ){
                case 'Z1001':
                return callback(new Error('系统异常'))
                case 'Z1002':
                return callback(new Error('请求方法异常'))
                case 'Z1007':
                return callback(new Error('邮箱已注册'))
                default:
                callback()
            }
        })
    }
}

/* 注册时用户名规则 */
export function isusername (rule, value, callback) {
    const reg = /^[A-Za-z0-9]{1,10}$/
    if(!reg.test(value.trim())) {
        return callback(new Error('用户名输入错误'));
    }
    else {
        let data = {
            'type': 'username',
            'data': value
        }
        data = JSON.stringify(data)
        let params = {'data': RSA.Encrypt(data)}
        http.post('/api/query', params).then((res) => {
            res.data = eval('(' + res.data + ')');
            switch(res.data.code ){
                case 'Z1001':
                return callback(new Error('系统异常'))
                case 'Z1002':
                return callback(new Error('请求方法异常'))
                case 'Z1006':
                return callback(new Error('用户名已注册'))
                default:
                callback()
            }
        })
    }
  }

/* 新建目标时的规则 */
export function istarget (rule, value, callback) {
    value = value.split(/[(\r\n)\r\n]+/);
    for (var i=0; i<value.length; i++)
    {
        let data = {
            'type': 'target',
            'data': {
                'data': value[i],
                'token': getToken()
            }
        }
        data = JSON.stringify(data)
        let params = {'data': RSA.Encrypt(data)}
        http.post('/api/query', params).then((res) => {
            res.data = eval('(' + res.data + ')');
            switch(res.data.code ){
                case 'Z1001':
                return callback(new Error('系统异常'))
                case 'Z1002':
                return callback(new Error('请求方法异常'))
                case 'Z10010':
                return callback(new Error('目标已存在,请不要重复添加目标,如已删除请在垃圾箱内恢复'))
                default:
                callback()
            }
        })
    }
    
  }

export function loginusername (rule, value, callback) {
    const reg = /^[A-Za-z0-9]{1,10}$/
    if(!reg.test(value.trim())) {
        return callback(new Error('用户名输入错误'));
    }
    else {
        callback()
        }
}

/* 注册码长度是否达到要求 */
export function ischecknum(rule, value, callback) {
    const reg = /^[A-Za-z0-9]{6}$/
    if (!reg.test(value.trim())) {
        return callback(new Error('注册码输入错误'));
    }
    else {
        callback()
    }
}

/* 密码长度是否达到要求 */
export function ispassword(rule, value, callback) {
    const reg = /^[A-Za-z0-9]{8,16}$/
    if (!reg.test(value.trim())) {
        return callback(new Error('密码输入错误'));
    }
    else {
        callback()
        }
}