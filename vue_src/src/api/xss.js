import request from '@/utils/request'

export function xsslogList(data) {
  return request({
    url: '/api/xss/log',
    method: 'post',
    data
  })
}

export function authList(data) {
  return request({
    url: '/api/xss/auth',
    method: 'post',
    data
  })
}

export function generateAuth(data) {
  return request({
    url: '/api/generate/auth',
    method: 'post',
    data
  })
}

export function updateAuth(data) {
  return request({
    url: '/api/update/auth',
    method: 'post',
    data
  })
}

export function deletexssLog(data) {
  return request({
    url: '/api/delete/xss/log',
    method: 'post',
    data
  })
}

export function deleteAuth(data) {
  return request({
    url: '/api/delete/auth',
    method: 'post',
    data
  })
}
