import request from '@/utils/request'

export function systemList(data) {
  return request({
    url: '/api/system/list',
    method: 'post',
    data
  })
}

export function systemSet(data) {
  return request({
    url: '/api/system/set',
    method: 'post',
    data
  })
}
