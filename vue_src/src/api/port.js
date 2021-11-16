import request from '@/utils/request'

export function portList(data) {
  return request({
    url: '/api/port/list',
    method: 'post',
    data
  })
}

export function deletePort(data) {
  return request({
    url: '/api/delete/port',
    method: 'post',
    data
  })
}
