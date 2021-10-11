import request from '@/utils/request'

export function pocName(data) {
  return request({
    url: '/api/poc/name',
    method: 'post',
    data
  })
}

export function pocList(data) {
  return request({
    url: '/api/poc/list',
    method: 'post',
    data
  })
}
