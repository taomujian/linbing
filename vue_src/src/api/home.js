import request from '@/utils/request'

export function getCard(data) {
  return request({
    url: '/api/home/card',
    method: 'post',
    data
  })
}

export function get7day(data) {
  return request({
    url: '/api/home/7day',
    method: 'post',
    data
  })
}
