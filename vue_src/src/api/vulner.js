import request from '@/utils/request'

export function vulnerName(data) {
  return request({
    url: '/api/vulner/name',
    method: 'post',
    data
  })
}

export function vulnerList(data) {
  return request({
    url: '/api/vulner/list',
    method: 'post',
    data
  })
}

export function deleteVulner(data) {
  return request({
    url: '/api/delete/vulner',
    method: 'post',
    data
  })
}
