import request from '@/utils/request'

export function vulnerList(data) {
  return request({
    url: '/api/vulner/list',
    method: 'post',
    data
  })
}

export function setVulner(data) {
  return request({
    url: '/api/set/vulner',
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
