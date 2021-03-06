/** When your routing table is too long, you can split it into small modules **/

import Layout from '@/layout'

const vulnerRouter = {
  path: '/vulner',
  name: 'vulner',
  redirect: '/vulner/index',
  component: Layout,
  meta: { title: 'VulnerManager', icon: 'el-icon-s-grid', noCache: true },
  children: [
    {
      path: 'index',
      name: 'VulnerList',
      component: () => import('@/views/vulner/index'),
      meta: { title: 'VulnerList', icon: 'el-icon-s-grid', noCache: true }
    }
  ]
}
export default vulnerRouter
