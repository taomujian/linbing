/** When your routing table is too long, you can split it into small modules **/

import Layout from '@/layout'

const scanRouter = {
  path: '/scan',
  name: 'scan',
  redirect: '/scan/index',
  component: Layout,
  meta: { title: 'ScanManager', icon: 'el-icon-view', noCache: true },
  children: [
    {
      path: 'index',
      name: 'ScanList',
      component: () => import('@/views/scan/index'),
      meta: { title: 'ScanList', icon: 'el-icon-view', noCache: true }
    },
    {
      path: 'detail',
      name: 'ScanDetail',
      hidden: true,
      component: () => import('@/views/change/avatar'),
      meta: { title: '扫描详情', icon: 'user', noCache: true }
    }
  ]
}
export default scanRouter
