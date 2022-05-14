/** When your routing table is too long, you can split it into small modules **/

import Layout from '@/layout'

const portRouter = {
  path: '/port',
  name: 'port',
  redirect: '/port/index',
  component: Layout,
  meta: { icon: 'el-icon-info', noCache: true, breadcrumb: false },
  children: [
    {
      path: 'index',
      name: 'AssetManager',
      component: () => import('@/views/port/index'),
      meta: { title: 'AssetManager', icon: 'el-icon-info', noCache: true }
    }
  ]
}
export default portRouter
