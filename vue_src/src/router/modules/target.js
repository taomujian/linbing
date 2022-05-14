/** When your routing table is too long, you can split it into small modules **/

import Layout from '@/layout'

const targetRouter = {
  path: '/target',
  component: Layout,
  redirect: '/target/index',
  name: 'target',
  meta: { title: 'TargetManager', icon: 'el-icon-link', noCache: true, breadcrumb: false },
  children: [
    {
      path: 'index',
      component: () => import('@/views/target/index'),
      name: 'TargetManager',
      meta: { title: 'TargetManager', noCache: true }
    },
    {
      path: 'detail',
      component: () => import('@/views/target/detail'),
      name: 'TargetDetail',
      hidden: true,
      meta: { title: 'TargetDetail', noCache: true }
    }
  ]
}
export default targetRouter
