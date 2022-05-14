/** When your routing table is too long, you can split it into small modules **/

import Layout from '@/layout'

const pocRouter = {
  path: '/poc',
  name: 'poc',
  redirect: '/poc/index',
  component: Layout,
  meta: { title: 'PocManager', icon: 'el-icon-scissors', noCache: true, breadcrumb: false },
  children: [
    {
      path: 'index',
      name: 'PocManager',
      component: () => import('@/views/poc/index'),
      meta: { title: 'PocManager', icon: 'el-icon-scissors', noCache: true }
    }
  ]
}
export default pocRouter
