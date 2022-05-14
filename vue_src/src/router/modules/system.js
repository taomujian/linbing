/** When your routing table is too long, you can split it into small modules **/

import Layout from '@/layout'

const systemRouter = {
  path: '/system',
  name: 'system',
  redirect: '/system/index',
  component: Layout,
  meta: { icon: 'el-icon-s-tools', noCache: true, breadcrumb: false },
  children: [
    {
      path: 'index',
      name: 'SystemList',
      component: () => import('@/views/system/index'),
      meta: { title: 'SystemSetting', icon: 'el-icon-s-tools', noCache: true }
    }
  ]
}
export default systemRouter
