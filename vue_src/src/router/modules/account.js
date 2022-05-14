/** When your routing table is too long, you can split it into small modules **/

import Layout from '@/layout'

const accountRouter = {
  path: '/account',
  component: Layout,
  redirect: '/account/index',
  name: 'account',
  meta: { icon: 'el-icon-user-solid', roles: ['admin'], noCache: true, breadcrumb: false },
  children: [
    {
      path: 'index',
      component: () => import('@/views/account/index'),
      name: 'AccountManager',
      meta: { title: 'AccountManager', roles: ['admin'], noCache: true }
    }
  ]
}
export default accountRouter
