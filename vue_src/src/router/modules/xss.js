/** When your routing table is too long, you can split it into small modules **/

import Layout from '@/layout'

const xssRouter = {
  path: '/xss',
  name: 'xss',
  redirect: '/xss/index',
  component: Layout,
  meta: { title: 'XssManager', icon: 'el-icon-monitor', noCache: true, breadcrumb: false },
  children: [
    {
      path: 'log',
      name: 'XssLog',
      component: () => import('@/views/xss/log'),
      meta: { title: 'XssLog', icon: 'el-icon-chat-round', noCache: true }
    },
    {
      path: 'auth',
      name: 'XssAuth',
      component: () => import('@/views/xss/auth'),
      meta: { title: 'XssAuth', icon: 'el-icon-umbrella', noCache: true }
    }
  ]
}
export default xssRouter
