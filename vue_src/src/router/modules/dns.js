/** When your routing table is too long, you can split it into small modules **/

import Layout from '@/layout'

const dnsRouter = {
  path: '/dns',
  name: 'dns',
  redirect: '/dns/index',
  component: Layout,
  meta: { title: 'DNS日志', icon: 'el-icon-monitor', noCache: true, breadcrumb: false },
  children: [
    {
      path: 'log',
      name: 'DnsLog',
      component: () => import('@/views/dns/log'),
      meta: { title: 'DnsLog', icon: 'el-icon-chat-round', noCache: true }
    }
  ]
}
export default dnsRouter
