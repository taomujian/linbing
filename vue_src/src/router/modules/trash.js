/** When your routing table is too long, you can split it into small modules **/

import Layout from '@/layout'

const trashRouter = {
  path: '/trash',
  name: 'trash',
  redirect: '/trash/index',
  component: Layout,
  meta: { title: 'Trash', icon: 'el-icon-delete-solid', noCache: true },
  children: [
    {
      path: 'target',
      name: 'TrashTarget',
      component: () => import('@/views/trash/target'),
      meta: { title: 'TargetList', icon: 'el-icon-link', noCache: true }
    },
    {
      path: 'port',
      name: 'TrashPort',
      component: () => import('@/views/trash/port'),
      meta: { title: 'PortList', icon: 'el-icon-info', noCache: true }
    },
    {
      path: 'vulner',
      name: 'TrashVulner',
      component: () => import('@/views/trash/vulner'),
      meta: { title: 'VulnerList', icon: 'table', noCache: true }
    }
  ]
}
export default trashRouter
