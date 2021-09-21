/** When your routing table is too long, you can split it into small modules **/

import Layout from '@/layout'

const userRouter = {
  path: '/change',
  component: Layout,
  redirect: 'noRedirect',
  name: 'change',
  hidden: true,
  meta: {
    title: '修改',
    icon: 'component'
  },
  children: [
    {
      path: 'avatar',
      component: () => import('@/views/change/avatar'),
      name: 'ChangeAvatar',
      meta: { title: 'ChangeAvatar' }
    },
    {
      path: 'password',
      component: () => import('@/views/change/password'),
      name: 'ChangePassword',
      meta: { title: '修改密码' }
    }
  ]
}

export default userRouter
