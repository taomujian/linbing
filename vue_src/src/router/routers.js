import Main from '@/components/main'
import parentView from '@/components/parent-view'

/**
 * iview-admin中meta除了原生参数外可配置的参数:
 * meta: {
 *  title: { String|Number|Function }
 *         显示在侧边栏、面包屑和标签栏的文字
 *         使用'{{ 多语言字段 }}'形式结合多语言使用，例子看多语言的路由配置;
 *         可以传入一个回调函数，参数是当前路由对象，例子看动态路由和带参路由
 *  hideInBread: (false) 设为true后此级路由将不会出现在面包屑中，示例看QQ群路由配置
 *  hideInMenu: (false) 设为true后在左侧菜单不会显示该页面选项
 *  notCache: (false) 设为true后页面在切换标签后不会缓存，如果需要缓存，无需设置这个字段，而且需要设置页面组件name属性和路由配置的name一致
 *  access: (null) 可访问该页面的权限数组，当前路由设置的权限会影响子路由
 *  icon: (-) 该页面在左侧菜单、面包屑和标签导航处显示的图标，如果是自定义图标，需要在图标名称前加下划线'_'
 *  beforeCloseName: (-) 设置该字段，则在关闭当前tab页时会去'@/router/before-close.js'里寻找该字段名对应的方法，作为关闭前的钩子函数
 * }
 */

export default [
  {
    path: '/login',
    name: 'login',
    meta: {
      title: 'Login - 登录',
      hideInMenu: true
    },
    component: () => import('@/view/login/login.vue')
  },
  {
    path: '/register',
    name: 'register',
    meta: {
      title: 'Register - 注册',
      hideInMenu: true
    },
    component: () => import('@/view/register/register.vue')
  },
  {
    path: '/findpassword',
    name: 'findpassword',
    meta: {
      title: 'Findpassword- 找回密码',
      hideInMenu: true
    },
    component: () => import('@/view/findpassword/findpassword.vue')
  },
  {
    path: '/',
    name: '_home',
    redirect: '/login',
    component: Main,
    meta: {
      hideInMenu: true,
      notCache: true
    },
    children: [
      {
        path: '/home',
        name: 'home',
        meta: {
          hideInMenu: true,
          title: '首页',
          notCache: true,
          icon: 'md-home'
        },
        component: () => import('@/view/single-page/home')
      }
    ]
  },
  {
    path: '/password',
    name: 'password',
    component: Main,
    meta: {
      hideInBread: true,
      hideInMenu: true
    },
    children: [
      {
        path: 'change_password',
        name: 'change_password',
        meta: {
          icon: 'md-notifications',
          title: '修改密码'
        },
        component: () => import('@/view/changepassword/changepassword.vue')
      }
    ]
  },
  {
    path: '/avatar',
    name: 'avatar',
    component: Main,
    meta: {
      hideInBread: true,
      hideInMenu: true
    },
    children: [
      {
        path: 'change_avatar',
        name: 'change_avatar',
        meta: {
          icon: 'md-notifications',
          title: '修改头像',
        },
        component: () => import('@/view/changeavatar/changeavatar.vue')
      }
    ]
  },
  {
    path: '/new',
    name: '新建目标',
    component: Main,
    meta: {
      hideInBread: true,
      hideInMenu: false
    },
    children: [
      {
        path: 'target',
        name: '新建目标',
        meta: {
          icon: 'ios-infinite',
          title: '新建目标',
        },
        component: () => import('@/view/components/new_target/new_target.vue')
      }
    ]
  },
  {
    path: '/scan_set',
    name: '扫描设置',
    component: Main,
    meta: {
      hideInBread: true,
      hideInMenu: true
    },
    children: [
      {
        path: '/scan_set',
        name: '扫描设置',
        meta: {
          icon: 'ios-infinite',
          title: '扫描设置',
        },
        component: () => import('@/view/components/scan_set/scan_set.vue')
      }
    ]
  },
  {
    path: 'edit',
    name: '修改目标',
    meta: {
      hideInMenu: true,
      icon: 'ios-infinite',
      title: '修改目标',
    },
    component: () => import('@/view/components/new_target/new_target.vue')
  },
  {
    path: '/detail',
    name: '漏洞详情',
    component: Main,
    meta: {
      hideInBread: true,
      hideInMenu: true
    },
    children: [
      {
        path: 'port',
        name: '端口详情',
        meta: {
          icon: 'ios-infinite',
          title: '端口详情',
        },
        component: () => import('@/view/components/port_detail/port_detail.vue')
      },
      {
        path: 'subdomain',
        name: '子域名详情',
        meta: {
          icon: 'ios-infinite',
          title: '子域名详情',
        },
        component: () => import('@/view/components/domain_detail/domain_detail.vue')
      },
      {
        path: 'vuln',
        name: '漏洞详情',
        meta: {
          icon: 'ios-infinite',
          title: '漏洞详情',
        },
        component: () => import('@/view/components/vuln_detail/vuln_detail.vue')
      }
    ]
  },
  {
    path: '/target',
    name: '目标',
    component: Main,
    meta: {
      hideInBread: true,
      hideInMenu: false
    },
    children: [
      {
        path: 'list',
        name: '目标列表',
        meta: {
          icon: 'ios-infinite',
          title: '目标列表',
        },
        component: () => import('@/view/components/target/target_list.vue')
      }
    ]
  },
  {
    path: '/scan',
    name: '扫描列表',
    component: Main,
    meta: {
      hideInBread: true,
      hideInMenu: false
    },
    children: [
      {
        path: 'list',
        name: '扫描列表',
        meta: {
          icon: 'ios-infinite',
          title: '扫描列表',
        },
        component: () => import('@/view/components/scan/scan_list.vue')
      }
    ]
  },
  {
    path: '/vulner',
    name: '漏洞',
    component: Main,
    meta: {
      hideInBread: true,
      hideInMenu: false
    },
    children: [
      {
        path: 'list',
        name: '漏洞列表',
        meta: {
          icon: 'ios-infinite',
          title: '漏洞列表',
        },
        component: () => import('@/view/components/vulner/vulner_list.vue')
      }
    ]
  },
  {
    path: '/trash',
    name: '漏洞',
    component: Main,
    meta: {
      hideInBread: true,
      hideInMenu: false
    },
    children: [
      {
        path: 'targetlist',
        name: '目标垃圾箱',
        meta: {
          icon: 'ios-infinite',
          title: '目标垃圾箱列表',
        },
        component: () => import('@/view/components/trash/trash_list.vue')
      }
    ]
  },
  {
    path: '/trash',
    name: '漏洞',
    component: Main,
    meta: {
      hideInBread: true,
      hideInMenu: false
    },
    children: [
      {
        path: 'vulnerlist',
        name: '漏洞垃圾箱',
        meta: {
          icon: 'ios-infinite',
          title: '漏洞垃圾箱列表',
        },
        component: () => import('@/view/components/trash/vulner_list.vue')
      }
    ]
  },

  {
    path: '/system',
    name: '系统设置路由前缀',
    component: Main,
    meta: {
      hideInBread: true,
      hideInMenu: false
    },
    children: [
      {
        path: '/',
        name: '系统设置',
        meta: {
          icon: 'ios-infinite',
          title: '系统设置',
        },
        component: () => import('@/view/components/system/system.vue')
      },
      {
        path: '/system/set',
        name: '配置系统信息',
        meta: {
          icon: 'ios-infinite',
          title: '配置系统信息',
          hideInBread: true,
          hideInMenu: true
        },
        component: () => import('@/view/components/system_set/system_set.vue')
      }
    ]
  },
  
  {
    path: '/argu',
    name: 'argu',
    meta: {
      hideInMenu: true
    },
    component: Main,
    children: [
      {
        path: 'params/:id',
        name: 'params',
        meta: {
          icon: 'md-flower',
          title: route => '{{ params }}-${route.params.id}',
          notCache: true,
          beforeCloseName: 'before_close_normal'
        },
        component: () => import('@/view/argu-page/params.vue')
      },
      {
        path: 'query',
        name: 'query',
        meta: {
          icon: 'md-flower',
          title: route => `{{ query }}-${route.query.id}`,
          notCache: true
        },
        component: () => import('@/view/argu-page/query.vue')
      }
    ]
  },
  {
    path: '/401',
    name: 'error_401',
    meta: {
      hideInMenu: true
    },
    component: () => import('@/view/error-page/401.vue')
  },
  {
    path: '/500',
    name: 'error_500',
    meta: {
      hideInMenu: true
    },
    component: () => import('@/view/error-page/500.vue')
  },
  {
    path: '*',
    name: 'error_404',
    meta: {
      hideInMenu: true
    },
    component: () => import('@/view/error-page/404.vue')
  }
]
