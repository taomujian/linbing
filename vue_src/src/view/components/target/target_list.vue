<template>
  <div>
    <Card>
      <Table   border  editable searchable search-place="top" :data="tableData" :columns="columns"/>
      <Page
          class="page" 
          :current="this.page.pageNum" 
          :page-size="this.page.pageSize" 
          :total= "this.page.count" 
          :page-size-opts="[10,20]"
          show-sizer
          show-elevator
          show-total
          @on-change="handlePage"
          @on-page-size-change="handlePageSize">
      </Page>
    </Card>
  </div>
</template>

<script>
import RSA  from '@/libs/crypto'
import http  from '@/libs/http'
import {getToken } from '@/libs/util'
export default {
  inject: ['reload'],
  name: 'tables_page',
  data () {
    return {
      token: getToken(),
      page: {
          pageNum: 1,
          pageSize: 10,
          count: 0
      },
      columns: [
        {
          title: '目标',
          key: 'target',
          sortable: true,
          resizable: true,
          width: 150
        },
        {
          title: '描述',
          key: 'description',
          sortable: true,
          resizable: true,
          width: 290
        },
        { 
          title: '创建时间', 
          key: 'create_time',
          resizable: true,
          width: 260
        },
        {
          title: '漏洞数量',
          key: 'vulner_number',
          resizable: true,
          width: 150
        },
        { 
          title: '扫描状态',
          key: 'scan_schedule',
          resizable: true,
          width: 150
        },
        {
          title: '操作',
          key: 'action',
          width: 350,
          resizable: true,
          align: 'center',
          render: (h, params) => {
            return h('div', [
                h('Button', {
                    props: {
                        type: 'primary',
                        size: 'small'
                    },
                    style: {
                        marginRight: '10px'
                    },
                    on: {
                        click: () => {
                            this.scan(params)
                        }
                    }
                }, '开始扫描'),
                h('Button', {
                    props: {
                        type: 'primary',
                        size: 'small'
                    },
                    style: {
                        marginRight: '10px'
                    },
                    on: {
                        click: () => {
                            this.scan_set(params)
                        }
                    }
                }, '扫描设置'),
                h('Button', {
                    props: {
                        type: 'primary',
                        size: 'small'
                    },
                    style: {
                        marginRight: '10px'
                    },
                    on: {
                        click: () => {
                            this.show(params)
                        }
                    }
                }, '漏洞详情'),
                h('Button', {
                    props: {
                        type: 'error',
                        size: 'small'
                    },
                    on: {
                        click: () => {
                            this.remove(params)
                        }
                    }
                }, '删除')
            ]);
        }
      }
      ],
      tableData: []
    }
  },
  methods: {
    getTableData () {
      let data = {
        'pagenum': this.page.pageNum,
        'pagesize': this.page.pageSize,
        'flag': '0',
        'token': this.token.trim()
      }
      data = JSON.stringify(data)
      let params = {'data': RSA.Encrypt(data)}
      http.post('/api/targetlist', params).then((res) => {
        res.data = eval('(' + res.data + ')')
        switch(res.data.code ){
          case'Z1000':
          if (res.data.data.result !== ""){
            this.tableData = res.data.data.result
          }
          this.page.count = res.data.data.total
          break
          case 'Z1001':
          this.$Notice.error({
              title: '获取数据失败',
              desc: '系统发生异常,请稍后再次尝试'
          })
          break
          case 'Z1002':
          this.$Notice.error({
              title: '获取数据失败',
              desc: '系统发生异常,请稍后再次尝试'
          })
          break
          case 'Z1004':
          this.$Notice.error({
              title: '获取数据失败',
              desc: '认证失败,请稍后再次尝试'
          })
          break
          case 'Z1009':
          this.$Notice.info({
              title: '数据为空',
              desc: '数据为空,请新建笔记'
          })
          break
          default:
          break
        }
      })
    },
    scan (params) {
      let data = {
        'target': params.row.target,
        'description': params.row.description,
        'token': this.token.trim()
      }
      data = JSON.stringify(data)
      let req_params = {'data': RSA.Encrypt(data)}
      http.post('/api/scan', req_params).then((res) => {
        res.data = eval('(' + res.data + ')')
        switch(res.data.code ){
          case'Z1000':
          this.$Notice.success({
              title: '已开始扫描',
              desc: '请稍后在扫描列表中查看'
          })
          setTimeout(() => {
            this.$router.push({
                path: '/scan/list'
              })
            },5000)
          break
          case 'Z1001':
          this.$Notice.error({
              title: '请求失败',
              desc: '系统发生异常,请稍后再次尝试'
          })
          break
          case 'Z1002':
          this.$Notice.error({
              title: '请求失败',
              desc: '系统发生异常,请稍后再次尝试'
          })
          break
          case 'Z1004':
          this.$Notice.error({
              title: '请求失败',
              desc: '认证失败,请稍后再次尝试'
          })
          break
          case 'Z1020':
          this.$Notice.error({
              title: '请求失败',
              desc: '添加的目标无法解析,请重新输入'
          })
          break
          default:
          break
        }
      })
    },
    show (params) {
      this.$router.push({
        name:'漏洞详情',
        query:{
          params : params['row']['target']
        }
      })
    },
    scan_set (params) {
      this.$router.push({
        name:'扫描设置',
        query:{
          params : params['row']['target']
        }
      })
    },
    remove (params) {
      let flag = {
        'type': 'target',
        'data': '1'
      }
      let data = {
        'target': params.row.target,
        'flag': flag,
        'token': this.token.trim()
      }
      data = JSON.stringify(data)
      let req_params = {'data': RSA.Encrypt(data)}
      http.post('/api/setflag', req_params).then((res) => {
        res.data = eval('(' + res.data + ')')
        switch(res.data.code ){
          case'Z1000':
          this.reload()
          break
          case 'Z1001':
          this.$Notice.error({
              title: '请求失败',
              desc: '系统发生异常,请稍后再次尝试'
          })
          break
          case 'Z1002':
          this.$Notice.error({
              title: '请求失败',
              desc: '系统发生异常,请稍后再次尝试'
          })
          break
          case 'Z1004':
          this.$Notice.error({
              title: '请求失败',
              desc: '认证失败,请稍后再次尝试'
          })
          break
          default:
          break
        }
      })
    },
    handlePage (pageNum) {
      this.page.pageNum = pageNum
      this.getTableData()
    },
    handlePageSize (pageSize) {
      this.page.pageSize = pageSize
      this.getTableData()
    }
  },
  mounted () {
    this.getTableData()
  },
}
</script>

<style>
 .page{
    border-radius: 100px;
    padding: 10px;
    text-align:center;
    margin-top: 10px;
    margin-left: auto;
    margin-right: auto;
  }
</style>
