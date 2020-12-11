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
          width: 160
        },
        {
          title: '描述',
          key: 'description',
          sortable: true,
          resizable: true,
          width: 240
        },
        {
          title: '时间',
          key: 'time',
          sortable: true,
          resizable: true,
          width: 160
        },
        { 
          title: 'IP:PORT', 
          key: 'ip_port',
          resizable: true,
          width: 160
        },
        {
          title: '漏洞名称',
          key: 'vulner_name',
          resizable: true,
          width: 160
        },
        { 
          title: '漏洞描述',
          key: 'vulner_descrip',
          resizable: true,
          width: 160
        },
        {
        title: '操作',
        key: 'action',
        width: 310,
        resizable: true,
        align: 'center',
        render: (h, params) => {
          return h('div', [
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

  created() {
    // 在页面加载时读取sessionStorage里的状态信息
    if (sessionStorage.getItem('store')) {
      this.$store.replaceState(
        Object.assign(
          {},
          this.$store.state,
          JSON.parse(sessionStorage.getItem('store'))
        )
      )
    }
 
    // 在页面刷新时将vuex里的信息保存到sessionStorage里
    // beforeunload事件在页面刷新时先触发
    window.addEventListener('beforeunload', () => {
      sessionStorage.setItem('store', JSON.stringify(this.$store.state))
    })
  },
  
  methods: {
    getTableData () {
      let flag = {
        'type': 'vulner',
        'data': '0'
      }
      let data = {
        'pagenum': this.page.pageNum,
        'pagesize': this.page.pageSize,
        'flag': flag,
        'token': this.token.trim()
      }
      data = JSON.stringify(data)
      let params = {'data': RSA.Encrypt(data)}
      http.post('/api/vulnerlist', params).then((res) => {
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
    remove (params) {
      let flag = {
        'type': 'vulner',
        'data': '1',
        'id': params.row.id,
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
