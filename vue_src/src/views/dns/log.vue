<style lang="scss" scoped>
  @import '@/styles/dnslog.scss';
</style>

<template>
  <div class="app-container">
    <div class="filter-container">
      <el-input v-model="listQuery.dns_log" placeholder="日志关键字" class="header" @keyup.enter.native="handleFilter" />
      <el-input v-model="listQuery.ip" placeholder="ip关键字" class="header" @keyup.enter.native="handleFilter" />
      <el-button v-waves class="button" type="primary" icon="el-icon-search" @click="handleFilter">
        搜索
      </el-button>
      <el-tag class="tag">当前域名: {{ domain }}</el-tag>
      <el-button v-waves class="button" type="primary" @click="handleDomain">
        重新生成域名
      </el-button>
    </div>

    <el-table
      :key="tableKey"
      v-loading="listLoading"
      :data="list"
      border
      fit
      highlight-current-row
      style="width: 100%;"
    >
      <el-table-column label="ID" sortable align="center" prop="id" width="100">
        <template slot-scope="{row}">
          <span>{{ row.id }}</span>
        </template>
      </el-table-column>
      <el-table-column label="DNS Log" sortable prop="dns_log" align="center">
        <template slot-scope="{row}">
          <span>{{ row.dns_log }}</span>
        </template>
      </el-table-column>
      <el-table-column label="IP" sortable prop="ip" align="center">
        <template slot-scope="{row}">
          <span>{{ row.ip }}</span>
        </template>
      </el-table-column>
      <el-table-column label="接收时间" sortable prop="time" align="center">
        <template slot-scope="{row}">
          <span>{{ row.time | parseTime('{y}-{m}-{d} {h}:{i}') }}</span>
        </template>
      </el-table-column>
      <el-table-column label="操作" align="center" width="300" class-name="small-padding fixed-width">
        <template slot-scope="{row}">
          <el-button size="mini" type="danger" icon="el-icon-error" @click="handleDelete(row)">
            删除
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <pagination v-show="page.total>=0" :total="page.total" :page.sync="page.pageNum" :limit.sync="page.pageSize" @pagination="getList" />
  </div>
</template>

<script>
import { Encrypt } from '@/utils/rsa'
import { getToken } from '@/utils/auth'
import { dnslogList, deletednsLog, generateDomain } from '@/api/dns'

import waves from '@/directive/waves' // waves directive
import Pagination from '@/components/Pagination' // secondary package based on el-pagination

export default {
  name: 'DnsLog',
  components: { Pagination },
  directives: { waves },
  data() {
    return {
      tableKey: 0,
      domain: '',
      list: null,
      total: 0,
      query: false,
      listLoading: true,
      page: {
        pageNum: 1,
        pageSize: 10,
        total: 10
      },
      listQuery: {
        dns_log: '',
        ip: ''
      }
    }
  },
  created() {
    this.getList()
  },
  methods: {
    getList() {
      this.listLoading = true
      let data = {
        'pagenum': this.page.pageNum,
        'pagesize': this.page.pageSize,
        'token': getToken(),
        'listQuery': JSON.stringify(this.listQuery)
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      dnslogList(params).then(response => {
        if (response.data === '') {
          this.list = []
          this.page.total = 0
        } else {
          this.list = response.data.result
          this.page.total = response.data.total
        }
        this.domain = response.domain
        console.log(this.domain)
        setTimeout(() => {
          this.listLoading = false
        }, 0.5 * 1000)
      })
    },
    handleFilter() {
      this.page.pageNum = 1
      this.getList()
    },
    handleDelete(row) {
      let data = {
        'id': row.id,
        'token': getToken()
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      deletednsLog(params).then(() => {
        this.getList()
        this.$notify({
          message: '日志删除成功!',
          type: 'success',
          center: true,
          duration: 3 * 1000
        })
      })
    },
    handleDomain() {
      let data = {
        'token': getToken()
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      generateDomain(params).then(response => {
        this.domain = response.data
        this.getList()
        this.$notify({
          message: '重新获取域名成功!',
          type: 'success',
          center: true,
          duration: 3 * 1000
        })
      })
    }
  }
}
</script>
