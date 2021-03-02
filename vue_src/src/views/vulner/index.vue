<style lang="scss" scoped>
  @import '@/styles/vulner.scss';
</style>

<template>
  <div class="app-container">
    <div class="filter-container">
      <el-input v-model="listQuery.target" placeholder="目标关键字" class="header" @keyup.enter.native="handleFilter" />
      <el-input v-model="listQuery.ip_port" placeholder="IP和端口关键字" class="header" @keyup.enter.native="handleFilter" />
      <el-input v-model="listQuery.vulner_name" placeholder="漏洞关键字" class="header" @keyup.enter.native="handleFilter" />
      <el-input v-model="listQuery.vulner_descrip" placeholder="漏洞描述关键字" class="header" @keyup.enter.native="handleFilter" />
      <el-button v-waves class="button" type="primary" icon="el-icon-search" @click="handleFilter">
        搜索
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
      <el-table-column label="ID" sortable align="center" width="100">
        <template slot-scope="{row}">
          <span>{{ row.id }}</span>
        </template>
      </el-table-column>
      <el-table-column label="目标" sortable align="center">
        <template slot-scope="{row}">
          <span>{{ row.target }}</span>
        </template>
      </el-table-column>
      <el-table-column label="IP_PORT" sortable align="center">
        <template slot-scope="{row}">
          <span>{{ row.ip_port }}</span>
        </template>
      </el-table-column>
      <el-table-column label="漏洞名字" sortable align="center">
        <template slot-scope="{row}">
          <span>{{ row.vulner_name }}</span>
        </template>
      </el-table-column>
      <el-table-column label="漏洞描述" sortable align="center">
        <template slot-scope="{row}">
          <span>{{ row.vulner_descrip }}</span>
        </template>
      </el-table-column>
      <el-table-column label="扫描时间" sortable align="center">
        <template slot-scope="{row}">
          <span>{{ row.scan_time | parseTime('{y}-{m}-{d} {h}:{i}') }}</span>
        </template>
      </el-table-column>
      <el-table-column label="操作" align="center" class-name="small-padding fixed-width">
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
import { vulnerList, setVulner } from '@/api/vulner'
import { Encrypt } from '@/utils/rsa'
import { getToken } from '@/utils/auth'
import waves from '@/directive/waves' // waves directive
import Pagination from '@/components/Pagination' // secondary package based on el-pagination

export default {
  name: 'VulnerList',
  components: { Pagination },
  directives: { waves },
  data() {
    return {
      tableKey: 0,
      list: null,
      total: 0,
      listLoading: true,
      page: {
        pageNum: 1,
        pageSize: 10,
        total: 10
      },
      listQuery: {
        target: '',
        ip_port: '',
        vulner_name: '',
        vulner_descrip: ''
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
        'flag': '0',
        'token': getToken(),
        'listQuery': JSON.stringify(this.listQuery)
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      vulnerList(params).then(response => {
        if (response.data === '') {
          this.list = []
          this.page.total = 0
        } else {
          this.list = response.data.result
          this.page.total = response.data.total
        }
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
        'target': row.target,
        'ip_port': row.ip_port,
        'vulner_name': row.vulner_name,
        'flag': '1',
        'token': getToken()
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      setVulner(params).then(() => {
        this.getList()
        this.$notify({
          message: '漏洞删除成功!',
          type: 'success',
          center: true,
          duration: 3 * 1000
        })
      })
    }
  }
}
</script>
