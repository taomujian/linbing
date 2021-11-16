<style lang="scss" scoped>
  @import '@/styles/xssauth.scss';
</style>

<template>
  <div class="app-container">
    <div class="filter-container">
      <el-input v-model="listQuery.token" placeholder="token关键字" class="header" @keyup.enter.native="handleFilter" />
      <el-input v-model="listQuery.url" placeholder="url关键字" class="header" @keyup.enter.native="handleFilter" />
      <el-select v-model="listQuery.token_status" placeholder="扫描状态" clearable class="header">
        <el-option v-for="item in statusOptions" :key="item" :label="item" :value="item" />
      </el-select>
      <el-button v-waves class="button" type="primary" icon="el-icon-search" @click="handleFilter">
        搜索
      </el-button>
      <el-button class="button" type="primary" icon="el-icon-edit" @click="handleCreate">
        生成token
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
      <el-table-column label="token" sortable prop="token" width="200px" align="center">
        <template slot-scope="{row}">
          <span>{{ row.token }}</span>
        </template>
      </el-table-column>
      <el-table-column label="url" sortable prop="url" align="center">
        <template slot-scope="{row}">
          <span>{{ row.url }}</span>
        </template>
      </el-table-column>
      <el-table-column label="状态" sortable prop="token_status" class-name="status-col">
        <template slot-scope="{row}">
          <el-tag effect="dark" :type="row.token_status | statusFilter">
            {{ row.token_status }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="操作" align="center" width="300" class-name="small-padding fixed-width">
        <template slot-scope="{row}">
          <el-button size="mini" type="warning" icon="el-icon-warning" @click="handleUpdate(row, '失效')">
            弃用
          </el-button>
          <el-button size="mini" type="success" icon="el-icon-success" @click="handleUpdate(row, '生效')">
            恢复
          </el-button>
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
import { authList, generateAuth, updateAuth, deleteAuth } from '@/api/xss'
import { Encrypt } from '@/utils/rsa'
import { getToken } from '@/utils/auth'
import waves from '@/directive/waves' // waves directive
import Pagination from '@/components/Pagination' // secondary package based on el-pagination

export default {
  name: 'XssAuth',
  components: { Pagination },
  directives: { waves },
  filters: {
    statusFilter(status) {
      const statusMap = {
        生效: 'success',
        失效: 'danger'
      }
      return statusMap[status]
    }
  },
  data() {
    return {
      tableKey: 0,
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
        token: '',
        url: '',
        token_status: ''
      },
      statusOptions: ['生效', '失效']
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
      authList(params).then(response => {
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
    handleCreate() {
      this.listLoading = true
      let data = {
        'token': getToken()
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      generateAuth(params).then(response => {
        this.getList()
      })
    },
    handleUpdate(row, status) {
      let data = {
        'xss_token': row.token,
        'token_status': status,
        'token': getToken()
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      updateAuth(params).then(() => {
        this.getList()
        this.$notify({
          message: 'token弃用成功,token已失效!',
          type: 'success',
          center: true,
          duration: 3 * 1000
        })
      })
    },
    handleDelete(row) {
      let data = {
        'xss_token': row.token,
        'token': getToken()
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      deleteAuth(params).then(() => {
        this.getList()
        this.$notify({
          message: 'token删除成功!',
          type: 'success',
          center: true,
          duration: 3 * 1000
        })
      })
    }
  }
}
</script>
