<style lang="scss" scoped>
  @import '@/styles/poc.scss';
</style>

<template>
  <div class="app-container">
    <div class="filter-container">
      <el-input v-model="listQuery.poc_name" placeholder="POC名字关键字" class="header" @keyup.enter.native="handleFilter" />
      <el-input v-model="listQuery.poc_description" placeholder="POC描述关键字" class="header" @keyup.enter.native="handleFilter" />
      <el-input v-model="listQuery.type" placeholder="POC类型关键字" class="header" @keyup.enter.native="handleFilter" />
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
      <el-table-column label="ID" sortable align="center" prop="id" width="100">
        <template slot-scope="{row}">
          <span>{{ row.id }}</span>
        </template>
      </el-table-column>
      <el-table-column label="漏洞名字" sortable prop="poc_name" align="center">
        <template slot-scope="{row}">
          <span>{{ row.poc_name }}</span>
        </template>
      </el-table-column>
      <el-table-column label="漏洞描述" sortable prop="poc_description" align="center">
        <template slot-scope="{row}">
          <span>{{ row.poc_description }}</span>
        </template>
      </el-table-column>
      <el-table-column label="漏洞日期" sortable prop="time" align="center">
        <template slot-scope="{row}">
          <span>{{ row.time | parseTime('{y}-{m}-{d} {h}:{i}') }}</span>
        </template>
      </el-table-column>
      <el-table-column label="漏洞类型" sortable prop="type" align="center">
        <template slot-scope="{row}">
          <span>{{ row.type }}</span>
        </template>
      </el-table-column>
    </el-table>

    <pagination v-show="page.total>=0" :total="page.total" :page.sync="page.pageNum" :limit.sync="page.pageSize" @pagination="getList" />
  </div>
</template>

<script>
import { pocList } from '@/api/poc'
import { Encrypt } from '@/utils/rsa'
import { getToken } from '@/utils/auth'
import waves from '@/directive/waves' // waves directive
import Pagination from '@/components/Pagination' // secondary package based on el-pagination

export default {
  name: 'PocManager',
  components: { Pagination },
  directives: { waves },
  data() {
    return {
      tableKey: 0,
      list: null,
      total: 0,
      listLoading: true,
      listQuery: {
        poc_name: '',
        poc_description: '',
        type: ''
      },
      page: {
        pageNum: 1,
        pageSize: 10,
        total: 10
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
      data = JSON.stringify(data)
      pocList(params).then(response => {
        this.list = response.data
        this.page.total = response.total
        setTimeout(() => {
          this.listLoading = false
        }, 0.5 * 1000)
      })
    },
    handleFilter() {
      this.page.pageNum = 1
      this.getList()
    }
  }
}
</script>
