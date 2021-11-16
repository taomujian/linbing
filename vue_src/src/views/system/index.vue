<style lang="scss" scoped>
  @import '@/styles/target.scss';
</style>

<template>
  <div class="app-container">
    <div class="filter-container" />

    <el-table
      :key="tableKey"
      v-loading="listLoading"
      :data="list"
      border
      fit
      highlight-current-row
      style="width: 100%;"
    >
      <el-table-column label="代理IP" sortable prop="proxy" align="center">
        <template slot-scope="{row}">
          <span>{{ row.proxy }}</span>
        </template>
      </el-table-column>
      <el-table-column label="扫描超时时间" sortable prop="timeout" align="center">
        <template slot-scope="{row}">
          <span>{{ row.timeout }}</span>
        </template>
      </el-table-column>
      <el-table-column label="操作" align="center" class-name="small-padding fixed-width">
        <template slot-scope="{row}">
          <el-button type="primary" size="mini" icon="el-icon-edit" @click="handleSet(row)">
            扫描设置
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <pagination v-show="page.total>=0" :total="page.total" :page.sync="page.pageNum" :limit.sync="page.pageSize" @pagination="getList" />

    <el-dialog :title="setTitle" :visible.sync="setFormVisible">
      <el-form ref="dataForm" :model="setTemp" label-position="left" label-width="100px" style="width: 400px; margin-left:50px;">
        <el-form-item label="代理类型">
          <el-select v-model="setTemp.proxytype" filterable clearable placeholder="请选择代理类型">
            <el-option
              v-for="item in proxytype"
              :key="item.value"
              :label="item.label"
              :value="item.value"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="代理地址">
          <el-input v-model="setTemp.proxyip" show-word-limit :autosize="{ minRows: 2, maxRows: 4}" placeholder="代理地址,比如127.0.0.1:8080" />
        </el-form-item>
        <el-form-item label="超时时间">
          <el-input v-model="setTemp.timeout" show-word-limit :autosize="{ minRows: 2, maxRows: 4}" placeholder="请输入超时时间,单位为秒" />
        </el-form-item>
      </el-form>
      <div slot="footer" class="dialog-footer">
        <el-button @click="setFormVisible = false">
          取消
        </el-button>
        <el-button type="primary" @click="ScanSet()">
          确认
        </el-button>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { systemList, systemSet } from '@/api/system'
import { Encrypt } from '@/utils/rsa'
import { getToken } from '@/utils/auth'
import waves from '@/directive/waves' // waves directive
import Pagination from '@/components/Pagination' // secondary package based on el-pagination

export default {
  name: 'SystemList',
  components: { Pagination },
  directives: { waves },
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
      proxytype: [{
        value: 'http',
        label: 'http'
      }, {
        value: 'socks4',
        label: 'socks4'
      }, {
        value: 'socks5',
        label: 'socks5'
      }],
      setTemp: {
        proxytype: '',
        proxyip: '',
        timeout: ''
      },
      setFormVisible: false,
      setTitle: '系统扫描设置'
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
      systemList(params).then(response => {
        if (response.data === '') {
          this.list = []
          this.page.total = 0
        } else {
          this.list = response.data
          this.page.total = response.total
        }
        setTimeout(() => {
          this.listLoading = false
        }, 0.5 * 1000)
      })
    },
    resetSetTemp() {
      this.setTemp = {
        proxytype: '',
        proxyip: '',
        timeout: ''
      }
    },
    handleSet(row) {
      this.resetSetTemp()
      this.setFormVisible = true
      this.$nextTick(() => {
        this.$refs['dataForm'].clearValidate()
      })
    },
    ScanSet() {
      this.$refs['dataForm'].validate((valid) => {
        if (valid) {
          let data = {
            'proxytype': this.setTemp.proxytype,
            'proxyip': this.setTemp.proxyip,
            'timeout': this.setTemp.timeout,
            'token': getToken()
          }
          data = JSON.stringify(data)
          const params = { 'data': Encrypt(data) }
          systemSet(params).then(() => {
            this.setFormVisible = false
            this.getList()
            this.$notify({
              message: '扫描设置成功!',
              type: 'success',
              center: true,
              duration: 3 * 1000
            })
          })
        }
      })
    }
  }
}
</script>
