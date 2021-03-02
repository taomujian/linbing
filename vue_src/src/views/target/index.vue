<style lang="scss" scoped>
  @import '@/styles/target.scss';
</style>

<template>
  <div class="app-container">
    <div class="filter-container">
      <el-input v-model="listQuery.target" placeholder="目标关键字" class="header" @keyup.enter.native="handleFilter" />
      <el-input v-model="listQuery.description" placeholder="描述关键字" class="header" @keyup.enter.native="handleFilter" />
      <el-select v-model="listQuery.scan_status" placeholder="扫描状态" clearable class="header">
        <el-option v-for="item in statusOptions" :key="item" :label="item" :value="item" />
      </el-select>
      <el-select v-model="listQuery.scan_schedule" placeholder="扫描进度" clearable class="header">
        <el-option v-for="item in scheduleOptions" :key="item" :label="item" :value="item" />
      </el-select>
      <el-button v-waves class="button" type="primary" icon="el-icon-search" @click="handleFilter">
        搜索
      </el-button>
      <el-button class="button" type="primary" icon="el-icon-edit" @click="handleCreate">
        添加目标
      </el-button>
      <el-button class="button-long" type="primary" icon="el-icon-video-play" @click="handleScanAll">
        扫描所有未开始目标
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
      <el-table-column label="目标" sortable width="200px" align="center">
        <template slot-scope="{row}">
          <div v-if="isurl(row.target) === true">
            <span class="link-type" @click="handleDetail(row)">{{ row.target }}</span>
          </div>
          <div v-else>
            <span>{{ row.target }}</span>
          </div>
        </template>
      </el-table-column>
      <el-table-column label="描述" sortable align="center">
        <template slot-scope="{row}">
          <span class="link-type" @click="handleUpdate(row)">{{ row.description }}</span>
        </template>
      </el-table-column>
      <el-table-column label="创建时间" sortable align="center">
        <template slot-scope="{row}">
          <span>{{ row.create_time | parseTime('{y}-{m}-{d} {h}:{i}') }}</span>
        </template>
      </el-table-column>
      <el-table-column label="扫描状态" sortable class-name="status-col">
        <template slot-scope="{row}">
          <el-tag effect="dark" :type="row.scan_status | statusFilter">
            {{ row.scan_status }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="扫描进度" sortable align="center">
        <template slot-scope="{row}">
          <el-tag effect="dark" :type="row.scan_schedule | statusFilter">
            {{ row.scan_schedule }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="漏洞数量" sortable align="center">
        <template slot-scope="{row}">
          <span>{{ row.vulner_number }}</span>
        </template>
      </el-table-column>
      <el-table-column label="操作" align="center" width="300" class-name="small-padding fixed-width">
        <template slot-scope="{row}">
          <el-button type="primary" size="mini" icon="el-icon-video-play" @click="handleScan(row)">
            开始扫描
          </el-button>
          <el-button type="primary" size="mini" icon="el-icon-edit" @click="handleScanSet(row)">
            扫描设置
          </el-button>
          <el-button size="mini" type="danger" icon="el-icon-error" @click="handleDelete(row)">
            删除
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <pagination v-show="page.total>=0" :total="page.total" :page.sync="page.pageNum" :limit.sync="page.pageSize" @pagination="getList" />

    <el-dialog :title="textMap[dialogStatus]" :visible.sync="editFormVisible">
      <el-form ref="dataForm" :rules="rules" :model="targetTemp" label-position="left" label-width="70px" style="width: 400px; margin-left:50px;">
        <el-form-item label="目标" prop="target">
          <div v-if="dialogStatus === 'update'">
            <el-input v-model="targetTemp.target" :autosize="{ minRows: 2, maxRows: 4}" :disabled="true" type="textarea" placeholder="请输入目标,多个目标时以每行一个目标为格式输入,格式可以是url,ip,域名,网段..." @keyup.enter.native="handleQuery" />
          </div>
          <div v-if="dialogStatus === 'create'">
            <el-input v-model="targetTemp.target" :autosize="{ minRows: 2, maxRows: 4}" type="textarea" placeholder="请输入目标,多个目标时以每行一个目标为格式输入,格式是url,ip,域名,网段..." @keyup.enter.native="handleQuery" @blur="handleQuery" />
          </div>
        </el-form-item>
        <el-form-item label="描述" prop="description">
          <el-input v-model="targetTemp.description" maxlength="50" show-word-limit :autosize="{ minRows: 2, maxRows: 4}" type="textarea" placeholder="请输入描述..." />
        </el-form-item>
      </el-form>
      <div slot="footer" class="dialog-footer">
        <el-button @click="editFormVisible = false">
          取消
        </el-button>
        <el-button type="primary" @click="dialogStatus==='create'?createData():updateData()">
          确认
        </el-button>
      </div>
    </el-dialog>
    <el-dialog :title="scanTitle" :visible.sync="scanFormVisible">
      <el-form ref="dataForm" :rules="rules" :model="scanTemp" label-position="left" label-width="100px" style="width: 400px; margin-left:50px;">
        <el-form-item label="端口扫描器">
          <el-select v-model="scanTemp.scanner" filterable clearable placeholder="默认为nmap">
            <el-option
              v-for="item in scanner"
              :key="item.value"
              :label="item.label"
              :value="item.value"
            />
          </el-select>
        </el-form-item>
        <div v-if="scanTemp.scanner === 'masscan'">
          <el-form-item label="扫描速率">
            <el-input-number v-model="scanTemp.rate" label="默认为5000" />
          </el-form-item>
        </div>
        <el-form-item label="最小端口">
          <el-input-number v-model="scanTemp.min_port" :min="1" :max="65535" label="最小为1" />
        </el-form-item>
        <el-form-item label="最大端口">
          <el-input-number v-model="scanTemp.max_port" :min="1" :max="65535" label="最大为65535" />
        </el-form-item>
        <el-form-item label="POC并发量">
          <el-input-number v-model="scanTemp.concurren_number" :min="1" :max="200" label="默认为50,最高200" />
        </el-form-item>
      </el-form>
      <div slot="footer" class="dialog-footer">
        <el-button @click="scanFormVisible = false">
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
import { scanSet, startScan } from '@/api/scan'
import { newTarget, queryTarget, editTarget, setTarget, targetList } from '@/api/target'
import { Encrypt } from '@/utils/rsa'
import { getToken } from '@/utils/auth'
import waves from '@/directive/waves' // waves directive
import Pagination from '@/components/Pagination' // secondary package based on el-pagination

export default {
  name: 'TargetList',
  components: { Pagination },
  directives: { waves },
  filters: {
    statusFilter(status) {
      const statusMap = {
        未开始: 'info',
        扫描结束: 'success',
        扫描中: '',
        子域名扫描中: '',
        端口扫描中: '',
        目录扫描中: '',
        POC扫描中: '',
        扫描失败: 'danger'
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
        target: '',
        description: '',
        scan_status: '',
        scan_schedule: ''
      },
      statusOptions: ['全部', '未开始', '扫描中', '扫描结束', '扫描失败'],
      scheduleOptions: ['全部', '未开始', '子域名扫描中', '端口扫描中', '目录扫描中', 'POC扫描中', '扫描结束', '扫描失败'],
      targetTemp: {
        target: '',
        description: ''
      },
      scanTarget: '',
      scanner: [{
        value: 'nmap',
        label: 'nmap'
      }, {
        value: 'masscan',
        label: 'masscan'
      }],
      scanTemp: {
        scanner: 'nmap',
        min_port: '1',
        max_port: '65535',
        rate: '5000',
        concurren_number: '50'
      },
      editFormVisible: false,
      scanFormVisible: false,
      dialogStatus: '',
      scanTitle: '目标扫描设置',
      textMap: {
        update: '编辑',
        create: '新建'
      },
      rules: {
        target: [{ required: true, message: '请输入目标', trigger: 'change' }],
        description: [{ required: false, message: '请输入目标描述', trigger: 'change' }]
      }
    }
  },
  created() {
    this.getList()
  },
  methods: {
    isurl(value) {
      const ip_reg = /^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$/
      const domain_reg = /^(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$/
      if (value.startsWith('http://') === true) {
        return true
      } else if (value.startsWith('https://') === true) {
        return true
      } else if (ip_reg.test(value)) {
        return false
      } else if (domain_reg.test(value)) {
        return true
      }
      return false
    },
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
      targetList(params).then(response => {
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
    resetTargetTemp() {
      this.targetTemp = {
        target: '',
        description: ''
      }
    },
    resetScanTemp() {
      this.scanTemp = {
        scanner: 'nmap',
        min_port: '1',
        max_port: '65535',
        rate: '5000',
        concurren_number: '50'
      }
    },
    handleCreate() {
      this.resetTargetTemp()
      this.dialogStatus = 'create'
      this.editFormVisible = true
      this.$nextTick(() => {
        this.$refs['dataForm'].clearValidate()
      })
    },
    handleQuery() {
      let data = {
        'target': this.targetTemp.target.trim().split(/[(\r\n)\r\n]+/).join(';'),
        'token': getToken()
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      queryTarget(params).then(() => {
        this.query = true
      })
    },
    createData() {
      this.$refs['dataForm'].validate((valid) => {
        if (valid) {
          if (this.query === true) {
            let data = {
              'target': this.targetTemp.target.trim().split(/[(\r\n)\r\n]+/).join(';'),
              'description': this.targetTemp.description.trim(),
              'token': getToken()
            }
            data = JSON.stringify(data)
            const params = { 'data': Encrypt(data) }
            newTarget(params).then(() => {
              this.list.unshift(this.targetTemp)
              this.editFormVisible = false
              this.getList()
              this.query = false
              this.$notify({
                message: '目标添加成功!',
                type: 'success',
                center: true,
                duration: 3 * 1000
              })
            })
          }
        }
      })
    },
    handleUpdate(row) {
      this.targetTemp = Object.assign({}, row) // copy obj
      this.dialogStatus = 'update'
      this.editFormVisible = true
      this.$nextTick(() => {
        this.$refs['dataForm'].clearValidate()
      })
    },
    updateData() {
      this.$refs['dataForm'].validate((valid) => {
        if (valid) {
          let data = {
            'target': this.targetTemp.target.trim(),
            'description': this.targetTemp.description.trim(),
            'token': getToken()
          }
          data = JSON.stringify(data)
          const params = { 'data': Encrypt(data) }
          editTarget(params).then(() => {
            this.list.unshift(this.targetTemp)
            this.editFormVisible = false
            this.getList()
            this.$notify({
              message: '描述更新成功!',
              type: 'success',
              center: true,
              duration: 3 * 1000
            })
          })
        }
      })
    },
    handleDelete(row) {
      let data = {
        'target': row.target,
        'flag': '1',
        'token': getToken()
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      setTarget(params).then(() => {
        this.getList()
        this.$notify({
          message: '目标删除成功!',
          type: 'success',
          center: true,
          duration: 3 * 1000
        })
      })
    },
    handleScan(row) {
      let data = {
        'target': row.target,
        'description': row.description,
        'token': getToken()
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      startScan(params).then(() => {
        this.$notify({
          message: '已开始扫描!',
          type: 'success',
          center: true,
          duration: 3 * 1000
        })
      })
    },
    handleDetail(row) {
      this.$router.push({
        name: 'TargetDetail',
        query: {
          params: row['target']
        }
      })
    },
    handleScanAll() {
      let data = {
        'target': 'all',
        'token': getToken()
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      startScan(params).then(() => {
        this.$notify({
          message: '已开始扫描',
          type: 'success',
          center: true,
          duration: 3 * 1000
        })
      })
    },
    handleScanSet(row) {
      this.resetScanTemp()
      this.scanFormVisible = true
      this.scanTarget = row.target
      this.$nextTick(() => {
        this.$refs['dataForm'].clearValidate()
      })
    },
    ScanSet() {
      this.$refs['dataForm'].validate((valid) => {
        if (valid) {
          let data = {
            'target': this.scanTarget,
            'scan_data': JSON.stringify(this.scanTemp),
            'token': getToken()
          }
          data = JSON.stringify(data)
          const params = { 'data': Encrypt(data) }
          scanSet(params).then(() => {
            this.scanFormVisible = false
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
