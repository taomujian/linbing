<style lang="scss" scoped>
  @import '@/styles/account.scss';
</style>

<template>
  <div class="app-container">
    <div class="filter-container">
      <el-input v-model="listQuery.username" placeholder="用户关键字" class="header" @keyup.enter.native="handleFilter" />
      <el-input v-model="listQuery.description" placeholder="描述关键字" class="header" @keyup.enter.native="handleFilter" />
      <el-select v-model="listQuery.role" placeholder="权限" clearable class="header">
        <el-option v-for="item in roleOptions" :key="item" :label="item" :value="item" />
      </el-select>
      <el-button v-waves class="button" type="primary" icon="el-icon-search" @click="handleFilter">
        搜索
      </el-button>
      <el-button class="button" type="primary" icon="el-icon-edit" @click="handleCreate">
        添加用户
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
      <el-table-column label="username" sortable prop="username" align="center">
        <template slot-scope="{row}">
          <span>{{ row.username }}</span>
        </template>
      </el-table-column>
      <el-table-column label="描述" sortable prop="description" align="center">
        <template slot-scope="{row}">
          <span class="link-type" @click="handleEditDescription(row)">{{ row.description }}</span>
        </template>
      </el-table-column>
      <el-table-column label="权限" sortable prop="role" class-name="status-col">
        <template slot-scope="{row}">
          <el-tag effect="dark" :type="row.role | statusFilter">
            {{ row.role }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="创建时间" sortable prop="create_time" align="center">
        <template slot-scope="{row}">
          <span>{{ row.create_time | parseTime('{y}-{m}-{d} {h}:{i}') }}</span>
        </template>
      </el-table-column>
      <el-table-column label="操作" align="center" width="300" class-name="small-padding fixed-width">
        <template slot-scope="{row}">
          <el-button type="primary" size="mini" icon="el-icon-edit" @click="handleEditPassword(row)">
            修改密码
          </el-button>
          <el-button type="primary" size="mini" icon="el-icon-edit" @click="handleEditRole(row)">
            修改权限
          </el-button>
          <el-button size="mini" type="danger" icon="el-icon-error" @click="handleDelete(row)">
            删除
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <pagination v-show="page.total>=0" :total="page.total" :page.sync="page.pageNum" :limit.sync="page.pageSize" @pagination="getList" />

    <el-dialog :title="textMap[dialogStatus]" :visible.sync="editFormVisible">
      <el-form ref="dataForm" :rules="rules" :model="editTemp" label-position="left" label-width="70px" style="width: 400px; margin-left:50px;">
        <div v-if="dialogStatus === 'password'">
          <el-form-item label="密码" prop="password">
            <el-input v-model="editTemp.password" :autosize="{ minRows: 2, maxRows: 4}" placeholder="请输入密码..." />
          </el-form-item>
        </div>
        <div v-if="dialogStatus === 'description'">
          <el-form-item label="description" prop="description">
            <el-input v-model="editTemp.description" :autosize="{ minRows: 2, maxRows: 4}" placeholder="请输入描述..." />
          </el-form-item>
        </div>
        <div v-if="dialogStatus === 'role'">
          <el-form-item label="权限">
            <el-select v-model="editTemp.role" filterable clearable placeholder="请选择权限">
              <el-option
                v-for="item in roles"
                :key="item.value"
                :label="item.label"
                :value="item.value"
              />
            </el-select>
          </el-form-item>
        </div>
      </el-form>
      <div slot="footer" class="dialog-footer">
        <el-button @click="editFormVisible = false">
          取消
        </el-button>
        <el-button type="primary" @click="handleEdit()">
          确认
        </el-button>
      </div>
    </el-dialog>
    <el-dialog :title="accountTitle" :visible.sync="accountFormVisible">
      <el-form ref="dataForm" :rules="rules" :model="accountTemp" label-position="left" label-width="100px" style="width: 400px; margin-left:50px;">
        <el-form-item label="用户名" prop="username">
          <el-input v-model="accountTemp.username" :autosize="{ minRows: 2, maxRows: 4}" placeholder="请输入用户名..." @keyup.enter.native="handleQuery" @blur="handleQuery" />
        </el-form-item>
        <el-form-item label="description" prop="description">
          <el-input v-model="accountTemp.description" :autosize="{ minRows: 2, maxRows: 4}" placeholder="请输入描述..." />
        </el-form-item>
        <el-form-item label="密码" prop="password">
          <el-input v-model="accountTemp.password" :autosize="{ minRows: 2, maxRows: 4}" placeholder="请输入密码..." />
        </el-form-item>
        <el-form-item label="设置权限" prop="role">
          <el-select v-model="accountTemp.role" filterable clearable placeholder="请选择权限" style="width: 300px">
            <el-option
              v-for="item in roles"
              :key="item.value"
              :label="item.label"
              :value="item.value"
            />
          </el-select>
        </el-form-item>
      </el-form>
      <div slot="footer" class="dialog-footer">
        <el-button @click="accountFormVisible = false">
          取消
        </el-button>
        <el-button type="primary" @click="createData()">
          确认
        </el-button>
      </div>
    </el-dialog>
  </div>
</template>

<script>
import { Encrypt } from '@/utils/rsa'
import { getToken } from '@/utils/auth'
import waves from '@/directive/waves' // waves directive
import Pagination from '@/components/Pagination' // secondary package based on el-pagination
import { validPassword } from '@/utils/validate'
import { accountList, accountAdd, deleteAccount, queryAccount, accountRole, accountPassword, accountDescription } from '@/api/account'

export default {
  name: 'AccountList',
  components: { Pagination },
  directives: { waves },
  filters: {
    statusFilter(status) {
      const statusMap = {
        admin: 'info',
        管理员: '',
        普通用户: 'success'
      }
      return statusMap[status]
    }
  },
  data() {
    var validpass = (rule, value, callback) => {
      if (!validPassword(value)) {
        return callback(new Error('密码必须由数字、字母、特殊字符组合,长度在8-16位之间'))
      } else {
        callback()
      }
    }
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
        username: '',
        description: '',
        role: ''
      },
      roleOptions: ['全部', 'admin', '管理员', '普通用户'],
      editTemp: {
        username: '',
        description: '',
        password: '',
        role: ''
      },
      accountTemp: {
        username: '',
        description: '',
        password: '',
        role: ''
      },
      roles: [{
        value: '管理员',
        label: '管理员'
      }, {
        value: '普通用户',
        label: '普通用户'
      }],
      editFormVisible: false,
      accountFormVisible: false,
      dialogStatus: '',
      accountTitle: '新建用户',
      textMap: {
        role: '权限',
        password: '密码'
      },
      rules: {
        username: [{ required: true, message: '请输入用户名,长度为1~10位', trigger: 'change', min: 1, max: 10 }],
        description: [{ required: true, message: '请输入描述,长度为1~50位', trigger: 'change', min: 1, max: 50 }],
        password: [{ required: true, trigger: 'change', validator: validpass }],
        role: [{ required: true, trigger: 'change' }]
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
      accountList(params).then(response => {
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
    resetAccountemp() {
      this.accountTemp = {
        username: '',
        description: '',
        password: '',
        role: ''
      }
    },
    handleCreate() {
      this.resetAccountemp()
      this.accountFormVisible = true
      this.$nextTick(() => {
        this.$refs['dataForm'].clearValidate()
      })
    },
    handleQuery() {
      let data = {
        'username': this.accountTemp.username.trim(),
        'token': getToken()
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      queryAccount(params).then(response => {
        if (response.code === 'L1000') {
          this.query = true
        }
      })
    },
    createData() {
      this.$refs['dataForm'].validate((valid) => {
        if (valid) {
          if (this.query === true) {
            let data = {
              'username': this.accountTemp.username.trim(),
              'description': this.accountTemp.description.trim(),
              'password': this.accountTemp.password.trim(),
              'role': this.accountTemp.role.trim(),
              'token': getToken()
            }
            data = JSON.stringify(data)
            const params = { 'data': Encrypt(data) }
            accountAdd(params).then(() => {
              this.list.unshift(this.accountTemp)
              this.accountFormVisible = false
              this.getList()
              this.query = false
              this.$notify({
                message: '用户添加成功!',
                type: 'success',
                center: true,
                duration: 3 * 1000
              })
            })
          }
        }
      })
    },
    handleEditPassword(row) {
      if (row.username === 'admin') {
        this.$notify({
          message: '系统内置管理员,不可删除,不可修改!',
          type: 'error',
          center: true,
          duration: 3 * 1000
        })
      } else {
        this.editTemp = Object.assign({}, row) // copy obj
        this.editFormVisible = true
        this.dialogStatus = 'password'
        this.editTemp.username = row.username
        this.$nextTick(() => {
          this.$refs['dataForm'].clearValidate()
        })
      }
    },
    handleEditRole(row) {
      if (row.username === 'admin') {
        this.$notify({
          message: '系统内置管理员,不可删除,不可修改!',
          type: 'error',
          center: true,
          duration: 3 * 1000
        })
      } else {
        this.editTemp = Object.assign({}, row) // copy obj
        this.editFormVisible = true
        this.dialogStatus = 'role'
        this.editTemp.username = row.username
        this.$nextTick(() => {
          this.$refs['dataForm'].clearValidate()
        })
      }
    },
    handleEditDescription(row) {
      this.editTemp = Object.assign({}, row) // copy obj
      this.editFormVisible = true
      this.dialogStatus = 'description'
      this.editTemp.username = row.username
      this.$nextTick(() => {
        this.$refs['dataForm'].clearValidate()
      })
    },
    handleEdit() {
      if (this.dialogStatus === 'password') {
        let data = {
          'username': this.editTemp.username.trim(),
          'password': this.editTemp.password.trim(),
          'token': getToken()
        }
        data = JSON.stringify(data)
        const params = { 'data': Encrypt(data) }
        accountPassword(params).then(() => {
          this.list.unshift(this.editTemp)
          this.editFormVisible = false
          this.$notify({
            message: '用户密码更新成功!',
            type: 'success',
            center: true,
            duration: 3 * 1000
          })
          this.getList()
        })
      } else if (this.dialogStatus === 'role') {
        let data = {
          'username': this.editTemp.username.trim(),
          'role': this.editTemp.role.trim(),
          'token': getToken()
        }
        data = JSON.stringify(data)
        const params = { 'data': Encrypt(data) }
        accountRole(params).then(() => {
          this.list.unshift(this.editTemp)
          this.editFormVisible = false
          this.getList()
          this.$notify({
            message: '用户权限更新成功!',
            type: 'success',
            center: true,
            duration: 3 * 1000
          })
          this.getList()
        })
      } else if (this.dialogStatus === 'description') {
        let data = {
          'username': this.editTemp.username.trim(),
          'description': this.editTemp.description.trim(),
          'token': getToken()
        }
        data = JSON.stringify(data)
        const params = { 'data': Encrypt(data) }
        accountDescription(params).then(() => {
          this.list.unshift(this.editTemp)
          this.editFormVisible = false
          this.getList()
          this.$notify({
            message: '用户描述更新成功!',
            type: 'success',
            center: true,
            duration: 3 * 1000
          })
          this.getList()
        })
      }
    },
    handleDelete(row) {
      if (row.username === 'admin') {
        this.$notify({
          message: '系统内置管理员,不可删除,不可修改!',
          type: 'error',
          center: true,
          duration: 3 * 1000
        })
      } else {
        let data = {
          'username': row.username,
          'token': getToken()
        }
        data = JSON.stringify(data)
        const params = { 'data': Encrypt(data) }
        deleteAccount(params).then(() => {
          this.getList()
          this.$notify({
            message: '用户删除成功!',
            type: 'success',
            center: true,
            duration: 3 * 1000
          })
          this.getList()
        })
      }
    }
  }
}
</script>
