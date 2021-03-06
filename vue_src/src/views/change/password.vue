<template>
  <div class="components-container">
    <el-form ref="passwordForm" :rules="rules" :model="passwordForm" label-position="left" label-width="20%" style="width: 60%; margin-left:-10%;">
      <el-form-item label="旧密码" prop="oldpassword">
        <el-input v-model="passwordForm.oldpassword" type="password" placeholder="请输入旧密码" @keyup.enter.native="handleQuery" />
      </el-form-item>
      <el-form-item label="新密码" prop="newpassword">
        <el-input v-model="passwordForm.newpassword" type="password" placeholder="请输入新密码..." />
      </el-form-item>
      <el-form-item label="再次输入" prop="repetpassword">
        <el-input v-model="passwordForm.repetpassword" type="password" placeholder="请再次输入新密码..." />
      </el-form-item>
    </el-form>
    <div slot="footer" class="dialog-footer">
      <el-button type="primary" style="width: 15%; margin-left:6%;" @click="resetForm('passwordForm')">重置</el-button>
      <el-button type="primary" style="width: 15%; margin-left:10%;" @click="submitForm('passwordForm')">
        确认
      </el-button>
    </div>
  </div>
</template>

<script>
import { changePassword, queryPassword } from '@/api/user'
import { Encrypt } from '@/utils/rsa'
import { getToken } from '@/utils/auth'
import { validPassword } from '@/utils/validate'

export default {
  name: 'ChangePassword',
  data() {
    var validpass = (rule, value, callback) => {
      if (!validPassword(value)) {
        return callback(new Error('密码必须由数字、字母、特殊字符组合,长度在8-16位之间'))
      } else {
        callback()
      }
    }
    var validpass2 = (rule, value, callback) => {
      if (!validPassword(value)) {
        return callback(new Error('密码必须由数字、字母、特殊字符组合,长度在8-16位之间'))
      } else {
        if (value !== this.passwordForm.newpassword) {
          callback(new Error('两次输入密码不一致!'))
        } else {
          callback()
        }
      }
    }
    return {
      passwordForm: {
        oldpassword: '',
        newpassword: '',
        repetpassword: ''
      },
      rules: {
        oldpassword: [{ required: true, trigger: 'change', validator: validpass }],
        newpassword: [{ required: true, trigger: 'change', validator: validpass }],
        repetpassword: [{ required: true, trigger: 'change', validator: validpass2 }]
      }
    }
  },
  methods: {
    handleQuery() {
      let data = {
        'password': this.passwordForm.oldpassword,
        'token': getToken()
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      queryPassword(params).then(() => {
        return true
      })
      return false
    },
    submitForm(formName) {
      this.$refs[formName].validate((valid) => {
        if (valid) {
          let data = {
            'oldpassword': this.passwordForm.oldpassword,
            'newpassword': this.passwordForm.newpassword,
            'token': getToken()
          }
          data = JSON.stringify(data)
          const params = { 'data': Encrypt(data) }
          changePassword(params).then(() => {
            this.$notify({
              message: '密码修改成功,请重新登陆',
              type: 'success',
              center: true,
              duration: 3 * 1000
            })
            setTimeout(() => {
              this.logout()
            }, 3 * 1000)
          })
        } else {
          this.$notify({
            message: '表单验证失败',
            type: 'eerror',
            center: true,
            duration: 2 * 1000
          })
          return false
        }
      })
    },
    resetForm(formName) {
      this.$refs[formName].resetFields()
    },
    async logout() {
      await this.$store.dispatch('user/logout')
      this.$router.push(`/login?redirect=${this.$route.fullPath}`)
    }
  }
}
</script>

<style scoped>
  .avatar{
    width: 200px;
    height: 200px;
    border-radius: 50%;
  }
</style>

