<template>
  
  <Form ref = "RegisterForm" :model="form" :rules="rules" @keydown.enter.native="handleSubmit">
    <FormItem prop = "username"> 
      <Input  @on-blur = "handleusername()" v-model="form.username" placeholder="请输入用户名,1-10位字母数字">
        <span slot="prepend">
          <Icon :size="16" type="ios-contact"></Icon>
        </span>
      </Input>
    </FormItem>
    <FormItem prop="email">
      <Input  @on-blur = "handlemail()"  v-model="form.email" placeholder="请输入邮箱地址">
        <span slot="prepend">
          <Icon :size="16" type="ios-mail"></Icon>
        </span>
      </Input>
    </FormItem>
    <FormItem prop="checknum">
      <Input  v-model="form.checknum"  placeholder="请输入验证码"  style="width: 170px">
        <span slot="prepend">
          <Icon :size="16" type="ios-key"></Icon>
        </span>
      </Input>
      <Button style="position:absolute; right: 0px; top: 2px;" type="primary" float: left @click="getchecknum">获取验证码</Button>
    </FormItem>
    <FormItem prop="password">
      <Input type="password" v-model="form.password" placeholder="请输入密码,8-16位字母数字">
        <span slot="prepend">
          <Icon :size="14" type="md-lock"></Icon>
        </span>
      </Input>
    </FormItem>
    <FormItem prop="passwordconfirm">
      <Input type="password" v-model="form.passwordconfirm" placeholder="请再次输入密码,8-16位字母数字">
        <span slot="prepend">
          <Icon :size="14" type="md-lock"></Icon>
        </span>
      </Input>
    </FormItem>
    <FormItem>
      <Button @click="handleSubmit" type="primary" long>注册</Button>
    </FormItem>
     <FormItem>
      <Button @click="ToLogin" type="primary" long>已有账号?马上登录</Button>
    </FormItem>
  </Form>
</template>

<script>
import {isemail, isusername, ischecknum, ispassword} from '@/libs/validate'
import RSA  from '@/libs/crypto'
import AES  from '@/libs/AES'
import http  from '@/libs/http'
export default {
  name: 'RegisterForm',
  props: {
    usernameRules: {
      type: Array,
      default: () => {
        return [
          { required: true, trigger: 'blur', validator: isusername, min:1},
        ]
      }
    },
    emailRules: {
      type: Array,
      default: () => {
        return [
          { required: true, trigger: 'blur', validator: isemail }
        ]
      }
    },
    checknumRules: {
      type: Array,
      default: () => {
        return [
          { required: true, trigger: 'blur', validator: ischecknum }
        ]
      }
    },
    passwordRules: {
      type: Array,
      default: () => {
        return [
          { required: true, trigger: 'blur', validator: ispassword }
        ]
      }
    },
    passwordconfirmRules: {
      type: Array,
      default: () => {
        return [
          { required: true, trigger: 'blur', validator: ispassword }
        ]
      }
    }
  },
  data () {
    return {
      capta: '',
      form: {
        username: '',
        email: '',
        checknum: '',
        password: '',
        passwordconfirm: ''
      },
      username: {
        'type': 'username', 
        'data': ''
      }
    }
  },
  computed: {
    rules () {
      return {
        username: this.usernameRules,
        email: this.emailRules,
        checknum: this.checknumRules,
        password: this.passwordRules,
        passwordconfirm: this.passwordconfirmRules
      }
    }
  },
  methods: {
    handleusername () {
      this.$refs.RegisterForm.validateField('username', (valid) => {

      })
   },

    handlemail () {
        this.$refs.RegisterForm.validateField('email', (valid) => {
        })
    },

    getchecknum () {
      if (this.form.email== ''){
        this.$refs.RegisterForm.validateField('email', (valid) => {
        })
      }
      else{
        let data = {
          'type': 'email', 
          'data': this.form.email
        }
        data = JSON.stringify(data)
        let params = {'data': RSA.Encrypt(data)}
        http.post('/api/getchecknum', params).then((res) => {
          res.data = eval('(' + res.data + ')')
          switch(res.data.code ){
            case'Z1000':
            this.$Notice.success({
                title: '发送邮件成功',
                desc: '请打开邮件查收验证码 '
            })
            this.capta = AES.Decrypt(res.data.data)
            break
            case 'Z1001':
            this.$Notice.error({
                title: '发送邮件失败',
                desc: '系统发生异常,请稍后再次尝试'
            })
            break
            case 'Z1002':
            this.$Notice.error({
                title: '发送邮件失败',
                desc: '系统发生异常,请稍后再次尝试'
            })
            break
          }
        })
      }
    },
    handleSubmit () {
     this.$refs.RegisterForm.validate( (valid) => {
        if (valid) {
          if (this.form.password != this.form.passwordconfirm){
            this.$Notice.error({
                title: '二次密码输入错误',
                desc: '二次密码输入错误,请重新输入!'
            })
          }
          else{
            console.log(this.capta)
            this.$emit('on-success-valid', {
              username: this.form.username,
              email: this.form.email,
              password: this.form.password,
              checknum: this.form.checknum,
              capta: this.capta
            })
          }
        }
      })
    },

    ToLogin () {
      setTimeout(() => {
        this.$router.push({
        path: '/login'
        })
      },1000)
    }
  }  
}
</script>
