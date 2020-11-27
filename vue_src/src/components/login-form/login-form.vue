<template>
  <Form ref="LoginForm" :model="form" :rules="rules" @keydown.enter.native="handleSubmit">
    <FormItem prop="username">
      <Input v-model="form.username" placeholder="请输入用户名,1-10位字母数字" clearable>
        <span slot="prepend">
          <Icon :size="16" type="ios-person"></Icon>
        </span>
      </Input>
    </FormItem>
    <FormItem prop="password">
      <Input type="password" v-model="form.password" placeholder="请输入密码,8-16位字母数字" clearable>
        <span slot="prepend">
          <Icon :size="14" type="md-lock"></Icon>
        </span>
      </Input>
    </FormItem>
    <FormItem>
      <Button @click="handleSubmit" type="primary" long>登录</Button>
    </FormItem>
    <FormItem>
      <Button @click="Toregister" type="primary" long>没有账号?马上注册</Button>
    </FormItem>
    <FormItem>
      <Button @click="Tofindpassword" type="primary" long>忘记密码?马上找回</Button>
    </FormItem>
  </Form>
</template>
<script>
import {loginusername, ispassword} from '../../libs/validate'
import {Encrypt}  from '../../libs/crypto'
export default {
  name: 'LoginForm',
  props: {
    userNameRules: {
      type: Array,
      default: () => {
        return [
          { required: true, trigger: 'blur', validator: loginusername  }
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
    }
  },
  data () {
    return {
      form: {
        username: '',
        password: ''
      }
    }
  },
  computed: {
    rules () {
      return {
        username: this.userNameRules,
        password: this.passwordRules
      }
    }
  },
  methods: {
    handleSubmit () {
      this.$refs.LoginForm.validate( (valid) => {
        if (valid) {
          this.$emit('on-success-valid', {
            username: this.form.username,
            password: this.form.password
          })
        }
      })
    },
  Toregister () {
      setTimeout(() => {
        this.$router.push({
        path: '/register'
        })
      },1000)
  },
  Tofindpassword () {
      setTimeout(() => {
        this.$router.push({
        path: '/findpassword'
        })
      },1000)
  }
 }
}
</script>
