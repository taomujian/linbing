<template>
  <div class="user-avatar-dropdown">
    <Dropdown @on-click="handleClick">
        <Avatar :src="userAvatar"/>
      <Icon :size="18" type="md-arrow-dropdown"></Icon>
      <DropdownMenu slot="list">
        <DropdownItem name="changeavatar">修改头像</DropdownItem>
        <DropdownItem name="password">修改密码</DropdownItem>
        <DropdownItem name="logout">退出登录</DropdownItem>
      </DropdownMenu>
    </Dropdown>
  </div>
</template>

<script>
import './user.less'
import store from '../../../../store'
import { mapActions } from 'vuex'
export default {
  name: 'User',
  props: {
    userAvatar: {
      type: String,
      default: store.getters.imagename
    },
  },
  methods: {
    ...mapActions([
      'handleLogOut'
    ]),
    changeavatar (){
      this.$router.push({
        name: 'change_avatar'
      })
    },
    logout () {
      store.commit('setToken', '')
      store.commit('setUserName', '')
      store.commit('setUserEmail', '')
      store.commit('setAvatar', '')
      store.commit('setAccess','')
      store.commit('setUserId', '')
      store.commit('setHasGetInfo', false)
      setTimeout(() => {
        this.$router.push({
          name: 'login'
        })
      },1000)
    },
    message () {
      this.$router.push({
        name: 'message_page'
      })
    },
    password () {
      this.$router.push({
        name: 'change_password'
      })
    },
    handleClick (name) {
      switch (name) {
        case 'logout': this.logout()
          break
        case 'message': this.message()
          break
        case 'password': this.password()
          break
        case 'changeavatar': this.changeavatar()
          break
      }
    }
  }
}
</script>
