import { defineStore } from 'pinia'
import {ref, computed} from 'vue'
// You can name the return value of `defineStore()` anything you want,
// but it's best to use the name of the store and surround it with `use`
// and `Store` (e.g. `useUserStore`, `useCartStore`, `useProductStore`)
// the first argument is a unique id of the store across your application
export const useAuthStore = defineStore('auth', () => {
  // state
  const accessToken = ref(null || localStorage.getItem('access_token'))
  const refreshToken = ref(null || localStorage.getItem('refresh_token'))
  // getters
  const isAuthenticated = computed(() => {
    return accessToken.value !== null
  })


  // actions
  const setToken = (access_token, refresh_token) => {
   localStorage.setItem("access_token", access_token)
   localStorage.setItem("refresh_token", refresh_token)
    accessToken.value = access_token
    refreshToken.value = refresh_token
  }
  const removeToken = () => {
    localStorage.removeItem("access_token")
    localStorage.removeItem("refresh_token")
    accessToken.value = null
    refreshToken.value = null   
}

return {
  accessToken, refreshToken, setToken, removeToken, isAuthenticated
}
})