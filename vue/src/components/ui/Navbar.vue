<template>
  <div class="bg-green-500 flex justify-around h-10 text-white">
    <h3 class="self-center text-2xl font-bold">Navbar</h3>
    <ul class="flex justify-evenly items-center">
      <RouterLink to="/" active-class="border-b-2 border-white"
        class="hover:border-b-4 hover:border-white p-1 rounded-sm">Home</RouterLink>
      <RouterLink to="/leaderboard" active-class="border-b-2 border-white"
        class="hover:border-b-4 hover:border-white p-1 rounded-sm">Leaderboard</RouterLink>
      <RouterLink to="/login" active-class="border-b-2 border-white"
      class="hover:border-b-4 hover:border-white p-1 rounded-sm">Login</RouterLink>
      <a 
      :href="urlAdmin" class="hover:border-b-2 border-white mr-2">Admin</a>
      <button @click="handleLogout" class="hover:border-b-2 border-white">Logout</button>
    </ul>
  </div>
</template>
  
<script setup>
import { RouterLink } from 'vue-router'
import { useAuthStore } from '../../stores/auth';
import { useRouter } from 'vue-router'
import { useAuth } from '@/composable/auth.js'

import { ref } from 'vue'
import Swal from 'sweetalert2'

const router = useRouter()
const { removeToken, accessToken } = useAuthStore()
const { tryLogOut } = useAuth()

const success = ref(false)
const successMessage = ref(null)
const urlAdmin = import.meta.env.VITE_FLASK_API_BASEURL + '/admin'

const handleLogout =  () => {
  // console.log("logout")
  Swal.fire({
    title: 'Logout',
    text: "Apakah anda yakin mau logout!",
    icon: 'warning',
    showCancelButton: true,
    confirmButtonColor: '#3085d6',
    cancelButtonColor: '#d33',
    confirmButtonText: 'Ya'
  }).then( async (result) => {
    if (result.isConfirmed) {
      const res = await tryLogOut(import.meta.env.VITE_FLASK_API_BASEURL + '/api/auth/logout', accessToken)
      success.value = res.data.success
      successMessage.value = res.data.message
      removeToken()
      router.push('/login')
      if(success.value){
        Swal.fire(
          'Logout!',
          successMessage.value,
          'success'
        )
      }
    }
  })
  // const res = await tryLogOut(import.meta.env.VITE_FLASK_API_BASEURL + '/api/auth/logout', accessToken)
  // if (success.value) {
  //   console.log(message.value)
  //   removeToken()
  //   router.push('/login')
  // }
  // removeToken()
  // router.push('/login')
}

</script>