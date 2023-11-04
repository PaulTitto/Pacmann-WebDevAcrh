<template>
    <div class="p-20">
        <Form>
            <h1 class="text-2xl text-center">Login Form</h1>
            <p v-if="error" class="bg-red-500 text-white p-3 mb-2 mt-2">{{ error }}</p>
           <Input label-name="Username" v-model="userData.username" input-type="text"/>
           <p v-if="validationErrors.username" class="text-red-500">{{ validationErrors.username }}</p>
           <Input label-name="Password" v-model="userData.password" input-type="password"/>
           <p v-if="validationErrors.password" class="text-red-500">{{ validationErrors.password }}</p>
           <Button button-type="submit" name="Submit" @click="handleLogin"/>
           <RouterLink to="/register" class="text-blue-500 mt-4 hover:underline underline-offset-4">Mendaftar Sekarang!</RouterLink>
        </Form>
    </div>
</template>

<script setup>
import Form from '../components/ui/Form.vue';
import Input from '../components/ui/Input.vue';
import Button from '../components/ui/Button.vue';
import { reactive, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { useAuth } from '../composable/auth';
import { useAuthStore } from '@/stores/auth.js'
import { useRouter } from 'vue-router'
import { SwitchLabel } from '@headlessui/vue';

const {tryLogin,accessToken, refreshToken} = useAuth()

import Swal from 'sweetalert2';

const {setToken} = useAuthStore()
const router = useRouter()
const error = ref(null)


const success = ref(false)
const successMessage = ref(null)

const userData = reactive({
    username: '',
    password: ''
})

const validationErrors = reactive({
    username: '',
    password: ''
})

const handleLogin = async () => {
     // Reset errors
  Object.keys(validationErrors).forEach(key => {
    validationErrors[key] = '';
  });

  let isValid = true

  if (!userData.username){
    validationErrors.username = 'Username is required',
    isValid = false
  }

  if(!userData.password){
    validationErrors.password = "Password is required"
    isValid = false
  }

 

  if(isValid){
      const res = await tryLogin(import.meta.env.VITE_FLASK_API_BASEURL + '/api/auth/login', userData)
        error.value = res.error
        console.log(error.value)
        success.value = res.data.success
        successMessage.value = res.data.message
      if(success.value){
          //simpan token ke localStorage dengan state
          setToken(accessToken.value, refreshToken.value)
          //panggil sweetalert 2 disini
        Swal.fire(successMessage.value)
          //redirect ke home
          router.push('/')
      }
  }

}

</script>