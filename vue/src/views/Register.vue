<template>
    <div class="p-20">
        <Form>
            <h1 class="text-2xl text-center">Registration Form</h1>
            <p v-if="error" class="bg-red-500 text-white p-3 mt-2 mb-2">{{ error }}</p>
            <Input label-name="Username" v-model="userData.username" input-type="text" />
            <p v-if="validationErrors.username" class="text-red-500">{{ validationErrors.username }}</p>
            <Input label-name="Email" v-model="userData.email" input-type="email" />
            <p v-if="validationErrors.email" class="text-red-500">{{ validationErrors.email }}</p>
            <Input label-name="Password" v-model="userData.password" input-type="password" />
            <p v-if="validationErrors.password" class="text-red-500">{{ validationErrors.password }}</p>
            <Input label-name="Confirm Password" v-model="confirm_password" input-type="password" />
            <p v-if="validationErrors.confirmPassword" class="text-red-500">{{ validationErrors.confirmPassword }}</p>
            <Button button-type="submit" name="Submit" @click="handleRegistration" />
            <RouterLink to="/login" class="text-blue-500 mt-4 hover:underline underline-offset-4">Back to Login!
            </RouterLink>
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
import { useAuthStore } from '../stores/auth';

import Swal from 'sweetalert2'

const { tryRegister, error } = useAuth()

const successMessage = ref(null)
const success = ref(false)

const { accessToken } = useAuthStore()
const userData = reactive({
    username: '',
    password: '',
    email: ''
})
const confirm_password = ref('')

const validationErrors = reactive({
    username: '',
    password: '',
    email: '',
    confirmPassword: ''
})

const handleRegistration = async () => {
    // Reset errors
    Object.keys(validationErrors).forEach(key => {
        validationErrors[key] = '';
    });

    let isValid = true

    if (!userData.username) {
        // cek apakah isian username kosong atau tidak
        validationErrors.username = 'Username is required';
        isValid = false;
    }

    if (!userData.password) {
        validationErrors.password = "Password is required"
        isValid = false
    } else if (userData.password < 8) {
        validationErrors.password = "Password must at least 8 character"
        isValid = false
    }
    if (!userData.email) {
        validationErrors.email = "Email is required"
        isValid = false
    }
    if (confirm_password.value !== userData.password) {
        validationErrors.confirmPassword = "Password do no match"
        isValid = false
    }

    // validasi password dan confirm password
    if (isValid) {
        const res = await tryRegister(import.meta.env.VITE_FLASK_API_BASEURL + '/api/auth/register', userData, accessToken)
        successMessage.value = res.data.message
        success.value = res.data.success
        if(success.value){
            Swal.fire(
                'Berhasil',
                successMessage.value,
                'success'
            )
        }


    }
}


</script>