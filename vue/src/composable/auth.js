import { ref } from 'vue'
import axios from 'axios'
// import axios from '@/service/axiosInstance.js'


export function useAuth() {
    
    const loading = ref(true)
    const message = ref(null)
    const success = ref(false)
    const error = ref(null)
    const accessToken = ref(null)
    const refreshToken = ref(null)
 
 
    axios.defaults.withCredentials = true;
    const tryLogin = async (url, formData) => {
        try{
        
            const response = await axios.post(url, formData)
            accessToken.value = response.data.access_token
            refreshToken.value = response.data.refresh_token
            success.value = response.data.success
            loading.value = false
            return response
        }catch(err){
            error.value = err.response.data.error
            loading.value = false
        }
    }

    const tryLogOut = async (url, access_token) => {
        try{
            const response = await axios.post(url, null,{
                headers:{
                    "Content-Type": 'application/json',
                    'Authorization' : 'Bearer ' + access_token
                }
            })
            success.value = response.data.success
            message.value = response.data.message
            loading.value = false
            return response
        }catch(err){
            error.value = err
            console.log(err)
            loading.value = false
        }
    }

    const tryRegister = async (url, formData, access_token) => {
        try{
            const response = await axios.post(url, formData,{
                headers:{
                    "Content-Type": 'application/json',
                    'Authorization' : 'Bearer ' + access_token
                }
            })
            success.value = response.data.success
            message.value = response.data.message
            loading.value = false
            return response
        }catch(err){
            error.value = err.response.data.error
            loading.value = false
        }
    }


    return {
        error,
        loading,
        success,
        message,
        tryLogin,
        tryLogOut,
        tryRegister,
        accessToken,
        refreshToken
    }
}