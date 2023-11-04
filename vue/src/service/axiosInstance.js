import axios from 'axios'

const axiosInstance = axios.create({
    baseURL: import.meta.env.VITE_FLASK_API_BASEURL,
    timeout: 1000,
  });


// Request interceptor to add the access token to outgoing requests
axiosInstance.interceptors.request.use(
  (config) => {
    const accessToken = localStorage.getItem('access_token');
    if (accessToken) {
      config.headers.Authorization = `Bearer ${accessToken}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

  // Response interceptor to handle token refresh
// Response interceptor to handle token refresh
axiosInstance.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    const originalRequest = error.config;
    // Check if the response status is 401 (Unauthorized) and it's not a token refresh request
    if (error.response.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
    // the function to refresh token will be place here
    try {
      const refreshToken = localStorage.getItem('refresh_token');
      const response = await axios.post(import.meta.env.VITE_FLASK_API_BASEURL + '/api/auth/refresh', null, {
          headers:{
          'Authorization': `Bearer ${refreshToken}`
      }});
      const newAccessToken = response.data.access_token;
      localStorage.setItem('access_token', newAccessToken);
      // Retry the original request with the new access token
      originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;
      return axiosInstance(originalRequest);
    } catch (refreshError) {
      console.error('Token refresh failed', refreshError);
    }}  
    return Promise.reject(error);
  });




export default axiosInstance