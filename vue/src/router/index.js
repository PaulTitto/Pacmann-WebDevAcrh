import { createRouter, createWebHistory } from 'vue-router'
// there is also createWebHashHistory and createMemoryHistory
import HomeView from '@/views/HomeView.vue'
import LeaderboardView from '@/views/LeaderBoard.vue'
import LoginView from '@/views/Login.vue'
import RegisterView from '@/views/Register.vue'
//import 
import { useAuthStore } from '../stores/auth';

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
        path:"/",
        name:"home",
        component:HomeView,
        meta: {
          requiresAuth: true, // Specify that this route requires authentication
        }, 
    },
    {
        path:"/leaderboard",
        name:"leaderboard",
        component:LeaderboardView,
        meta: {
          requiresAuth: true, // Specify that this route requires authentication
        }, 
    },
    {
        path:"/login",
        name:"login",
        component:LoginView 
    },
    {
        path:"/register",
        name:"register",
        component:RegisterView 
    },
  ],
})

//MAKE NAVIGATION GUARD
//IF USER NOT LOGIN


router.beforeEach((to, from, next) => {
  const authStore = useAuthStore();  
  // Check if the route requires authentication
  if (to.meta.requiresAuth) {
    // If the user is authenticated, allow access
    if (authStore.isAuthenticated) {
      next();
    } else {
      // If the user is not authenticated, redirect to the login page or another route
      next('/login');
    }
  } else {
    // If the route does not require authentication, allow access
    next();
  }
});

export default router