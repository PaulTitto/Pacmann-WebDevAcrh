<template>
  <div class="bg-white rounded-lg shadow-lg mb-10 mt-5 hover:scale-105">
    <!-- Card Body -->
    <div class="p-4">
      <img v-if="imgPath" :src="imgPath" :alt="imgName">
      <p class="text-gray-800 font-bold text-2xl">
        {{ tweet }}
      </p>
    </div>
    <div class="ml-2 mb-2">
      <Button name="Like" :is-clicked="isClicked" class="hover:bg-green-800 p-2  rounded-md" :class="{'bg-green-500 text-white': !isClicked, 'border-2 border-green-500 text-green-500': isClicked}" @click="buttonClicked"/>
    </div>
    <!-- Card Caption -->
    <div class="bg-gray-200 p-3 text-gray-600">
      <p>Tweet From {{ user }}</p>
    </div>
  </div>
</template>
<script setup>
defineProps(['user', 'tweet', 'imgPath', 'imgName'])
import Button from './Button.vue';
import { ref } from 'vue'

const isClicked = ref(false)

const buttonClicked = () => {
  isClicked.value = !isClicked.value
}
</script>