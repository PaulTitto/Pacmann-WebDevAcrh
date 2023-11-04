<template>
  <div class="items-center">
    <label
      class="bg-green-500 hover:bg-green-700 text-white py-2 px-4 rounded cursor-pointer"
    >
      <span>{{ buttonText }}</span>
      <input
        :id="id"
        type="file"
        class="hidden"
        @change="handleFileChange"
      />
    </label>
    <span v-if="selectedFile">{{ selectedFile.name }}</span>
  </div>
</template>

<script setup>
import { ref } from 'vue';

const { buttonText, id, modelValue } = defineProps(['buttonText', 'id', 'modelValue']);
const emits = defineEmits(['update:modelValue']); // Use defineEmits to declare the emit function

const selectedFile = ref(null);

function handleFileChange(event) {
  const file = event.target.files[0];
  selectedFile.value = file;
  emits('update:modelValue', file); // Emit the event with the selected file
}
</script>
