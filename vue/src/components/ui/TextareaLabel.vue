<template>
    <label :for="id" class="text-2md font-semibold">{{ label }}</label>
    <textarea :id="id" class="rounded-md bg-gray-300 focus:bg-white focus:outline-none focus:border-b-4 focus:border-green-500" placeholder="Enter text here" :rows="row"  :value="modelValue" @input="$emit('update:modelValue', $event.target.value)"></textarea>
</template>

<script setup>
defineProps(['label', 'id', 'modelValue', 'row'])
defineEmits(['update:modelValue'])
</script>