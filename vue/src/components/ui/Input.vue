<template>
    <label>{{ labelName }}</label>
    <input :type="inputType"  :value="modelValue" @input="$emit('update:modelValue', $event.target.value)" class="rounded-md bg-gray-300 focus:bg-white focus:outline-none focus:border-b-4 focus:border-green-500 h-10"/>
</template>

<script setup>
defineProps(['labelName', 'inputType', 'modelValue'])
defineEmits(['update:modelValue'])
</script>