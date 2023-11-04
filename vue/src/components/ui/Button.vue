<template>
    <button :type="buttonType" class="bg-green-500 p-2 mt-3 rounded-md text-white hover:bg-green-800" > {{ name }}</button>
</template>

<script setup>
defineProps({
    class:String,
    isClicked: Boolean,
    buttonType: String,
    name:{
        type:String,
        defaul: "Submit"
    }
})
</script>