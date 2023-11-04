<template>
  <Dialog :open="showModal"  @close="$emit('toggleModal')" class="bg-white rounded-md">
    <div class="fixed inset-0 bg-black/30" aria-hidden="true" />
    <div class="fixed inset-0 flex w-screen items-center justify-center p-4">
    <DialogPanel class="bg-white rounded-md p-10" >
      <DialogTitle>{{ modalTitle }}</DialogTitle>
      <DialogDescription>
        {{ modalDesc }}
      </DialogDescription>
      <slot>

      </slot>
    </DialogPanel>
    </div>
  </Dialog>
</template>
  
<script setup>
defineProps(['modalTitle', 'modalDesc', 'showModal'])
defineEmits(['toggleModal'])
import {
  Dialog,
  DialogPanel,
  DialogTitle,
  DialogDescription,
} from '@headlessui/vue'

</script>