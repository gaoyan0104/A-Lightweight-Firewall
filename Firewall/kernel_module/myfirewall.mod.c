#include <linux/build-salt.h>
#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(.gnu.linkonce.this_module) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section(__versions) = {
	{ 0xdd8f8694, "module_layout" },
	{ 0x2621e291, "nf_unregister_sockopt" },
	{ 0xbbea7e99, "nf_unregister_net_hook" },
	{ 0x2b68bd2f, "del_timer" },
	{ 0x9fdd072c, "nf_register_sockopt" },
	{ 0x62a38e34, "nf_register_net_hook" },
	{ 0x30cb0399, "init_net" },
	{ 0xc6f46339, "init_timer_key" },
	{ 0x953e1b9e, "ktime_get_real_seconds" },
	{ 0x5ab904eb, "pv_ops" },
	{ 0x5e5292c, "filp_close" },
	{ 0x4e1bcc1b, "kernel_write" },
	{ 0xddd346a3, "filp_open" },
	{ 0xdbf17652, "_raw_spin_lock" },
	{ 0xdecd0b29, "__stack_chk_fail" },
	{ 0x656e4a6e, "snprintf" },
	{ 0xe4c2c66c, "rtc_ktime_to_tm" },
	{ 0xc4f0da12, "ktime_get_with_offset" },
	{ 0xca7a3159, "kmem_cache_alloc_trace" },
	{ 0x428db41d, "kmalloc_caches" },
	{ 0xb44ad4b3, "_copy_to_user" },
	{ 0xc5850110, "printk" },
	{ 0xfb578fc5, "memset" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0x24d273d1, "add_timer" },
	{ 0x15ba50a6, "jiffies" },
	{ 0x37a0cba, "kfree" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "3D9204E50D521B96D73493D");
