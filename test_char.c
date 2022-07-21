#include <linux/module.h>
#include <linux/mm_types.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/mm_types.h>
#include <asm/pgtable_areas.h>		/* VMALLOC_START, ...		*/
#include <linux/sched.h>		/* test_thread_flag(), ...	*/
#include <linux/sched/task_stack.h>	/* task_stack_*(), ...		*/
#include <linux/kdebug.h>		/* oops_begin/end, ...		*/
#include <linux/extable.h>		/* search_exception_tables	*/
#include <linux/memblock.h>		/* max_low_pfn			*/
#include <linux/kprobes.h>		/* NOKPROBE_SYMBOL, ...		*/
#include <linux/mmiotrace.h>		/* kmmio_handler, ...		*/
#include <linux/perf_event.h>		/* perf_sw_event		*/
#include <linux/hugetlb.h>		/* hstate_index_to_shift	*/
#include <linux/prefetch.h>		/* prefetchw			*/
#include <linux/context_tracking.h>	/* exception_enter(), ...	*/
#include <linux/uaccess.h>		/* faulthandler_disabled()	*/
#include <linux/mm_types.h>
#include <asm/cpufeature.h>		/* boot_cpu_has, ...		*/
#include <asm/traps.h>			/* dotraplinkage, ...		*/
#include <asm/fixmap.h>			/* VSYSCALL_ADDR		*/
#include <asm/vsyscall.h>		/* emulate_vsyscall		*/
#include <asm/vm86.h>			/* struct vm86			*/
#include <asm/mmu_context.h>		/* vma_pkey()			*/
#include <asm/desc.h>			/* store_idt(), ...		*/
#include <asm/cpu_entry_area.h>		/* exception stack		*/
#include <asm/pgtable_areas.h>		/* VMALLOC_START, ...		*/
#include <asm/kvm_para.h>		/* kvm_handle_async_pf		*/
#include <linux/sched.h>		/* test_thread_flag(), ...	*/
#include <linux/sched/task_stack.h>	/* task_stack_*(), ...		*/
#include <linux/kdebug.h>		/* oops_begin/end, ...		*/
#include <linux/extable.h>		/* search_exception_tables	*/
#include <linux/memblock.h>		/* max_low_pfn			*/
#include <linux/kfence.h>		/* kfence_handle_page_fault	*/
#include <linux/kprobes.h>		/* NOKPROBE_SYMBOL, ...		*/
#include <linux/mmiotrace.h>		/* kmmio_handler, ...		*/
#include <linux/perf_event.h>		/* perf_sw_event		*/
#include <linux/hugetlb.h>		/* hstate_index_to_shift	*/
#include <linux/prefetch.h>		/* prefetchw			*/
#include <linux/context_tracking.h>	/* exception_enter(), ...	*/
#include <linux/uaccess.h>		/* faulthandler_disabled()	*/
#include <linux/efi.h>			/* efi_crash_gracefully_on_page_fault()*/
#include <linux/mm_types.h>

#include <asm/cpufeature.h>		/* boot_cpu_has, ...		*/
#include <asm/traps.h>			/* dotraplinkage, ...		*/
#include <asm/fixmap.h>			/* VSYSCALL_ADDR		*/
#include <asm/vsyscall.h>		/* emulate_vsyscall		*/
#include <asm/vm86.h>			/* struct vm86			*/
#include <asm/mmu_context.h>		/* vma_pkey()			*/


static dev_t test_char_dev;
static struct cdev test_char_cdev;
static struct class *test_char_cl;

static int test_char_open(struct inode *i, struct file *f) {
    pr_info("test_char: open()");
    return 0;
}

static int test_char_close(struct inode *i, struct file *f) {
    pr_info("test_char: close()");
    return 0;
}

static ssize_t test_char_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
    pr_info("test_char: read()");
    return 0;
}

static ssize_t test_char_write(struct file *f, const char __user *buf, size_t len,
    loff_t *off) {

	unsigned long address;
	pgd_t *cr3, *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	ssize_t sz;

	unsigned long memcpyaddr;
	unsigned long memcpydaddr;
	unsigned long memcpypaddr;

	int i;
	char c;

	unsigned long page_base_addr, page_offset, phy_addr, direct_addr;

	pr_info("test_char: write()");

	sz = copy_from_user(&address, buf, 8);
	if (sz < 0) {
		return -EINVAL;
	}

	pr_info("get virt user addr: 0x%lx", address);

	cr3 = __va(read_cr3_pa());
	pr_info("cr3 %lx ", (unsigned long)cr3);

	pgd = cr3 + pgd_index(address);
	pr_info("PGD %lx ", (unsigned long)pgd_val(*pgd));
	p4d = p4d_offset(pgd, address);
	pr_info("P4D %lx ", (unsigned long)p4d_val(*p4d));

	pud = pud_offset(p4d, address);
	pr_info("PUD %lx ", (unsigned long)pud_val(*pud));

	pmd = pmd_offset(pud, address);
	pr_info("PMD %lx ", (unsigned long)pmd_val(*pmd));

	pte = pte_offset_kernel(pmd, address);
	pr_info("PTE %lx", (unsigned long)pte_val(*pte));
	pr_info("PAGE_MASK %lx", PAGE_MASK);

	page_base_addr = pte_val(*pte) & ~(1UL << 63) /* clear NX bit */ & PAGE_MASK;
	page_offset = address & ~PAGE_MASK;
	phy_addr = page_base_addr | page_offset;

	pr_info("virt user addr = %lx, phy_addr = %lx", address, phy_addr);
	pr_info("page_base_addr = %lx, page_offset = %lx", page_base_addr, page_offset);

	direct_addr = (unsigned long)__va(phy_addr) ;
	pr_info("page direct addr: %lx", direct_addr);

	*((unsigned long*)direct_addr) = 0xabcdef0123456789;

	memcpyaddr = (unsigned long)&memcpy;

	memcpypaddr = (unsigned long)__pa(memcpyaddr);

	memcpydaddr = (unsigned long)__va(memcpypaddr);


	pr_info("memcpy image addr: %lx", memcpyaddr);
	pr_info("memcpy phy addr: %lx", memcpypaddr);
	pr_info("memcpy direct vaddr: %lx", memcpydaddr);


	pr_info("diff of kernel image addr & phy: %lx\n", memcpyaddr - memcpypaddr);
	pr_info("diff of direct addr & phy: %lx\n", memcpydaddr - memcpypaddr);

	pr_info("memcpy image addr: "); /* kernel image address mapping */
	for (i=0; i < 16; ++i) {
		c = *(((char*)memcpyaddr) +i);
		pr_info("%d ", c);
	}

	pr_info("memcpy direct mapping addr: "); /* physical direct mapping */
	for (i=0; i < 16; ++i) {
		c = *(((char*)memcpydaddr) +i);
		pr_info("%d ", c);
	}
	pr_info("\n");

	return len;
}

static struct file_operations test_char_dev_fops =
{
    .owner = THIS_MODULE,
    .open = test_char_open,
    .release = test_char_close,
    .read = test_char_read,
    .write = test_char_write
};

static int __init test_char_dev_init(void)
{
    int ret;
    struct device *dev_ret;

    pr_info("test_char: init");

    if ((ret = alloc_chrdev_region(&test_char_dev, 0, 1, "test_char")) < 0) {
        return ret;
    }

    if (IS_ERR(test_char_cl = class_create(THIS_MODULE, "test_char"))) {
        unregister_chrdev_region(test_char_dev, 1);
        return PTR_ERR(test_char_cl);
    }
    if (IS_ERR(dev_ret = device_create(test_char_cl, NULL, test_char_dev, NULL, "test_char")))
    {
        class_destroy(test_char_cl);
        unregister_chrdev_region(test_char_dev, 1);
        return PTR_ERR(dev_ret);
    }

    cdev_init(&test_char_cdev, &test_char_dev_fops);
    if ((ret = cdev_add(&test_char_cdev, test_char_dev, 1)) < 0)
    {
        device_destroy(test_char_cl, test_char_dev);
        class_destroy(test_char_cl);
        unregister_chrdev_region(test_char_dev, 1);
        return ret;
    }
    return 0;
}

static void __exit test_char_dev_exit(void)
{
    cdev_del(&test_char_cdev);
    device_destroy(test_char_cl, test_char_dev);
    class_destroy(test_char_cl);
    unregister_chrdev_region(test_char_dev, 1);
    pr_info("test_char: exit");
}

module_init(test_char_dev_init);
module_exit(test_char_dev_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Wang Xinyong <wang.xy.chn@gmail.com>");
MODULE_DESCRIPTION("Test memory direct mapping");
