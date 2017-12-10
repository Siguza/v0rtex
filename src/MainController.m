#include <mach/mach.h>

#import "MainController.h"
#import "v0rtex.h"
#import "common.h"

@implementation MainController

- (id)initWithNav:(UINavigationController*)nav
{
    id ret = [super init];
    self.nav = nav;
    return ret;
}

- (void)loadView
{
    [super loadView];

    task_t tfp0 = MACH_PORT_NULL;
    kptr_t kslide = 0;
    kern_return_t ret = v0rtex(&tfp0, &kslide);

    // XXX
    if(ret == KERN_SUCCESS)
    {
        extern kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
        uint32_t magic = 0;
        mach_vm_size_t sz = sizeof(magic);
        ret = mach_vm_read_overwrite(tfp0, 0xfffffff007004000 + kslide, sizeof(magic), (mach_vm_address_t)&magic, &sz);
        LOG("mach_vm_read_overwrite: %x, %s", magic, mach_error_string(ret));

        FILE *f = fopen("/var/mobile/test.txt", "w");
        LOG("file: %p", f);
    }
    // XXX
}

@end
