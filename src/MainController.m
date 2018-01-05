#include <pthread.h>
#include <mach/mach.h>

#import "MainController.h"
#import "common.h"
#import "offsets.h"
#import "v0rtex.h"

kern_return_t cb(task_t tfp0, kptr_t kbase, void *data)
{
    FILE *f = fopen("/var/mobile/test.txt", "w");
    LOG("file: %p", f);

    host_t host = mach_host_self();
    mach_port_t name = MACH_PORT_NULL;
    kern_return_t ret = processor_set_default(host, &name);
    LOG("processor_set_default: %s", mach_error_string(ret));
    if(ret == KERN_SUCCESS)
    {
        mach_port_t priv = MACH_PORT_NULL;
        ret = host_processor_set_priv(host, name, &priv);
        LOG("host_processor_set_priv: %s", mach_error_string(ret));
        if(ret == KERN_SUCCESS)
        {
            task_array_t tasks;
            mach_msg_type_number_t num;
            ret = processor_set_tasks(priv, &tasks, &num);
            LOG("processor_set_tasks: %u, %s", num, mach_error_string(ret));
        }
    }

    return KERN_SUCCESS;
}

void* bg(void *arg)
{
    offsets_t *off = get_offsets();
    if(off)
    {
        v0rtex(off, &cb, NULL);
    }
    return NULL;
}

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

    pthread_t th;
    pthread_create(&th, NULL, &bg, NULL);
}

@end
