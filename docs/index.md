_Siguza, 07. Dec 2017_

# v0rtex

Turning the IOSurface inside out.

## Introduction

On the 5th of December, [windknown][windknown] posted about an IOSurface mach port UaF on the [Pangu blog][blog], which [had been fixed in iOS 11.2](https://support.apple.com/en-us/HT208334) and apparently reported by [Ian Beer][ianbeer]. Now I neither speak Chinese nor really trust Google Translate with details, but the PoC on the Pangu blog was enough to illustrate the vulnerability and get me going. :P

There are a lot of things referenced in this write-up that I have not or only partially explored. I'll likely come back to expand or correct these once I learn more, but I wanted to get this write-up out as a sort of documentation for other devs who might wanna chip in.

Also, I didn't really proof-read this, I just wanna get the info out at the moment. Please kindly notify me of typos and the like?

## Exploit

### Freeing and reallocating

The bug decreases the ref count on a user-supplied mach port by one too many. This is very nice because it can leave you with a still-valid userland handle to a freed port which can then hopefully be reallocated with controlled contents, yielding a complete fake port.

Windknown's PoC uses the same port for first and subsequent registration, but I'd rather not have a freed object referenced more than necessary, so we'll use two different ports - and more, for the sake of heapcraft. We allocate in this order:

1. A single mach port called `realport`.
2. `0x1000` mach ports to spray the `ipc.ports` zone before `port`.
3. A single mach port called `port` (renamed to `fakeport` once freed).
4. Another `0x100` mach ports to spray the `ipc.ports` zone after `port`.

We then free `port` via the bug, and release the `0x1100` ports we sprayed as well. In the `ipc.ports` zone, that will hopefully lead to the page on which `port` resides to have all elements freed. Once that happens, we can use the `mach_zone_force_gc` MIG call to get the entire page out of the zone, allowing us to reallocate the port with arbitrary memory instead of just valid mach ports. (Note `mach_zone_force_gc` was disabled in iOS 11, but you should still be able to trigger a garbage collection by iterating over all zones, allocating and subsequently freeing something like 100MB in each, and measuring how long it takes to do so - garbage collection should be a significant spike.)

One obstacle I faced though was that the IOSurface bug seemed to have some asynchronicity or whatnot - for a short time after `IOConnectCallAsyncStructMethod` returned, the port seemed to still be valid, however after a `sleep(1)` it was not. I didn't feel like hunting down the cause of that, so I simply increased the ref count on `port` by using `mach_ports_register` on my own task, which would cause the bug to still drop one ref too many, but not free it anymore. Now after that call returns, we can `usleep(100000)` to synchronise, and then use `mach_ports_register` again to decrease the ref on `port` again, this time freeing it synchronously. And since we call `mach_ports_register` already, we also register our `IOSurfaceRootUserClient` handle there because we'll need that for later. Now we just need to call `mach_zone_force_gc` and if everything worked out, the memory that contained `port` is now available for reallocation.

Now we want to reallocate it, but how and with what content ? My favourite heap allocation primitive is `OSUnserializeXML` (or `OSUnserializeBinary` I should say) because it allows fine-grained control over allocation and contents, allows for both arbitrary data and pointers, and is used in many places. So since we're dealing with IOSurface anyway, I figured we might as well use IOSurface properties. An `IOSurfaceRootUserClient` offers external methods `9`, `10` and `11` to parse arbitrary data with `OSUnserializeXML`, store the result in the kernel, and read back or delete that result at any time. I'll leave the implementation details on this for another time, but they're effectively the same as`IOSurfaceSetValue`, `IOSurfaceCopyValue` and `IOSurfaceRemoveValue`, just faster since no CF serialisation has to happen.  
Alright, so now we've got to reallocate the freed pages. In order to avoid creating holes, this is best done with allocations of exactly the page size. On A9 and later that is 16KB, but on A8 and earlier the true hardware page size is 4KB, despite only 16KB being exported to userland. So we're going for `0x1000` here. Now, `OSData` would normally seem like the best choice for binary data, but it turns out that doesn't go through `kalloc` anymore for allocations larger or equal to the page size. The next best choice to me is `OSString` which works well, so long as you take into account that a null terminator is added to the serialised data, so in order to get a `0x1000` allocation, you'll want to have just `0xfff` bytes of serialised data.

### Fake port construction

At this point we merely have to put some data into our `OSString`s, and the kernel will treat it as a mach port. So let's start with a look at the structure:

```c
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
```

There is a slight problem now though: we don't know at which offset the mach ports start. When a page is allocated into a zone with elements of size `x`, the first element will start at offset `0`, the second one at `x`, then `x * 2`, etc. Depending on `x`, that might leave more or less memory at the end of a page unused. To optimise that, zones that would leave a significant amount of memory unused change their allocation size to multiple pages (most notable with e.g. the `kalloc.1280` zone - `0x1000` allocations would leave `256` bytes unused, but `0x5000` is an exact multiple of `1280` and thus wastes nothing). On 10.3.3 the size of a mach port is `0xa8` bytes, and the `ipc.ports` zone uses allocations of `0x3000` bytes. So the first port will be allocated at offset `0xa8` and the last port on the first page will start at `0xfc0` and extend onto the second page - but that means the first port on the second page will start at offset `0x1068` rather than `0x1000`, and the same thing repeats for the third page as well. The problem with that is that when we reallocate those pages, we don't know whether they used to be the first, second or third of their chunk - even using an allocation size of `0x3000` ourselves wouldn't help, since that might as well start on a second or third page and just extend beyond it, since pages are units of their own.

So what we'll have to do now is create a structure that is valid no matter with which of the three possible offsets it is accessed. These offsets are `0x0`, `0x68` and `0x28` respectively for first, second and third page. The absolute minimum for a valid port is an intact lock, so we'll start with that. Long story short, initialisation looks like this:

```c
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
```

Now so far this works, but it's obvious that as the struct populates, this will become a hazardous deathtrap. So it'd be nice if you could use a first, minimal mach port to _detect_ which offset we're dealing with, and then reallocate at just that offset without all this cruft. A very viable way to do this was previously outlined by Ian Beer in [his mach_portal write-up][mach_portal], making use of the `ip_context` field. In short, the `mach_port_get_context` MIG call lets you fetch the `ip_context` field of a port while touching nothing but that field and the port's lock. So what does `ip_context` overlay with when shifted? For the first page that's just `ip_context`, for the second page it's the field `msgcount`, `qlimit` and `pad` of `ip_messages.port`, and for the third page it's the `type` and `pad` fields of `ip_lock`. So the lower 32 bits of `ip_context` might intersect with `ip_lock.type` which is rather critical, but that still leaves us with the upper 32 bits in any case. That is plenty, and allows us to store both what offset is being used, as well as and identifier for the `OSString` object we're dealing with. So given a number `i` from which we can derive what key we later need to use to free and reallocate the `OSString`, this is how we initialise `ip_context`:

```c
volatile kport_t *dptr = ...;
for(size_t j = 0; j < DATA_SIZE / sizeof(kport_t); ++j)
{
    dptr[j].ip_context = (dptr[j].ip_context & 0xffffffff) | ((uint64_t)(0x10000000 | i) << 32);
    dptr[j].ip_messages.port.pad = 0x20000000 | i;
    dptr[j].ip_lock.pad = 0x30000000 | i;
}
```

Now when using the result of `mach_port_get_context`, the bits `0x3000000000000000` tell us whether our port was on page one, two or three, and the bits `0x0fffffff00000000` allow us to identify on which `OSString` it resides.

### Reading memory and defeating KASLR

Now we can properly reallocate it, but with what? In the end we'll probably want an `IKOT_IOKIT_CONNECT`-type port with a fake `IOUserClient` object, allowing us to call arbitrary kernel code, so at the very least we'll need to know the kernel slide. To get there, we probably also want to use `pid_for_task` with a fake task to read arbitrary memory first, but for that we need an address to start from, and so far we don't know a single valid kernel pointer. At this point I figured I had two options:

- Leverage a kernel pointer comparison (such as with the clock system port) to brute-force the kernel slide.
- Get a valid pointer into our fake port struct somehow and read back the `OSString`.

The former sounds like a horrible idea in our setting - since we have to change `ip_kobject`, we'd have to reallocate the `OSString` over and over, each time risking the memory getting snatched by someone else. The latter, however, turns our to be very viable. In the kernel's `struct ipc_port` there are a number of `struct ipc_port *` members, one of which is `ip_pdrequest`. That field can hold a pointer to a mach port which is to be notified on port death, and it can be set via `mach_port_request_notification`, provided the target port is of type `IKOT_NONE` (i.e. target is in userland) and the notification port is a send-once or receive right (from which a send-once one can be made). So let's create an `IKOT_NONE` port:

```c
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
    .ip_srights = 99,
};
```

References exist just to prevent deallocation, and `MACH_PORT_QLIMIT_KERNEL` prevents accidental sending of messages. Now we can register a send-once or receive right, such as e.g. `realport` on it:

```c
mach_port_t old = MACH_PORT_NULL; // unused
mach_port_request_notification(self, fakeport, MACH_NOTIFY_PORT_DESTROYED, 0, realport, MACH_MSG_TYPE_MAKE_SEND_ONCE, &old);
```

And now we merely need to read back the `OSString` with `IOSurfaceRootUserClient`'s external method 10, look for a `kport_t` with `ip_pdrequest != 0`, and we have the kernel's address for `realport`! Now we can prepare a fake task and then reallocate our port with type `IKOT_TASK`. I was too lazy to rebuild the entire `task_t` struct, so I just abused unions a bit:

```c
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
```

With that we can do:

```c
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
```

One call to external methods 11 and 9 each, and our changes are live and we just need to point `ktask.d.bsd_info` at some address, and `pid_for_task` will get us 4 bytes from an offset `0x10` after it. Now we can start reading from `realport`, jumping from one pointer to the next: `realport->receiver->is_task->itk_registered[0]->ip_kobject->vtab`. That is, from `realport` we read the `struct ipc_space` it belongs to (`receiver`) and from that we get the `task_t` by which it is owned (`is_task`), which is our own task. Now remember how we passed the port to `IOSurfaceRootUserClient` to `mach_ports_register` in the beginning ? Thanks to that, we can now read a pointer to that port from `itk_registered[0]`, from that a pointer to the `IOSurfaceRootUserClient` itself, and from that a pointer to its C++ vtable, which is, at long last, a value from which we can derive the kernel slide.

### Kernel code execution

While our fake port is still set for reading, we can also leak most of the `IOSurfaceRootUserClient`'s vtable contents and start building a fake vtable. That allows us to create a fake `IOUserClient` object, to which we can then stash a pointer in `fakeport->ip_kobject`, and switch the type of `fakeport` once more, this time to `IKOT_IOKIT_CONNECT`. Now what we wanna do is switch out `IOUserClient::getExternalTrapForIndex` in the fake vtable with something that returns an `IOExternalTrap` whose contents we control. For that, I use a gadgets like so:

```
add x0, x0, 8
ret
```

That just returns the address of the memory after the fake object's vtable pointer, so we can put an object and a function pointer right after the vtab. We can then call `iokit_user_client_trap` on `fakeport`, which will lead us to this bit in the kernel:

```cpp
result = (target->*func)(args->p1, args->p2, args->p3, args->p4, args->p5, args->p6);
```

We control all of `p1` through `p6` (passed in via `iokit_user_client_trap`) as well as `target` and `func` (the two pointers after the vtab) and on top of that, `result` will even be passed back to userland unchanged (formally it is a `kern_return_t`, but register `x0` is used rather than `w0`, so all 64 remain preserved).

For now, all I use that for is a call to `bzero(&self_task->bsd_info->p_ucred.cr_uid, 12)`, which sets effective, real and saved user IDs all to zero, elevating us to `root`. You can do pretty much anything you like at this point though - apart from function calls with more than 7 arguments, that is. :P

## Future work

Sorted by importance to me:

### tfp0

In the short term (i.e. as part of the exploit), a fake task with a `map` pointing to the `kernel_map` should suffice. That's really not something I'd like to stash in `realhost.special[4]` indefinitely however. Ideally I'd like to run this:

```c
vm_map_remap(
    kernel_map,
    &remap_addr,
    sizeof(task_t),
    0,
    VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
    zone_map,
    kernel_task,
    false,
    &dummy,
    &dummy,
    VM_INHERIT_NONE
);
mach_vm_wire(&realhost, kernel_map, remap_addr, sizeof(task_t), VM_PROT_READ | VM_PROT_WRITE);
ipc_port_t newport = ipc_port_alloc_special(ipc_space_kernel);
ipc_kobject_set(newport, remap_addr, IKOT_TASK);
realhost.special[4] = ipc_port_make_send(newport);
```

However, that call to `vm_map_remap` with 11 arguments is not so easily executed with an `iokit_user_client_trap` that only takes 6 arguments plus one from the kernel. Maybe a fake task with attached `zone_map`, and then call from userland ?

### SMAP

From the moment I declare my `ktask_t` on, I make extensive use of userland dereferences. That won't work on either the iPhone 7 and later due to SMAP, nor on 32-bit due to lack of a shared address space. So if these are to ever be supported, we need a place to put a fake task and other stuff. Now, `mach_port_request_notification` does allow a port to be registered on itself, so that way it should be possible to obtain the address of our `OSString` buffer. Since we only use `0xa8` bytes inside that, we could then use the remaining memory as scratch space. We'd need to reallocate on every read though, but if we go straight for a minimal fake kernel task port, we should get away with a total 8 reallocations (1 after finding the page offset, 5 for `realport->receiver->is_task->itk_registered[0]->ip_kobject->vtab`, 1 for reading `kernel_map`, and one for final fake `kernel_task` construction). At that point we'd know the address of our task, so we could `vm_allocate` some memory in the kernel, stash a pointer to that in `self_task->itk_registered` and retrieve it via `mach_ports_lookup`, and then use that to do kernel function calls.  

### 32-bit

In principle all of this should work on 32-bit as well, but things might be different due to different pointer size. In particular the thing with the three possible page offsets might either be less or more complicated, depending on how many pages are chunked into the `ipc.ports` zone on 32-bit, and resulting from that which fields overlay in a port struct.

I lack a 32-bit device that can go higher than 9.3.5 though, so... I can offer my knowledge to devs wanting to take a stab at it, but I won't personally do it.

### ETA wen ?

I don't know. I suppose this is a good time to start writing my own patchfinder (I want a _maintainable_ one), so... I guess I'll actually do that. No idea what roadblocks I'll run into though or how long that'll take. Don't expect anything soon.

## Conclusion

Awesome bug, mad props to Ian Beer (and windknown?) for finding it! Also props to both of them for all their previous work, not sure whether we'd all be where we are today without you.

Now, lots of work to be done! If anyone wants to chip in with anything, I'm readily available on Discord (`Siguza#7111`). For updates on this as well as general iOS hacking, you can follow me on [Twitter](https://twitter.com/s1guza)

## References

- windknown: [IOSurface UaF][blog]
- Ian Beer: [Through the mach portal][mach_portal]

<!-- link refs -->

  [windknown]: https://twitter.com/windknown
  [ianbeer]: https://twitter.com/i41nbeer
  [blog]: http://blog.pangu.io/iosurfacerootuserclient-port-uaf/
  [mach_portal]: https://bugs.chromium.org/p/project-zero/issues/attachment?aid=280146
