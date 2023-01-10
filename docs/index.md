_Siguza, 07. Dec 2017 (updated 12. Dec 2017)_

# v0rtex

Turning the IOSurface inside out.

## Introduction

On December 5th, [windknown][windknown] posted about an IOSurface mach port UaF on the [Pangu blog][blog], which [had been fixed in iOS 11.2](https://support.apple.com/en-us/HT208334) and reported by [Ian Beer][ianbeer]. Now I neither speak Chinese nor really trust Google Translate with details, but the PoC on the Pangu blog was enough to illustrate the vulnerability and get me going. :P

> Update:  
> Ian's exploit for iOS 11 is now [out as well][async_wake]!

## The Exploit

### Freeing and reallocating

The bug decreases the ref count on a user-supplied mach port by one too many. This is very nice because it can leave you with a still-valid userland handle to a freed port which can then hopefully be reallocated with controlled contents, yielding a complete fake port.

Windknown's PoC uses the same port for first and subsequent registration, but I'd rather not have a freed object referenced more than necessary, so we'll use two different ports - and more, for the sake of heapcraft. We allocate in this order:

1. A single mach port called `realport`.
2. `0x1000` mach ports to spray the `ipc.ports` zone before `port`.
3. A single mach port called `port` (renamed to `fakeport` once freed).
4. Another `0x100` mach ports to spray the `ipc.ports` zone after `port`.

We then free `port` via the bug, and release the `0x1100` ports we sprayed as well. In the `ipc.ports` zone that will hopefully lead to the page on which `port` resides to have all elements freed. Once that happens, we can use the `mach_zone_force_gc` MIG call to get the entire page out of the zone, allowing us to reallocate the port with arbitrary memory instead of just valid mach ports. (Note `mach_zone_force_gc` was disabled in iOS 11, but you should still be able to trigger a garbage collection by iterating over all zones, allocating and subsequently freeing something like 100MB in each, and measuring how long it takes to do so - garbage collection should be a significant spike.)

One obstacle I faced though was that the IOSurface bug seemed to have some asynchronicity or whatnot - for a short time after `IOConnectCallAsyncStructMethod` returned, the port seemed to still be valid, however after a `sleep(1)` it was not. I didn't feel like hunting down the cause of that, so I simply increased the ref count on `port` by using `mach_ports_register` on my own task, which would cause the bug to still drop one ref too many, but not free it anymore. Now after that call returns, we can `usleep(100000)` to synchronise, and then use `mach_ports_register` again to decrease the ref on `port` again, this time freeing it synchronously. And since we call `mach_ports_register` already, we also register our `IOSurfaceRootUserClient` handle there because we're gonna need that for later. All that remains is a call to `mach_zone_force_gc` and if everything worked out, the memory that contained `port` is now available for reallocation.

At this point we're gonna reallocate it, but how exactly and with what contents? My favourite heap allocation primitive is `OSUnserializeXML` (or `OSUnserializeBinary` to be exact) because it allows for fine-grained control over allocation and contents, allows for both arbitrary data and pointers, and is used in many places. So since we're dealing with IOSurface anyway I figured we might as well use IOSurface properties. An `IOSurfaceRootUserClient` offers external methods `9`, `10` and `11` to parse arbitrary data with `OSUnserializeXML`, store the result in the kernel, and read back or delete that result at any time. I'll leave the implementation details on this for another time, but they're effectively the same as `IOSurfaceSetValue`, `IOSurfaceCopyValue` and `IOSurfaceRemoveValue`, just faster since no CoreFoundation object serialisation has to happen.  
Alright, so we've got to reallocate the freed pages. In order to avoid creating holes, this is best done with allocations of the page size or smaller. On A9 and later the page size is 16KB, but on A8 and earlier the it is actually 4KB despite the 16KB being exported to userland - so we're gonna use `0x1000` here. Now, `OSData` would normally seem like the best choice for binary data, but it turns out that doesn't go through `kalloc` anymore for allocations larger or equal to the page size. The next best choice to me is `OSString` which works well, so long as you take into account that a null terminator is added when unserialising, so in order to get a `0x1000` allocation, you'll want to have only `0xfff` bytes of serialised data.

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
            uint32_t seqno;
            uint32_t receiver_name;
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
    uint64_t ip_context;
    uint32_t ip_flags;
    uint32_t ip_mscount;
    uint32_t ip_srights;
    uint32_t ip_sorights;
} kport_t;
```

(Here `kptr_t` is just a `typedef` to a type of the kernel's pointer size. Also on 32-bit, the two `pad` fields are missing.)

There is a slight problem now though: we don't know at which offset the mach ports start. When a page is allocated into a zone with elements of size `x`, the first element will start at offset `0`, the second one at `x`, then `x * 2`, etc. Depending on `x`, that might leave less or more memory at the end of a page unused. To minimise such losses, XNU can expand the allocation size of a zone up to 32KB. On 10.3.3 the size of a mach port is `0xa8` bytes (`0x74` for 32-bit), and the `ipc.ports` zone makes allocations of `0x3000` bytes. That means the first port will be allocated at offset `0x0`, the second at `0xa8`, etc., and the last port on the first page will start at `0xfc0` and extend onto the second page - but that means the first port on the second page will start at offset `0x1068` rather than `0x1000`, and the same thing repeats for the third page as well. The problem with that is that when we reallocate those pages, we don't know whether they used to be the first, second or third of their chunk - even using an allocation size of `0x3000` ourselves wouldn't help, since that might as well start on a second or third page and just extend beyond it, since pages are units of their own.

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

Now we can properly reallocate it, but with what? In the end we'll probably want an `IKOT_IOKIT_CONNECT`-type port with a fake `IOUserClient` object, allowing us to call arbitrary kernel code, so at the very least we'll need to know the kernel slide. To get there, we probably want an arbitrary read primitive first, but for that we need an address to start from, and so far we don't know a single valid kernel pointer. At this point I figured I had two options:

- Leverage a kernel pointer comparison (such as with the clock system port) to brute-force the kernel slide.
- Get a valid pointer into our fake port struct somehow and read back the `OSString`.

The former sounds like a horrible idea in our setting - since we have to change `ip_kobject`, we'd have to reallocate the `OSString` over and over, each time risking the memory getting snatched by something else. The latter, however, turns our to be very viable. In the kernel's `struct ipc_port` there are a number of `struct ipc_port *` members, one of which is `ip_pdrequest`. That field can hold a pointer to a mach port which is to be notified on port death, and it can be set via `mach_port_request_notification`, provided the target port is of type `IKOT_NONE` (i.e. target is in userland) and the notification port is a send-once or receive right (from which a send-once one is then made). A very nice thing about the `mach_port` subsystem is that the mach messages are sent to the _task_ port whose IPC space contains the port, rather than to the port itself (which would cause a major headache for us with our fake port). So let's create an `IKOT_NONE` port:

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

Reference counts exist just to prevent deallocation, and `MACH_PORT_QLIMIT_KERNEL` prevents accidental sending of messages to the port. Now we can register a send-once or receive right, such as e.g. `realport` on it:

```c
mach_port_t old = MACH_PORT_NULL; // unused
mach_port_request_notification(self, fakeport, MACH_NOTIFY_PORT_DESTROYED, 0, realport, MACH_MSG_TYPE_MAKE_SEND_ONCE, &old);
```

And now we merely need to read back the `OSString` with `IOSurfaceRootUserClient`'s external method 10, look for a `kport_t` with `ip_pdrequest != 0`, and we have the kernel's address for `realport`!

Now, how do we read arbitrary memory? A previous version of my exploit used `pid_for_task` with an `IKOT_TASK`-type port and a fake task in userland. That allowed for trivial updating of the address to read from, but it also only worked on systems with a shared address space and no SMAP (i.e. A7-A9). In order for it to work on A6 and A10, the fake task would have to be put in kernel memory at a known address, which is not so straightfoward.  
First there's the problem of getting data at a known address. So far we don't know the address of anything but `realport`, whose contents are not exactly controllable. However since `fakeport` was originally allocated as a receive right, the same trick that we used to leak `realport` can again be used on `fakeport`. That doesn't just give us the address of `fakeport`, but of the entire `0x1000` `OSString` buffer it resides on! That should be enough scratch space for a fake task. :P  
But now comes the second problem: updating the address. Unless we want to leak a mere 4 bytes of kernel memory, we're gonna need to update our fake tasks `bsd_info` pointer. As with `fakeport`, the only way to do that seems via reallocation of the `OSString`. For a large number of reads, that sounds like a really bad idea. If only there was a way to just write to that memory... or is there?

Remember `ip_context`? That field you can not only read from userland, but also set, which means you can write at least as much as 8 bytes directly to a known address. With that, we could overlay our fake port and task in a way that `fakeport->ip_context` and `faketask->bsd_info` mapped to the same address - and then we could use `mach_port_set_context` to update `bsd_info`, sparing us the reallocations. However that means that if our fake port is at the very beginning of the allocation, most of the fake task's field will lie before our allocation. One such field is the reference count, which is accessed by `pid_for_task` and which might cause the fake task to be freed, something we definitely don't want. However, there is a mechanism very similar to `pid_for_task`, but with slightly different constraints: `mach_port_get_attributes`. For a `flavor` value of `MACH_PORT_DNREQUESTS_SIZE`, that will return the value `fakeport->ip_requests->ipr_size->its_size`, so long as `ip_requests` is `!= NULL`. That call can again only be made on ports for which the caller has a receive right (unlike `pid_for_task`), but instead of a `0x550` bytes large fake task struct, we only have to deal with `0x10` bytes for a fake `ip_requests`. Also `its_size` is 4 bytes wide just like the value returned by `pid_for_task`. So we can pretty much read a 32-bit `value` from an `addr` like so:

```c
mach_msg_type_number_t outsz = 1;
int value = 0;
mach_port_set_context(self, fakeport, addr);
mach_port_get_attributes(self, fakeport, MACH_PORT_DNREQUESTS_SIZE, (mach_port_info_t)&value, &outsz);
```

Now we can finally start reading from the only other kernel address we know, `realport`. Jumping from one pointer to the next, we can get a pointer back to the main kernel binary by means of: `realport->receiver->is_task->itk_registered[0]->ip_kobject->vtab`. That is, from `realport` we read the `struct ipc_space` it belongs to (`receiver`) and from that we get the `task_t` by which it is owned (`is_task`), which is our own task. Now remember how we passed the port to `IOSurfaceRootUserClient` to `mach_ports_register` in the beginning? Thanks to that, we can now read a pointer to that port from `itk_registered[0]`, from that a pointer to the `IOSurfaceRootUserClient` object itself, and from that a pointer to its C++ vtable, which is, at long last, a value from which we can derive the kernel slide.

### Kernel code execution

While our fake port is still set for reading, we can also leak most of the `IOSurfaceRootUserClient`'s vtable contents and start building a fake vtable. That will allow us to create a fake `IOUserClient` object, to which we can then stash a pointer in `fakeport->ip_kobject`, and switch the type of `fakeport` to `IKOT_IOKIT_CONNECT`. Now what we wanna do is swap out `IOUserClient::getExternalTrapForIndex` in the fake vtable with something that returns an `IOExternalTrap` whose contents we control. For that, I use a gadgets like so:

```
add x0, x0, 10
ret
```

That simply returns the address of the memory after the fake object's vtable pointer and reference count, so we can put an object and a function pointer right after those. Here we run once again into a problem though: we have two pointers that we want to update, but only one `ip_context`. So we'll have to extend our write capabilities on the `OSString` buffer before we can proceed. Now, with the knowledge of the kernel slide and the ability to read arbitrary memory, we could actually build ourselves somewhat of a kernel task port by reading the value of the `kernel_map` symbol and stashing that into the `map` field of a fake task - only that we couldn't call `vm_read` or `vm_write` on such a port unless we actually built a valid message queue on our fake port. Such a partial task port is still useful though, because as we've seen, there are some APIs that send a MIG message to some other port. One such API is the MIG call  `mach_vm_remap`. That takes a source and a target task, and lets you remap arbitrary memory from the former into the latter. Now the MIG message is sent to the target task port. That means if we wanted to remap kernel memory into our own address space, we would only need _our_ task port to have a functioning message queue! Now, since the `OSString` buffer was allocated by `zalloc`, we actually need to pass a `zone_map` port as source rather than `kernel_map`, but other than that this call works perfectly:

```c
mach_vm_address_t shmem_addr = 0;
vm_prot_t cur = 0,
          max = 0;
mach_vm_remap(self, &shmem_addr, DATA_SIZE, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR, fakeport, fake_addr, false, &cur, &max, VM_INHERIT_NONE);
```

And with that, we're done with reallocating for good. We can now edit our fake port directly, as well as anything else residing on our `OSString` buffer. We could of course also map in any other kernel address, effectively giving us complete kernel r/w. We're not gonna do that though, but instead go for an even stronger primitive: direct kernel function calls. That still gives us complete r/w via `copyin`/`copyout`, but also the ability to call long and complex functions that would be very difficult to simulate with mere r/w. To that end, we construct a fake object on our newly acquired shared memory, and switch the type of `fakeport` one last time, to `IKOT_IOKIT_CONNECT`. We can then call `iokit_user_client_trap` on `fakeport`, which will lead us to this bit in the kernel:

```c++
result = (target->*func)(args->p1, args->p2, args->p3, args->p4, args->p5, args->p6);
```

We control all of `p1` through `p6` (passed in via `iokit_user_client_trap`) as well as `target` and `func` (the two pointers after the vtab and ref count) and on top of that, `result` will be passed back to userland, albeit truncated to the 32 bits.

### tfp0

Our true goal is a kernel task port like it used to exist pre-10.3, i.e. before Apple started checking against the `kernel_task` pointer. In order to get around that check, I would ideally like to run this code in the kernel:

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

Now there are two problems with that: First, that call to `vm_map_remap` has 11 arguments but our kernel call interface allows us only to pass 7, and second that pointer returned by `ipc_port_alloc_special` is gonna have its top 32 bits cut off. Getting around the `vm_map_remap` is rather simple: we just create two new ports with fake tasks representing the `kernel_map` and the `zone_map`, and pass those to `mach_vm_remap` in userland. Getting a 64-bit return value from our kernel call interface isn't so easy though. What's easier is to take advantage of the fact that the pointer will point to somewhere in the `zone_map`, which on iOS is still far smaller than 4GB. That means if we know the base address of the `zone_map`, the lower 32 bits of a pointer are enough to determine its original value! Knowing the address of the `zone_map` struct, we merely need to read its header from offset `0x10`, and we get a `start` and `end` pointer, allowing us to do the necessary computations.

Now we just call `bzero` on `&self_task->bsd_info->p_ucred->cr_uid` with a size of `12` to elevate us to uid 0, and copy the kernel's `p_ucred->cr_label` to our own credentials to get us out of the sandbox, and we're done. :)

## Future work

### 32-bit

In principle all of this should work on 32-bit as well, but things might be different due to different pointer size. In particular the thing with the three possible page offsets might either be less or more complicated, depending on how many pages are chunked into the `ipc.ports` zone on 32-bit, and resulting from that which fields overlay in a port struct.

I lack a 32-bit device that can go higher than 9.3.5 though, so... I can offer my knowledge to devs wanting to take a stab at it, but I won't personally do it.

### ETA wen?

I don't know. I suppose this is a good time to start writing my own patchfinder (I want a _maintainable_ one), so... I guess I'll actually do that. No idea what roadblocks I'll run into though, or how long that'll take. But don't expect anything soon.

## Conclusion

Awesome bug, mad props to Ian Beer (and windknown?) for finding it! Also props to both of them for all their previous work, not sure whether we'd all be where we are today without you.

Now, lots of work to be done! If anyone wants to chip in with anything, I'm readily available on Discord (`Siguza#7111`). For updates on this as well as general iOS hacking, you can follow me on ~~Twitter~~ [Mastodon](https://mastodon.social/@siguza)

The exploit code can be found [on GitHub](https://github.com/Siguza/v0rtex).

## References

- windknown: [IOSurface UaF][blog] (PoC)
- Ian Beer: [async_wake][async_wake] (iOS 11 exploit)
- Ian Beer: [Through the mach portal][mach_portal] (write-up)

<!-- link refs -->

  [windknown]: https://twitter.com/windknown
  [ianbeer]: https://twitter.com/i41nbeer
  [blog]: http://blog.pangu.io/iosurfacerootuserclient-port-uaf/
  [mach_portal]: https://bugs.chromium.org/p/project-zero/issues/attachment?aid=280146
  [async_wake]: https://bugs.chromium.org/p/project-zero/issues/detail?id=1417#c3
