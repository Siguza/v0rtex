#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>             // uint*_t
#include <Foundation/Foundation.h>

#define LOG(str, args...) do { NSLog(@str "\n", ##args); } while(0)
#ifdef __LP64__
#   define ADDR "0x%016llx"
    typedef uint64_t kptr_t;
#else
#   define ADDR "0x%08x"
    typedef uint32_t kptr_t;
#endif

#endif
