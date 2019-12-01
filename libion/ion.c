/*
 *  ion.c
 *
 * Memory Allocator functions for ion
 *
 *   Copyright 2011 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
#define LOG_TAG "ion"

#include <cutils/log.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <linux/ion.h>
#include <linux/mtk_ion.h>
#include <libion_mtk/ion.h>
#include <linux/ion_drv.h>
#include <ion/ion.h>
#include <string.h>

int ion_open()
{
    int fd = open("/dev/ion", O_RDWR);
    if (fd < 0)
        ALOGE("open /dev/ion failed!\n");
    return fd;
}

int ion_close(int fd)
{
    int ret = close(fd);
    if (ret < 0)
        return -errno;
    return ret;
}

static int ion_ioctl(int fd, int req, void *arg)
{
    int ret = ioctl(fd, req, arg);
    if (ret < 0) {
        ALOGE("ioctl %x failed with code %d: %s\n", req,
              ret, strerror(errno));
        return -errno;
    }
    return ret;
}

int ion_alloc(int fd, size_t len, size_t align, unsigned int heap_mask,
              unsigned int flags, ion_user_handle_t *handle)
{
    int ret;
    struct ion_allocation_data data = {
        .len = len,
        .align = align,
        .heap_id_mask = heap_mask,
        .flags = flags,
    };

    if (handle == NULL)
        return -EINVAL;

    ret = ion_ioctl(fd, ION_IOC_ALLOC, &data);
    if (ret < 0)
        return ret;
    *handle = data.handle;
    return ret;
}

int ion_free(int fd, ion_user_handle_t handle)
{
    struct ion_handle_data data = {
        .handle = handle,
    };
    return ion_ioctl(fd, ION_IOC_FREE, &data);
}

int ion_map(int fd, ion_user_handle_t handle, size_t length, int prot,
            int flags, off_t offset, unsigned char **ptr, int *map_fd)
{
    int ret;
    struct ion_fd_data data = {
        .handle = handle,
    };

    if (map_fd == NULL)
        return -EINVAL;
    if (ptr == NULL)
        return -EINVAL;

    ret = ion_ioctl(fd, ION_IOC_MAP, &data);
    if (ret < 0)
        return ret;
    *map_fd = data.fd;
    if (*map_fd < 0) {
        ALOGE("map ioctl returned negative fd\n");
        return -EINVAL;
    }
    *ptr = mmap(NULL, length, prot, flags, *map_fd, offset);
    if (*ptr == MAP_FAILED) {
        ALOGE("mmap failed: %s\n", strerror(errno));
        return -errno;
    }
    return ret;
}

int ion_share(int fd, ion_user_handle_t handle, int *share_fd)
{
    int map_fd;
    int ret;
    struct ion_fd_data data = {
        .handle = handle,
    };

    if (share_fd == NULL)
        return -EINVAL;

    ret = ion_ioctl(fd, ION_IOC_SHARE, &data);
    if (ret < 0)
        return ret;
    *share_fd = data.fd;
    if (*share_fd < 0) {
        ALOGE("share ioctl returned negative fd\n");
        return -EINVAL;
    }
    return ret;
}

int ion_alloc_fd(int fd, size_t len, size_t align, unsigned int heap_mask,
                 unsigned int flags, int *handle_fd) {
    ion_user_handle_t handle;
    int ret;

    ret = ion_alloc(fd, len, align, heap_mask, flags, &handle);
    if (ret < 0)
        return ret;
    ret = ion_share(fd, handle, handle_fd);
    ion_free(fd, handle);
    return ret;
}

int ion_import(int fd, int share_fd, ion_user_handle_t *handle)
{
    int ret;
    struct ion_fd_data data = {
        .fd = share_fd,
    };

    if (handle == NULL)
        return -EINVAL;

    ret = ion_ioctl(fd, ION_IOC_IMPORT, &data);
    if (ret < 0)
        return ret;
    *handle = data.handle;
    return ret;
}

int ion_sync_fd(int fd, int handle_fd)
{
    struct ion_fd_data data = {
        .fd = handle_fd,
    };
    return ion_ioctl(fd, ION_IOC_SYNC, &data);
}

static int ion_set_client_name(int ion_fd, const char *name)
{
    int ret;
    ion_sys_data_t sys_data;

    sys_data.sys_cmd = ION_SYS_SET_CLIENT_NAME;

    strncpy(sys_data.client_name_param.name, name, sizeof(sys_data.client_name_param.name)-1);

    if(ion_custom_ioctl(ion_fd, ION_CMD_SYSTEM, &sys_data))
    {
        //config error
        ALOGE("[ion_dbg] ion_set_client_name error\n");
        return -1;
    }

    return 0;
}

int mt_ion_open(const char *name)
{
    int fd;
    fd = ion_open();
    if(fd < 0)
    {
        ALOGE("ion_open failed! name=%s\n", name);
        return fd;
    }

    ion_set_client_name(fd, name);
    return fd;
}

int ion_alloc_mm(int fd, size_t len, size_t align, unsigned int flags,
              ion_user_handle_t *handle)
{

        return ion_alloc(fd, len, align, ION_HEAP_MULTIMEDIA_MASK, flags, handle);
}

int ion_alloc_syscontig(int fd, size_t len, size_t align, unsigned int flags, ion_user_handle_t *handle)
{

        return ion_alloc(fd, len, align, ION_HEAP_SYSTEM_CONTIG_MASK, flags, handle);
}

void* ion_mmap(int fd, void *addr, size_t length, int prot, int flags, int share_fd, off_t offset)
{
    void *mapping_address = NULL;

    mapping_address =  mmap(addr, length, prot, flags, share_fd, offset);

    if (mapping_address == MAP_FAILED) {
        ALOGE("ion_mmap failed fd = %d, addr = 0x%p, len = %zu, prot = %d, flags = %d, share_fd = %d, 0x%p: %s\n", fd, addr, length,
              prot, flags, share_fd, mapping_address, strerror(errno));
    }

    return mapping_address;
}

int ion_munmap(int fd, void *addr, size_t length)
{
    int ret = munmap(addr, length);

    if (ret < 0) {
        ALOGE("ion_munmap failed fd = %d, addr = 0x%p, len = %zu, %d: %s\n", fd, addr, length,
              ret, strerror(errno));
    }
    return ret;
}

int ion_share_close(int fd, int share_fd)
{
    int ret = close(share_fd);
    if (ret < 0) {
        ALOGE("ion_share_close failed fd = %d, share_fd = %d, %d: %s\n", fd, share_fd,
              ret, strerror(errno));
    }
    return ret;
}

int ion_custom_ioctl(int fd, unsigned int cmd, void* arg)
{
    struct ion_custom_data custom_data;
    custom_data.cmd = cmd;
    custom_data.arg = (unsigned long) arg;

    int ret = ioctl(fd, ION_IOC_CUSTOM, &custom_data);
    if (ret < 0) {
        ALOGE("ion_custom_ioctl %x failed with code %d: %s\n", ION_IOC_CUSTOM,
              ret, strerror(errno));
        return -errno;
    }
    return ret;
}

