/*
 * Copyright (C) 2017 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <ctype.h>

#define MAX_ETHPORTS 32



#include "ff_config.h"
#include "ff_ini_parser.h"

#define DEFAULT_CONFIG_FILE   "config.ini"

#define BITS_PER_HEX 4

struct ff_config ff_global_cfg;


char* const short_options = "c:i:";
struct option long_options[] = {
    { "conf", 1, NULL, 'c'},
    { "interface", 1, NULL, 'i'},
    { 0, 0, 0, 0},
};

static int
xdigit2val(unsigned char c)
{
    int val;

    if (isdigit(c))
        val = c - '0';
    else if (isupper(c))
        val = c - 'A' + 10;
    else
        val = c - 'a' + 10;
    return val;
}


static int
is_integer(const char *s)
{
    if (*s == '-' || *s == '+')
        s++;
    if (*s < '0' || '9' < *s)
        return 0;
    s++;
    while ('0' <= *s && *s <= '9')
        s++;
    return (*s == '\0');
}

static int
freebsd_conf_handler(struct ff_config *cfg, const char *section,
    const char *name, const char *value)
{
    struct ff_freebsd_cfg *newconf, **cur;
    newconf = (struct ff_freebsd_cfg *)malloc(sizeof(struct ff_freebsd_cfg));
    if (newconf == NULL) {
        fprintf(stderr, "freebsd conf malloc failed\n");
        return 0;
    }

    newconf->name = strdup(name);
    newconf->str = strdup(value);

    if (strcmp(section, "boot") == 0) {
        cur = &cfg->freebsd.boot;

        newconf->value = (void *)newconf->str;
        newconf->vlen = strlen(value);
    } else if (strcmp(section, "sysctl") == 0) {
        cur = &cfg->freebsd.sysctl;

        if (is_integer(value)) {
            if (strcmp(name, "kern.ipc.maxsockbuf") == 0) {
                long *p = (long *)malloc(sizeof(long));
                *p = atol(value);
                newconf->value = (void *)p;
                newconf->vlen = sizeof(*p);
            } else {
                 int *p = (int *)malloc(sizeof(int));
                 *p = atoi(value);
                 newconf->value = (void *)p;
                 newconf->vlen = sizeof(*p);
            }
        } else {
            newconf->value = (void *)newconf->str;
            newconf->vlen = strlen(value);
        }
    } else {
        fprintf(stderr, "freebsd conf section[%s] error\n", section);
        return 0;
    }

    if (*cur == NULL) {
        newconf->next = NULL;
        *cur = newconf;
    } else {
        newconf->next = (*cur)->next;
        (*cur)->next = newconf;
    }

    return 1;
}
// A recursive binary search function. It returns location of x in
// given array arr[l..r] is present, otherwise -1
static int
uint16_binary_search(uint16_t arr[], int l, int r, uint16_t x)
{
    if (r >= l) {
        int mid = l + (r - l)/2;

        // If the element is present at the middle itself
        if (arr[mid] == x)  return mid;

        // If element is smaller than mid, then it can only be present
        // in left subarray
        if (arr[mid] > x) return uint16_binary_search(arr, l, mid-1, x);

        // Else the element can only be present in right subarray
        return uint16_binary_search(arr, mid+1, r, x);
    }

    // We reach here when element is not present in array
    return -1;
}

static int
uint16_cmp (const void * a, const void * b)
{
    return ( *(uint16_t*)a - *(uint16_t*)b );
}

static inline void
sort_uint16_array(uint16_t arr[], int n)
{
    qsort(arr, n, sizeof(uint16_t), uint16_cmp);
}

static inline char *
__strstrip(char *s)
{
    char *end = s + strlen(s) - 1;
    while(*s == ' ') s++;
    for (; end >= s; --end) {
        if (*end != ' ') break;
    }
    *(++end) = '\0';
    return s;
}

static int
port_cfg_handler(struct ff_config *cfg, const char *section,
    const char *name, const char *value) {

    if (cfg->nb_ports == 0) {
        fprintf(stderr, "port_cfg_handler: must config dpdk.port_list first\n");
        return 0;
    }

    if (cfg->port_cfgs == NULL) {
        struct ff_port_cfg *pc = calloc(MAX_ETHPORTS, sizeof(struct ff_port_cfg));
        if (pc == NULL) {
            fprintf(stderr, "port_cfg_handler malloc failed\n");
            return 0;
        }

		cfg->portid_list = malloc(sizeof(uint16_t)*MAX_ETHPORTS);
        if (cfg->portid_list == NULL) {
            fprintf(stderr, "parse_port_list malloc failed\n");
            return 0;
        }
        cfg->max_portid = cfg->portid_list[MAX_ETHPORTS-1];
        // initialize lcore list and nb_lcores
        int i;
        for (i = 0; i < cfg->nb_ports; ++i) {
            uint16_t portid = cfg->portid_list[i];

            struct ff_port_cfg *pconf = &pc[portid];
            pconf->port_id = portid;
       
        }
        cfg->port_cfgs = pc;

		
    }

    int portid;
    int ret = sscanf(section, "port%d", &portid);
    if (ret != 1) {
        fprintf(stderr, "port_cfg_handler section[%s] error\n", section);
        return 0;
    }

    /* just return true if portid >= nb_ports because it has no effect */
    if (portid > cfg->max_portid) {
        fprintf(stderr, "port_cfg_handler section[%s] bigger than max port id\n", section);
        return 1;
    }

    struct ff_port_cfg *cur = &cfg->port_cfgs[portid];
    if (cur->name == NULL) {
        cur->name = strdup(section);
        cur->port_id = portid;
    }

    if (strcmp(name, "addr") == 0) {
        cur->addr = strdup(value);
    } else if (strcmp(name, "netmask") == 0) {
        cur->netmask = strdup(value);
    } else if (strcmp(name, "broadcast") == 0) {
        cur->broadcast = strdup(value);
    } else if (strcmp(name, "gateway") == 0) {
        cur->gateway = strdup(value);
	} else if (strcmp(name, "mac") == 0) {
		set_port_mac(cur->mac,value);
    }

    return 1;
}

static int
ini_parse_handler(void* user, const char* section, const char* name,
    const char* value)
{
    struct ff_config *pconfig = (struct ff_config*)user;

    #define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
   if (strcmp(section, "freebsd.boot") == 0) {
        if (strcmp(name, "hz") == 0) {
            pconfig->freebsd.hz = atoi(value);
        } else if (strcmp(name, "physmem") == 0) {
            pconfig->freebsd.physmem = atol(value);
        } else if (strcmp(name, "fd_reserve") == 0) {
            pconfig->freebsd.fd_reserve = atoi(value);
        } else {
            return freebsd_conf_handler(pconfig, "boot", name, value);
        }
    } else if (strcmp(section, "freebsd.sysctl") == 0) {
        return freebsd_conf_handler(pconfig, "sysctl", name, value);
    } else if (strncmp(section, "port", 4) == 0) {
        return port_cfg_handler(pconfig, section, name, value);
    }

    return 1;
}


static int
ff_parse_args(struct ff_config *cfg, int argc, char *const argv[])
{
    int c;
    int index = 0;
    optind = 1;
    while((c = getopt_long(argc, argv, short_options, long_options, &index)) != -1) {
        switch (c) {
            case 'c':
                cfg->filename = strdup(optarg);
                break;
			case 'i':
                cfg->packet_bind_dev = strdup(optarg);
                break;
            default:
                return -1;
        }
    }


    return 0;
}

static int
ff_check_config(struct ff_config *cfg)
{
    #define CHECK_VALID(n) \
        do { \
            if (!pc->n) { \
                fprintf(stderr, "port%d if config error: no %s\n", \
                    pc->port_id, #n); \
                return -1; \
            } \
        } while (0)

    int i;
    for (i = 0; i < cfg->nb_ports; i++) {
        uint16_t portid = cfg->portid_list[i];
        struct ff_port_cfg *pc = &cfg->port_cfgs[portid];
        CHECK_VALID(addr);
        CHECK_VALID(netmask);
        CHECK_VALID(broadcast);
        CHECK_VALID(gateway);
  
    }

    return 0;
}

static void
ff_default_config(struct ff_config *cfg)
{
    memset(cfg, 0, sizeof(struct ff_config));

    cfg->filename = DEFAULT_CONFIG_FILE;

	cfg->nb_ports = 1;

    cfg->freebsd.hz = 100;
    cfg->freebsd.physmem = 1048576*256;
    cfg->freebsd.fd_reserve = 0;

	cfg->packet_bind_dev = "eth0";
}

int
ff_load_config(int argc, char *const argv[])
{
    ff_default_config(&ff_global_cfg);

    int ret = ff_parse_args(&ff_global_cfg, argc, argv);
    if (ret < 0) {
        return ret;
    }

    ret = ini_parse(ff_global_cfg.filename, ini_parse_handler,
        &ff_global_cfg);
    if (ret != 0) {
        printf("parse %s failed on line %d\n", ff_global_cfg.filename, ret);
        return -1;
    }

    if (ff_check_config(&ff_global_cfg)) {
        return -1;
    }

    return 0;
}
