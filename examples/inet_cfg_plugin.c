/**
 * @file application_changes_example.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief example of an application handling changes
 *
 * @copyright
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _GNU_SOURCE

#include <inttypes.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netdb.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/if_vlan.h>
#include <linux/sockios.h>

#include "sysrepo.h"
#include "sysrepo/xpath.h"

#define XPATH_MAX_LEN		300
#define IF_NAME_MAX_LEN		20
#define NODE_NAME_MAX_LEN	80
#define MSG_MAX_LEN		100

#define IF_XPATH "/ietf-interfaces:interfaces/interface"
#define BRIDGE_XPATH "/ieee802-dot1q-bridge:bridges/bridge"
#define BRIDGE_COMPONENT_XPATH (BRIDGE_XPATH "/component")
#define IPV4_XPATH ("/ietf-ip:ipv4")

#define QBV_GATE_PARA_XPATH "/ieee802-dot1q-sched:gate-parameters"
#define QBV_MAX_SDU_XPATH "/ieee802-dot1q-sched:max-sdu-table"
#define IETFIP_MODULE_NAME "ietf-ip"

#define PRINT printf("%s-%d: ", __func__, __LINE__);printf
#define ADDR_LEN (sizeof(struct in_addr))

volatile int exit_application = 0;

typedef unsigned char uint8;
struct inet_cfg
{
	struct in_addr ip;
	struct in_addr mask;
	char ifname[IF_NAME_MAX_LEN + 1];
};

static struct inet_cfg sinet_conf;

static void
print_val(const sr_val_t *value)
{
    if (NULL == value) {
        return;
    }

    printf("XPATH:-%s-\n", value->xpath);

    switch (value->type) {
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
        printf("(container)");
        break;
    case SR_LIST_T:
        printf("(list instance)");
        break;
    case SR_STRING_T:
        printf("= %s", value->data.string_val);
        break;
    case SR_BOOL_T:
        printf("= %s", value->data.bool_val ? "true" : "false");
        break;
    case SR_DECIMAL64_T:
        printf("= %g", value->data.decimal64_val);
        break;
    case SR_INT8_T:
        printf("= %" PRId8, value->data.int8_val);
        break;
    case SR_INT16_T:
        printf("= %" PRId16, value->data.int16_val);
        break;
    case SR_INT32_T:
        printf("= %" PRId32, value->data.int32_val);
        break;
    case SR_INT64_T:
        printf("= %" PRId64, value->data.int64_val);
        break;
    case SR_UINT8_T:
        printf("= %" PRIu8, value->data.uint8_val);
        break;
    case SR_UINT16_T:
        printf("= %" PRIu16, value->data.uint16_val);
        break;
    case SR_UINT32_T:
        printf("= %" PRIu32, value->data.uint32_val);
        break;
    case SR_UINT64_T:
        printf("= %" PRIu64, value->data.uint64_val);
        break;
    case SR_IDENTITYREF_T:
        printf("= %s", value->data.identityref_val);
        break;
    case SR_INSTANCEID_T:
        printf("= %s", value->data.instanceid_val);
        break;
    case SR_BITS_T:
        printf("= %s", value->data.bits_val);
        break;
    case SR_BINARY_T:
        printf("= %s", value->data.binary_val);
        break;
    case SR_ENUM_T:
        printf("= %s", value->data.enum_val);
        break;
    case SR_LEAF_EMPTY_T:
        printf("(empty leaf)");
        break;
    default:
        printf("(unprintable)");
        break;
    }

    switch (value->type) {
    case SR_UNKNOWN_T:
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
    case SR_LIST_T:
    case SR_LEAF_EMPTY_T:
        printf("\n");
        break;
    default:
        printf("%s\n", value->dflt ? " [default]" : "");
        break;
    }
}

static void
print_change(sr_change_oper_t op, sr_val_t *old_val, sr_val_t *new_val)
{
    switch(op) {
    case SR_OP_CREATED:
        printf("CREATED: ");
        print_val(new_val);
        break;
    case SR_OP_DELETED:
        printf("DELETED: ");
        print_val(old_val);
        break;
    case SR_OP_MODIFIED:
        printf("MODIFIED: ");
        print_val(old_val);
        printf("to ");
        print_val(new_val);
        break;
    case SR_OP_MOVED:
        printf("MOVED: %s\n", new_val->xpath);
        break;
    }
}

static void
print_current_config(sr_session_ctx_t *session, const char *module_name)
{
    sr_val_t *values = NULL;
    size_t count = 0;
    int rc = SR_ERR_OK;
    char *xpath;

    asprintf(&xpath, "/%s:*//.", module_name);

    rc = sr_get_items(session, xpath, 0, &values, &count);
    free(xpath);
    if (rc != SR_ERR_OK) {
        return;
    }

    for (size_t i = 0; i < count; i++){
		printf("val%ld ", i);
        print_val(&values[i]);
    }
    sr_free_values(values, count);
}

const char *
ev_to_str(sr_event_t ev)
{
    switch (ev) {
    case SR_EV_CHANGE:
        return "change";
    case SR_EV_DONE:
        return "done";
    case SR_EV_ABORT:
    default:
        return "abort";
    }
}

static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data)
{
    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;

    (void)xpath;
    (void)request_id;
    (void)private_data;

    printf("\n\n ========== EVENT %s CHANGES: ====================================\n\n", ev_to_str(event));

    rc = sr_get_changes_iter(session, "//." , &it);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    while ((rc = sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {
        print_change(oper, old_value, new_value);
        sr_free_val(old_value);
        sr_free_val(new_value);
    }

    printf("\n ========== END OF CHANGES =======================================");

    if (event == SR_EV_DONE) {
        printf("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n\n");
        print_current_config(session, module_name);
    }

cleanup:
    sr_free_change_iter(it);
    return SR_ERR_OK;
}

static int set_inet_cfg(char *ifname, int req, void *buf, int len)
{
	int ret = 0;
	int sockfd = 0;
	struct ifreq ifr = {0};
	struct sockaddr_in *sin = NULL;

	if (!ifname || !buf)
		return -1;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
	{
		PRINT("create socket failed! ret:%d\n", sockfd);
		return -2;
	}

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);

	ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		PRINT("get interface %s flag failed! ret:%d\n", ifname, ret);
		return -3;
	}

	if (req == SIOCSIFHWADDR) {
		memcpy(&ifr.ifr_ifru.ifru_hwaddr.sa_data, buf, len);
		ifr.ifr_addr.sa_family = ARPHRD_ETHER;
	} else {
		sin = (struct sockaddr_in *)&ifr.ifr_addr;
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, (struct in_addr *)buf, len);
	}

	ret = ioctl(sockfd, req, &ifr);
	close(sockfd);
	if (ret < 0) {
		PRINT("ioctl error! ret:%d, need root account!\n", ret);
		PRINT("Note: this operation needs root permission!\n");
		return -4;
	}

	return 0;
}

int set_inet_ip(char *ifname, struct in_addr *ip)
{
	return set_inet_cfg(ifname, SIOCSIFADDR, ip, ADDR_LEN);
}

int set_inet_mask(char *ifname, struct in_addr *mask)
{
	return set_inet_cfg(ifname, SIOCSIFNETMASK, mask, ADDR_LEN);
}

int set_inet_mac(char *ifname, uint8 *buf, int len)
{
	return set_inet_cfg(ifname, SIOCSIFHWADDR, buf, len);
}

static int set_inet_updown(char *ifname, bool upflag)
{
	int ret = 0;
	int sockfd = 0;
	struct ifreq ifr = {0};
	struct sockaddr_in *sin = NULL;

	if (!ifname)
		return -1;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
	{
		PRINT("create socket failed! ret:%d\n", sockfd);
		return -2;
	}

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);

	ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		PRINT("get interface flag failed! ret:%d\n", ret);
		return -3;
	}

	sin = (struct sockaddr_in *)&ifr.ifr_addr;
	sin->sin_family = AF_INET;

	if (upflag)
		ifr.ifr_flags |= IFF_UP;
	else
		ifr.ifr_flags &= ~IFF_UP;

	ret = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
	close(sockfd);
	if (ret < 0) {
		PRINT("ioctl error! ret:%d, need root account!\n", ret);
		PRINT("Note: this operation needs root permission!\n");
		return -4;
	}

	return 0;
}

bool is_valid_addr(uint8 *ip)
{
	int ret = 0;
	struct in_addr ip_addr;

	if (!ip)
	      return false;

	ret = inet_aton(ip, &ip_addr);
	if (0 == ret)
		return false;

	return true;
}

static bool is_del_oper(sr_session_ctx_t *session, char *path)
{
	int rc = SR_ERR_OK;
	bool ret = false;
	sr_change_oper_t oper;
	sr_val_t *old_value;
	sr_val_t *new_value;
	sr_change_iter_t *it;
	char err_msg[MSG_MAX_LEN] = {0};

	rc = sr_get_changes_iter(session, path, &it);
	if (rc != SR_ERR_OK) {
		snprintf(err_msg, MSG_MAX_LEN, "Get changes from %s failed",
			 path);
		sr_set_error(session, err_msg, path);
		printf("ERROR: Get changes from %s failed\n", path);
		return false;
	}

	rc = sr_get_change_next(session, it, &oper, &old_value, &new_value);
	sr_free_val(old_value);
	sr_free_val(new_value);

	if (rc == SR_ERR_NOT_FOUND)
		ret = false;
	else if (oper == SR_OP_DELETED)
		ret = true;
	return ret;
}

int parse_inet(sr_session_ctx_t *session, sr_val_t *value, struct inet_cfg *conf)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	char *index = NULL;
	uint8_t u8_val = 0;
	uint32_t u32_val = 0;
	uint64_t u64_val = 0;
	char *nodename = NULL;
	char err_msg[MSG_MAX_LEN] = {0};
	char *strval = NULL;

	if (!session || !value || !conf)
		return rc;

	strval = value->data.string_val;

	sr_xpath_recover(&xp_ctx);
	nodename = sr_xpath_node_name(value->xpath);
	if (!nodename)
		goto out;
printf("WHB nodename:%s type:%d\n", nodename, value->type);

	if (!strcmp(nodename, "ip")) {
		if (is_valid_addr(strval)) {
			conf->ip.s_addr = inet_addr(strval);
			printf("\nVALID ip= %s\n", strval);
		}
	} else if (!strcmp(nodename, "netmask")) {
		if (is_valid_addr(strval)) {
			conf->mask.s_addr = inet_addr(strval);
			printf("\nVALID netmask = %s\n", strval);
		}
	}

out:
	return rc;
}
static int config_inet_per_port(sr_session_ctx_t *session, char *path, bool abort,
		char *ifname)
{
	int rc = SR_ERR_OK;
	sr_val_t *values;
	size_t count;
	size_t i;
	int valid = 0;
	char err_msg[MSG_MAX_LEN] = {0};
	struct inet_cfg *conf = &sinet_conf;

printf("IFNAME00:%s--len:%d\n", ifname, strlen(ifname));
	memset(conf, 0, sizeof(struct inet_cfg));
	snprintf(conf->ifname, IF_NAME_MAX_LEN, "%s", ifname);
printf("IFNAME11:%s--%s len:%d\n", ifname, conf->ifname, strlen(ifname));

	rc = sr_get_items(session, path, 0, &values, &count);
	if (rc == SR_ERR_NOT_FOUND) {
		/*
		 * If can't find any item, we should check whether this
		 * container was deleted.
		 */
		if (is_del_oper(session, path)) {
			printf("WARN: %s was deleted, disable %s",
			       path, "this Instance.\n");
			goto cleanup;
		} else {
			printf("WARN: %s sr_get_items: %s\n", __func__,
			       sr_strerror(rc));
			return SR_ERR_OK;
		}
	} else if (rc != SR_ERR_OK) {
		snprintf(err_msg, MSG_MAX_LEN,
			 "Get items from %s failed", path);
		sr_set_error(session, err_msg, path);

		printf("ERROR: %s sr_get_items: %s\n", __func__,
		       sr_strerror(rc));
		return rc;
	}

printf("CUR COUNT:%d\n", count);
	for (i = 0; i < count; i++) {
		if (values[i].type == SR_LIST_T
		    || values[i].type == SR_CONTAINER_PRESENCE_T)
			continue;

		if (!parse_inet(session, &values[i], conf))
			valid++;
	}

	if (!valid)
		goto cleanup;

cleanup:
    sr_free_values(values, count);

	return rc;
}

int inet_config(sr_session_ctx_t *session, const char *path, bool abort)
{
	int rc = SR_ERR_OK;
	sr_xpath_ctx_t xp_ctx = {0};
	sr_change_iter_t *it;
	sr_val_t *old_value;
	sr_val_t *new_value;
	sr_val_t *value;
	sr_change_oper_t oper;
	char *ifname;
	char ifname_bak[IF_NAME_MAX_LEN] = {0,};
	char xpath[XPATH_MAX_LEN] = {0};
	char err_msg[MSG_MAX_LEN] = {0};
	struct inet_cfg *conf = &sinet_conf;

	memset(conf, 0, sizeof(struct inet_cfg));

	snprintf(xpath, XPATH_MAX_LEN, "%s//*", path);
	rc = sr_get_changes_iter(session, xpath, &it);
	if (rc != SR_ERR_OK) {
		snprintf(err_msg, MSG_MAX_LEN,
			 "Get changes from %s failed", path);
		sr_set_error(session, err_msg, path);

		printf("ERROR: %s sr_get_changes_iter: %s\n", __func__,
		       sr_strerror(rc));
		goto cleanup;
	}
printf("XPATH:%s\n", xpath);
	while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
					&oper, &old_value, &new_value))) {

		//print_change(oper, old_value, new_value);

		value = new_value ? new_value : old_value;
		ifname = sr_xpath_key_value(value->xpath, "interface",
					    "name", &xp_ctx);
printf("IFNAME:%s\n", ifname);

		sr_free_val(old_value);
		sr_free_val(new_value);

		if (!ifname)
			continue;

		if (strcmp(ifname, ifname_bak)) {
			snprintf(ifname_bak, IF_NAME_MAX_LEN, "%s", ifname);
			snprintf(xpath, XPATH_MAX_LEN,
				 "%s[name='%s']/%s:*//*", IF_XPATH, ifname,
				 IETFIP_MODULE_NAME);

			printf("SUBXPATH:%s ifname:%s len:%d\n", xpath, ifname, strlen(ifname));
			rc = config_inet_per_port(session, xpath, abort, ifname);
			if (rc != SR_ERR_OK)
				break;
		}
	}
	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;

	if (conf->ip.s_addr) {
		set_inet_ip(conf->ifname, &conf->ip);
	}

	if (conf->mask.s_addr) {
		set_inet_mask(conf->ifname, &conf->mask);
	}

cleanup:
	return rc;
}

int inet_subtree_change_cb(sr_session_ctx_t *session, const char *module_name, const char *path,
		sr_event_t event, void *private_ctx)
{
	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0,};

	printf("INET mod:%s path:%s event:%d\n", module_name, path, event);

	snprintf(xpath, XPATH_MAX_LEN, "%s", path);
//	snprintf(xpath, XPATH_MAX_LEN, "%s/%s:*//*", IF_XPATH,
//		 IETFIP_MODULE_NAME);

	switch (event) {
	case SR_EV_CHANGE:
		if (rc)
			goto out;
		rc = inet_config(session, xpath, false);
		break;
	case SR_EV_ENABLED:
		rc = inet_config(session, xpath, false);
		break;
	case SR_EV_DONE:
		break;
	case SR_EV_ABORT:
		rc = inet_config(session, xpath, true);
		break;
	default:
		break;
	}
out:
	return rc;
}

static void
sigint_handler(int signum)
{
    (void)signum;

    exit_application = 1;
}

int
main(int argc, char **argv)
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;
    char path[XPATH_MAX_LEN];
    const char *mod_name, *xpath = NULL;
#if 0
    if ((argc < 2) || (argc > 3)) {
        printf("%s <module-to-subscribe> [<xpath-to-subscribe>]\n", argv[0]);
        return EXIT_FAILURE;
    }
    mod_name = argv[1];
    if (argc == 3) {
        xpath = argv[2];
    }
#else
    mod_name = "ietf-interfaces";
	snprintf(path, XPATH_MAX_LEN, "%s", IF_XPATH);
	strncat(path, IPV4_XPATH, XPATH_MAX_LEN - 1 - strlen(path));
	xpath = path;
#endif
    printf("Application will watch for changes in \"%s\".\n", xpath ? xpath : mod_name);

    /* turn logging on */
    sr_log_stderr(SR_LL_WRN);

    /* connect to sysrepo */
    rc = sr_connect(0, &connection);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* start session */
    rc = sr_session_start(connection, SR_DS_RUNNING, &session);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* read current config */
    printf("\n ========== READING RUNNING CONFIG: ==========\n\n");
    print_current_config(session, mod_name);

    /* subscribe for changes in running config */
    //rc = sr_module_change_subscribe(session, mod_name, xpath, module_change_cb, NULL, 0, 0, &subscription);
    rc = sr_module_change_subscribe(session, mod_name, xpath, inet_subtree_change_cb, NULL, 0, 0, &subscription);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    printf("\n\n ========== LISTENING FOR CHANGES ==========\n\n");

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    while (!exit_application) {
        sleep(1000);
    }

    printf("Application exit requested, exiting.\n");

cleanup:
    sr_disconnect(connection);
    return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}

