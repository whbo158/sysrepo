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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>

#include "sysrepo.h"
#include "sysrepo/xpath.h"

volatile int exit_application = 0;

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

#define XPATH_MAX_LEN		300
#define IF_NAME_MAX_LEN		20
#define NODE_NAME_MAX_LEN	80
#define MSG_MAX_LEN		100

#define IF_XPATH "/ietf-interfaces:interfaces/interface"
#define BRIDGE_XPATH "/ieee802-dot1q-bridge:bridges/bridge"
#define BRIDGE_COMPONENT_XPATH (BRIDGE_XPATH "/component")

#define QBV_GATE_PARA_XPATH "/ieee802-dot1q-sched:gate-parameters"
#define QBV_MAX_SDU_XPATH "/ieee802-dot1q-sched:max-sdu-table"
#define IETFIP_MODULE_NAME "ietf-ip"

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
	char xpath[XPATH_MAX_LEN] = {0,};
	char err_msg[MSG_MAX_LEN] = {0};

	rc = sr_get_changes_iter(session, "//.", &it);
	if (rc != SR_ERR_OK) {
		snprintf(err_msg, MSG_MAX_LEN,
			 "Get changes from %s failed", path);
		sr_set_error(session, err_msg, path);

		printf("ERROR: %s sr_get_changes_iter: %s\n", __func__,
		       sr_strerror(rc));
		goto cleanup;
	}
printf("XPATH:%s\n", path);
	while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
					&oper, &old_value, &new_value))) {

		print_change(oper, old_value, new_value);

		value = new_value ? new_value : old_value;
		ifname = sr_xpath_key_value(value->xpath, "interface",
					    "name", &xp_ctx);
printf("IFNAME:%s\n", ifname);

        sr_free_val(old_value);
        sr_free_val(new_value);
		continue;

		if (!ifname)
			continue;

		if (strcmp(ifname, ifname_bak)) {
			snprintf(ifname_bak, IF_NAME_MAX_LEN, ifname);
			snprintf(xpath, XPATH_MAX_LEN,
				 "%s[name='%s']/%s:*//*", IF_XPATH, ifname,
				 IETFIP_MODULE_NAME);

			printf("SUBXPATH:%s\n", path);
			//rc = config_qbv_per_port(session, xpath, abort, ifname);
			if (rc != SR_ERR_OK)
				break;
		}
	}
	if (rc == SR_ERR_NOT_FOUND)
		rc = SR_ERR_OK;
cleanup:
	return rc;
}

int inet_subtree_change_cb(sr_session_ctx_t *session, const char *module_name, const char *path,
		sr_event_t event, void *private_ctx)
{
	int rc = SR_ERR_OK;
	char xpath[XPATH_MAX_LEN] = {0,};

	printf("INET mod:%s path:%s event:%d\n", module_name, path, event);

	snprintf(xpath, XPATH_MAX_LEN, "%s:*//*", path);
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
    xpath = "/ietf-interfaces:interfaces/interface";
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

