/*******************************************************************
 * Pidgin KeePass Password Plugin
 * Copyright(C) 2016, Adam Delman <flyn@flyn.cc>
 *******************************************************************/

#ifndef PURPLE_PLUGINS
# define PURPLE_PLUGINS
#endif

#include <stdbool.h>
#include <string.h>
#include <libsoup/soup.h>
#include "json-c/json.h"
#include <libpurple/plugin.h>
#include <libpurple/notify.h>
#include <libpurple/version.h>
#include "config.h"

PurplePlugin *keepass_plugin = NULL; //A handle to our plugin - will be initiated in plugin_load().
SoupSession *session = NULL;
#define PLUGIN_ID "keepasshttp"
#define PREF_PREFIX     "/plugins/gtk/" PLUGIN_ID
#define PREF_KEEPASS_HOST_PATH        PREF_PREFIX "/keepass_host"
#define PREF_KEEPASS_PORT_PATH      PREF_PREFIX "/keepass_port"
#define PREF_KEEPASS_HOST_LABEL "KeePass Host"
#define PREF_KEEPASS_PORT_LABEL "KeePass Port"

#define MAX_URL_LENGTH 300

static char *const RequestType_key = "RequestType";
static char *const test_associate_request_type = "test-associate";
static char *const TriggerUnlock_key = "TriggerUnlock";

//static const char *key_for_account(PurpleAccount *account) {
//    static char key[1024];
//
//    sprintf(key, "%s:%s", purple_account_get_protocol_id(account),
//            purple_account_get_username(account));
//    return key;
//}

//static void store_password(PurpleAccount *account) {
//    int wallet = open_wallet(FALSE);
//    if (wallet >= 0) {
//        if (write_password(wallet, key_for_account(account),
//                           purple_account_get_password(account))) {
//            /* KWallet has the password now - so accounts.xml can forget it. */
//            purple_account_set_remember_password(account, FALSE);
//        } else
//            purple_notify_message(keepass_plugin, PURPLE_NOTIFY_MSG_ERROR,
//                                  "KeePass Error", "Could not save password in KeePass.",
//                                  NULL, NULL, NULL);
//    }
//}

static char *const json_mime_type = "application/json";

static char *get_keepass_url() {
    const char *keepass_host = purple_prefs_get_string(PREF_KEEPASS_HOST_PATH);
    const int keepass_port = purple_prefs_get_int(PREF_KEEPASS_PORT_PATH);
    static char url_string[MAX_URL_LENGTH];
    snprintf(url_string, MAX_URL_LENGTH, "http://%s:%d", keepass_host, keepass_port);
    return url_string;
}

static void perform_http(char *method, char *body) {

}

static void keepass_http_test_associate() {
    struct json_object *test_associate_msg = json_object_new_object();
    json_object_object_add(test_associate_msg, RequestType_key, json_object_new_string(test_associate_request_type));
    json_object_object_add(test_associate_msg, TriggerUnlock_key, json_object_new_boolean(false));
    const char *body = json_object_to_json_string(test_associate_msg);

    SoupMessage *msg = soup_message_new("POST", get_keepass_url());

    soup_message_set_request(msg, json_mime_type,
                             SOUP_MEMORY_COPY, body, strlen(body));
//    soup_message_headers_append(msg->request_headers, "Content-Type:", json_mime_type);
    soup_session_send_message(session, msg);

}
//
//static void encrypt_password(gpointer data, gpointer user_data) {
//    PurpleAccount *account = (PurpleAccount *) data;
//
//    /* Only save passwords for accounts that are remembering passwords in accounts.xml. */
//    if (purple_account_get_remember_password(account))
//        store_password(account);
//}
//
//static void fetch_password(gpointer data, gpointer user_data) {
//    PurpleAccount *account = (PurpleAccount *) data;
//
//    /* Only fetch passwords for accounts that are not remembering passwords in accounts.xml. */
//    if (!purple_account_get_remember_password(account)) {
//        int wallet = open_wallet(FALSE);
//        if (wallet >= 0) {
//            char *password = read_password(wallet, key_for_account(account));
//            if (!password)
//                return; // Don't print an error here - it could just be that the password isn't saved.
//            purple_account_set_password(account, password);
//            g_free(password);
//        }
//    }
//}
//
//static void decrypt_password(gpointer data, gpointer user_data) {
//    PurpleAccount *account = (PurpleAccount *) data;
//
//    /* Only decrypt passwords for accounts that are not remembering passwords in accounts.xml. */
//    if (!purple_account_get_remember_password(account)) {
//        int wallet = open_wallet(FALSE);
//        if (wallet >= 0) {
//            const char *key = key_for_account(account);
//            char *password = read_password(wallet, key);
//            if (!password)
//                return; // Don't print an error here - it could just be that the password isn't saved.
//            purple_account_set_password(account, password);
//            purple_account_set_remember_password(account, true);
//            remove_entry(wallet, key);
//            g_free(password);
//        }
//    }
//}
//
//static void encrypt_all_passwords(PurplePluginAction *action) {
//    GList *accounts = purple_accounts_get_all();
//    g_list_foreach(accounts, encrypt_password, NULL);
//    // You cannot g_list_free(accounts) here without segfaulting Pidgin.
//    purple_notify_message(keepass_plugin, PURPLE_NOTIFY_MSG_INFO,
//                          "KeePass Password", "All saved passwords are now in KeePass.",
//                          NULL, NULL, NULL);
//}
//
//static void decrypt_all_passwords(PurplePluginAction *action) {
//    GList *accounts = purple_accounts_get_all();
//    g_list_foreach(accounts, decrypt_password, NULL);
//    // You cannot g_list_free(accounts) here without segfaulting Pidgin.
//    purple_notify_message(keepass_plugin, PURPLE_NOTIFY_MSG_INFO,
//                          "KeePass Password",
//                          "All saved passwords are now in accounts.xml as plain text.", NULL,
//                          NULL, NULL);
//}
//
//static void account_added(gpointer data, gpointer user_data) {
//    store_password((PurpleAccount *) data);
//}
//
//static void account_removed(gpointer data, gpointer user_data) {
//    PurpleAccount *account = (PurpleAccount *) data;
//    int wallet = open_wallet(true);
//
//    if (wallet >= 0) {
//        const char *key = key_for_account(account);
//        char *password = read_password(wallet, key);
//
//        if (password) {
//            remove_entry(wallet, key);
//            g_free(password);
//        }
//    }
//}

static PurplePluginPrefFrame *
get_plugin_pref_frame(PurplePlugin *plugin) {
    PurplePluginPrefFrame *frame;
    PurplePluginPref *pref;

    frame = purple_plugin_pref_frame_new();

    pref = purple_plugin_pref_new_with_label(("KeePass Preferences"));
    purple_plugin_pref_frame_add(frame, pref);

    pref = purple_plugin_pref_new_with_name_and_label(PREF_KEEPASS_HOST_PATH, PREF_KEEPASS_HOST_LABEL);
    purple_plugin_pref_frame_add(frame, pref);

    pref = purple_plugin_pref_new_with_name_and_label(PREF_KEEPASS_PORT_PATH, PREF_KEEPASS_PORT_LABEL);
    purple_plugin_pref_frame_add(frame, pref);

    return frame;
}

static PurplePluginUiInfo prefs_info = {
        get_plugin_pref_frame,
        0,
        NULL,

        /* padding */
        NULL,
        NULL,
        NULL,
        NULL
};


//static void account_changed(gpointer data, gpointer user_data) {
//    char *password;
//    // TODO: Is there a way to detect when an account has changed?????
//    PurpleAccount *account = (PurpleAccount *) data;
//    printf("Account changed: %s -> %s\n", key_for_account(account),
//           password ? password : "<>");
//
//    //store_password((PurpleAccount*)data);
//}

/* Register plugin actions */
static GList *plugin_actions(PurplePlugin *plugin, gpointer context) {
    GList *list = NULL; // The action list.
//    PurplePluginAction *action = NULL; // A action temp pointer.
//
//    action = purple_plugin_action_new("Encrypt Passwords",
//                                      encrypt_all_passwords);
//    list = g_list_append(list, action);
//    action = purple_plugin_action_new("Decrypt Passwords",
//                                      decrypt_all_passwords);
//    list = g_list_append(list, action);

    return list;
}

/* Called when the plugin loads(after plugin_init()) */
static gboolean plugin_load(PurplePlugin *plugin) {
    keepass_plugin = plugin; /* assign this here so we have a valid handle later */

//    /* Set the passwords for the accounts before they try to connect. */
//    GList *accounts = NULL;
//    accounts = purple_accounts_get_all();
//    g_list_foreach(accounts, fetch_password, NULL);
//    // You cannot g_list_free(accounts) here without segfaulting Pidgin.
//
//    void *accounts_handle = purple_accounts_get_handle();
//    purple_signal_connect(accounts_handle, "account-added", plugin,
//                          PURPLE_CALLBACK(account_added), NULL);
//    purple_signal_connect(accounts_handle, "account-removed", plugin,
//                          PURPLE_CALLBACK(account_removed), NULL);
//    purple_signal_connect(accounts_handle, "account-set-info", plugin,
//                          PURPLE_CALLBACK(account_changed), NULL);
    return TRUE;
}

/* For specific notes on the meanings of each of these members, consult the C Plugin Howto on the website. */
static PurplePluginInfo info = {
        PURPLE_PLUGIN_MAGIC,
        PURPLE_MAJOR_VERSION,
        PURPLE_MINOR_VERSION, PURPLE_PLUGIN_STANDARD,
        NULL, 0,
        NULL,
        PURPLE_PRIORITY_DEFAULT, "core-keepass", "KeePass", PLUGIN_VERSION,
        "Use KeePass to store passwords.", /* Summary */
        "Store passwords encrypted within a KeePass database.", /* Description */
        "Adam Delman <flyn@flyn.cc>",
        NULL, plugin_load,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        plugin_actions, /* this tells libpurple the address of the function to call to get the list of plugin actions. */
        NULL,
        NULL,
        NULL,
        NULL};

static void init_plugin(PurplePlugin *plugin) {
    session = soup_session_new();
#if !GLIB_CHECK_VERSION (2, 35, 0)
    g_type_init();
#endif
    purple_prefs_add_none(PREF_PREFIX);
    purple_prefs_add_string(PREF_KEEPASS_HOST_PATH, "localhost");
    purple_prefs_add_int(PREF_KEEPASS_PORT_PATH, 19455);
    keepass_http_test_associate();

}

PURPLE_INIT_PLUGIN(keepass_pidgin, init_plugin, info)
