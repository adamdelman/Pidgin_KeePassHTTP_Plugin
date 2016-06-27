/*******************************************************************
 * Pidgin KeePass Password Plugin
 *
 * Copyright(C) 2010 Craig Drummond <craig.p.drummond@googlemail.com>

 * 
 * Copyright(C) 2016, Adam Delman <flyn@flyn.cc>
 *******************************************************************
 * USAGE
 * Create the accounts that you want to use in the chat program that
 * uses libpurple.  Save the passwords and check the "remember
 * passwords" checkbox.
 * In Tools->KWallet Passwords, select Encrypt Passwords.
 * All passwords will be moved from accounts.xml to KWallet.
 *
 * If you create a new account, check the "remember passwords"
 * checkbox on it and select Encrypt Passwords again.  It will
 * encrypt any accounts that have a password saved in accounts.xml.
 *
 * To put the passwords back in accounts.xml, select Decrypt
 * Passwords instead of Encrypt Passwords.  All passwords will be
 * put in the accounts.xml file and removed from KWallet.
 *******************************************************************
 * LICENSE
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or(at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02111-1301, USA.
 *******************************************************************/

#include "config.h"

/* config.h may define PURPLE_PLUGINS; protect the definition here so that we don't get complaints about redefinition when it's not necessary. */
#ifndef PURPLE_PLUGINS
# define PURPLE_PLUGINS
#endif

/* <b style="color: black; background-color: rgb(160, 255, 255);">Libpurple</b> is a glib application. */
#include <gdk/gdk.h>
#include <gio/gio.h>
#include <glib.h>
#include <gtk/gtk.h>
/* This will prevent compiler errors in some instances and is better explained in the how-to documents on the wiki */
#ifndef G_GNUC_NULL_TERMINATED
# if __GNUC__ >= 4
#  define G_GNUC_NULL_TERMINATED __attribute__((__sentinel__))
# else
#  define G_GNUC_NULL_TERMINATED
# endif
#endif

/* Include the required libpurple headers. */
#include <libpurple/notify.h>
#include <libpurple/plugin.h>
#include <libpurple/version.h>

/* Include libsoup for HTTP client. */
#include <libsoup/soup.h>
#include <json-glib/json-glib.h>
#include <stdbool.h>
#include <string.h>

PurplePlugin *keepass_plugin = NULL; //A handle to our plugin - will be initiated in plugin_load().
SoupSession *session = NULL;
#define PLUGIN_ID "keepasshttp"
#define PREF_PREFIX     "/plugins/gtk/" PLUGIN_ID
#define PREF_KEEPASS_HOST_PATH        PREF_PREFIX "/keepass_host"
#define PREF_KEEPASS_PORT_PATH      PREF_PREFIX "/keepass_port"
#define PREF_KEEPASS_HOST_LABEL "KeePass Host"
#define PREF_KEEPASS_PORT_LABEL "KeePass Port"

#define MAX_URL_LENGTH 300

static char *read_password(int wallet, const char *account) {
    char *rv;
    GError *error = NULL;
    return rv;
}

static gboolean write_password(int wallet, const char *account,
                               const char *passwd) {
    int rv;
    return 0 == rv;
}

static gboolean remove_entry(int wallet, const char *account) {
    int rv;
    GError *error = NULL;
    return 0 == rv;
}

static int open_wallet(gboolean silent) {
    GError *error = NULL;
    int wallet = -1;

    return wallet;
}

static const char *key_for_account(PurpleAccount *account) {
    static char key[1024];

    sprintf(key, "%s:%s", purple_account_get_protocol_id(account),
            purple_account_get_username(account));
    return key;
}

static void store_password(PurpleAccount *account) {
    int wallet = open_wallet(FALSE);
    if (wallet >= 0) {
        if (write_password(wallet, key_for_account(account),
                           purple_account_get_password(account))) {
            /* KWallet has the password now - so accounts.xml can forget it. */
            purple_account_set_remember_password(account, FALSE);
        } else
            purple_notify_message(keepass_plugin, PURPLE_NOTIFY_MSG_ERROR,
                                  "KeePass Error", "Could not save password in KeePass.",
                                  NULL, NULL, NULL);
    }
}

static char *get_keepass_url() {
    const char *keepass_host = purple_prefs_get_string(PREF_KEEPASS_HOST_PATH);
    const int keepass_port = purple_prefs_get_int(PREF_KEEPASS_PORT_PATH);
    static char url_string[MAX_URL_LENGTH];
    snprintf(url_string, MAX_URL_LENGTH, "http://%s:%d", keepass_host, keepass_port);
    return url_string;
}

static void perform_http(char *method,char *body){

}
static void keepass_http_test_associate() {
    const char *test_associate_msg_body = "{\"RequestType\":\"test-associate\",\"TriggerUnlock\":false}";
    SoupMessage *msg = soup_message_new("POST", get_keepass_url());

    soup_message_set_request(msg, "application/json",
                             SOUP_MEMORY_COPY, test_associate_msg_body, strlen(test_associate_msg_body));
    soup_message_headers_append(msg->request_headers, "Content-Type:", "application/json");
    soup_session_send_message(session, msg);

}

static void encrypt_password(gpointer data, gpointer user_data) {
    PurpleAccount *account = (PurpleAccount *) data;

    /* Only save passwords for accounts that are remembering passwords in accounts.xml. */
    if (purple_account_get_remember_password(account))
        store_password(account);
}

static void fetch_password(gpointer data, gpointer user_data) {
    PurpleAccount *account = (PurpleAccount *) data;

    /* Only fetch passwords for accounts that are not remembering passwords in accounts.xml. */
    if (!purple_account_get_remember_password(account)) {
        int wallet = open_wallet(FALSE);
        if (wallet >= 0) {
            char *password = read_password(wallet, key_for_account(account));
            if (!password)
                return; // Don't print an error here - it could just be that the password isn't saved.
            purple_account_set_password(account, password);
            g_free(password);
        }
    }
}

static void decrypt_password(gpointer data, gpointer user_data) {
    PurpleAccount *account = (PurpleAccount *) data;

    /* Only decrypt passwords for accounts that are not remembering passwords in accounts.xml. */
    if (!purple_account_get_remember_password(account)) {
        int wallet = open_wallet(FALSE);
        if (wallet >= 0) {
            const char *key = key_for_account(account);
            char *password = read_password(wallet, key);
            if (!password)
                return; // Don't print an error here - it could just be that the password isn't saved.
            purple_account_set_password(account, password);
            purple_account_set_remember_password(account, true);
            remove_entry(wallet, key);
            g_free(password);
        }
    }
}

static void encrypt_all_passwords(PurplePluginAction *action) {
    GList *accounts = purple_accounts_get_all();
    g_list_foreach(accounts, encrypt_password, NULL);
    // You cannot g_list_free(accounts) here without segfaulting Pidgin.
    purple_notify_message(keepass_plugin, PURPLE_NOTIFY_MSG_INFO,
                          "KeePass Password", "All saved passwords are now in KeePass.",
                          NULL, NULL, NULL);
}

static void decrypt_all_passwords(PurplePluginAction *action) {
    GList *accounts = purple_accounts_get_all();
    g_list_foreach(accounts, decrypt_password, NULL);
    // You cannot g_list_free(accounts) here without segfaulting Pidgin.
    purple_notify_message(keepass_plugin, PURPLE_NOTIFY_MSG_INFO,
                          "KeePass Password",
                          "All saved passwords are now in accounts.xml as plain text.", NULL,
                          NULL, NULL);
}

static void account_added(gpointer data, gpointer user_data) {
    store_password((PurpleAccount *) data);
}

static void account_removed(gpointer data, gpointer user_data) {
    PurpleAccount *account = (PurpleAccount *) data;
    int wallet = open_wallet(true);

    if (wallet >= 0) {
        const char *key = key_for_account(account);
        char *password = read_password(wallet, key);

        if (password) {
            remove_entry(wallet, key);
            g_free(password);
        }
    }
}

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


static void account_changed(gpointer data, gpointer user_data) {
    char *password;
    // TODO: Is there a way to detect when an account has changed?????
    PurpleAccount *account = (PurpleAccount *) data;
    printf("Account changed: %s -> %s\n", key_for_account(account),
           password ? password : "<>");

    //store_password((PurpleAccount*)data);
}

/* Register plugin actions */
static GList *plugin_actions(PurplePlugin *plugin, gpointer context) {
    GList *list = NULL; // The action list.
    PurplePluginAction *action = NULL; // A action temp pointer.

    action = purple_plugin_action_new("Encrypt Passwords",
                                      encrypt_all_passwords);
    list = g_list_append(list, action);
    action = purple_plugin_action_new("Decrypt Passwords",
                                      decrypt_all_passwords);
    list = g_list_append(list, action);

    return list;
}

/* Called when the plugin loads(after plugin_init()) */
static gboolean plugin_load(PurplePlugin *plugin) {
    keepass_plugin = plugin; /* assign this here so we have a valid handle later */

    /* Set the passwords for the accounts before they try to connect. */
    GList *accounts = NULL;
    accounts = purple_accounts_get_all();
    g_list_foreach(accounts, fetch_password, NULL);
    // You cannot g_list_free(accounts) here without segfaulting Pidgin.

    void *accounts_handle = purple_accounts_get_handle();
    purple_signal_connect(accounts_handle, "account-added", plugin,
                          PURPLE_CALLBACK(account_added), NULL);
    purple_signal_connect(accounts_handle, "account-removed", plugin,
                          PURPLE_CALLBACK(account_removed), NULL);
    purple_signal_connect(accounts_handle, "account-set-info", plugin,
                          PURPLE_CALLBACK(account_changed), NULL);
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
    GError *error = NULL;
//    msg = soup_message_new ("GET", "http://example.com/");
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
