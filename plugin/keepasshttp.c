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
#include <libpurple/debug.h>
#include <libpurple/notify.h>
#include <libpurple/version.h>
#include "config.h"
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <libsoup/soup-message-body.h>

#define PLUGIN_ID "keepasshttp"
#define PREF_PREFIX     "/plugins/gtk/" PLUGIN_ID
#define PREF_KEEPASS_HOST_PATH        PREF_PREFIX "/keepass_host"
#define PREF_KEEPASS_PORT_PATH      PREF_PREFIX "/keepass_port"
#define PREF_KEEPASS_CLIENT_ID_PATH      PREF_PREFIX "/keepass_client_id"
#define PREF_KEEPASS_KEY_PATH      PREF_PREFIX "/keepass_key"

#define PREF_KEEPASS_HOST_LABEL "KeePass Host"
#define PREF_KEEPASS_PORT_LABEL "KeePass Port"


#define REQUEST_TYPE "RequestType"
#define TEST_ASSOCIATE_REQUEST_TYPE "test-associate"
#define ASSOCIATE_REQUEST_TYPE "associate"
#define TRIGGER_UNLOCK "TriggerUnlock"
#define KEY "Key"
#define ID "ID"
#define NONCE "Nonce"
#define SUCCESS "Success"
#define VERIFIER "Verifier"
#define JSON_MIME_TYPE "application/json"

#define AES_KEY_SIZE 32
#define POST_METHOD "POST"


PurplePlugin *keepass_plugin = NULL;
SoupSession *session = NULL;
char *keepass_http_client_id = "";
unsigned char *aes_key;

struct Http_Response {
    guint status_code;
    struct json_object *json;
};
#define PIDGIN_KEY_STRING_MAX_SIZE 1024

static const char *key_for_account(PurpleAccount *account) {
    static char key[PIDGIN_KEY_STRING_MAX_SIZE];
    snprintf(key, PIDGIN_KEY_STRING_MAX_SIZE, "%s:%s", purple_account_get_protocol_id(account),
             purple_account_get_username(account));
    return key;
}

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

bool is_association_successful(struct Http_Response *http_response) {
    bool test_success = false;
    if ((*http_response).status_code == 200) {
        struct json_object *success_json = json_object_new_object();
        json_object_object_get_ex((*http_response).json, SUCCESS, &success_json);
        if (json_object_get_boolean(success_json) == true) {
            test_success = true;
        }
    }
    return test_success;
}

#define NONCE_SIZE 16

unsigned char *get_nonce() {
    unsigned char *nonce = malloc(NONCE_SIZE);
    RAND_bytes(nonce, NONCE_SIZE);
    return nonce;
}

#define MAX_URL_LENGTH 300

static char *get_keepass_url() {
    const char *keepass_host = purple_prefs_get_string(PREF_KEEPASS_HOST_PATH);
    const int keepass_port = purple_prefs_get_int(PREF_KEEPASS_PORT_PATH);
    static char url_string[MAX_URL_LENGTH];
    snprintf(url_string, MAX_URL_LENGTH, "http://%s:%d", keepass_host, keepass_port);
    return url_string;
}

static void log_http_header(const char *name, const char *value, gpointer http_request_or_response) {
    purple_debug_info(PLUGIN_ID, "HTTP %s header: %s: %s \n", (char *) http_request_or_response, name, value);
}

static struct Http_Response perform_keepass_http(const char *method, const char *body) {
    char *url = get_keepass_url();
    SoupMessage *msg = soup_message_new(method, url);
    soup_message_set_request(msg, JSON_MIME_TYPE, SOUP_MEMORY_COPY, body, strlen(body));
    guint status_code = soup_session_send_message(session, msg);
    purple_debug_info(PLUGIN_ID, "HTTP URL : %s, \n", url);

    soup_message_headers_foreach(msg->request_headers, log_http_header, "request");
    if (body != NULL) {
        purple_debug_info(PLUGIN_ID, "HTTP request body: %s, \n", body);
    }
    purple_debug_info(PLUGIN_ID, "HTTP response code: %d, \n", status_code);
    soup_message_headers_foreach(msg->response_headers, log_http_header, "response");
    if (msg->response_body->data != NULL) {
        purple_debug_info(PLUGIN_ID, "HTTP response body: %s, \n", msg->response_body->data);
    }
    struct Http_Response http_response;
    http_response.status_code = status_code;
    if (msg->response_body->data) {
        http_response.json = json_tokener_parse(msg->response_body->data);
    }
    return http_response;
}

static bool keepass_http_test_associate(const char *nonce, const char *verifier, bool trigger_unlock) {
    struct json_object *test_associate_msg = json_object_new_object();
    json_object_object_add(test_associate_msg, REQUEST_TYPE, json_object_new_string(TEST_ASSOCIATE_REQUEST_TYPE));
    json_object_object_add(test_associate_msg, TRIGGER_UNLOCK, json_object_new_boolean(trigger_unlock));
    json_object_object_add(test_associate_msg, ID, json_object_new_string(keepass_http_client_id));
    json_object_object_add(test_associate_msg, NONCE, json_object_new_string(nonce));
    json_object_object_add(test_associate_msg, VERIFIER, json_object_new_string(verifier));
    const char *body = json_object_to_json_string(test_associate_msg);

    struct Http_Response http_response = perform_keepass_http(POST_METHOD, body);
    bool test_success = is_association_successful(&http_response);
    if (test_success) {
        purple_debug_info(PLUGIN_ID, "KeePass test-association successful.\n");
    }
    else {
        purple_debug_info(PLUGIN_ID, "KeePass test-association failed.\n");
    }
    return test_success;

}

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

static int encrypt(const unsigned char *plaintext, const int plaintext_len, const unsigned char *key,
                   const unsigned char *iv,
                   unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) { handleErrors(); }

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handleErrors();
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        handleErrors();
    }
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

static unsigned char *base64_encode(const unsigned char *string) {
    return (unsigned char *) g_base64_encode(string, sizeof(string));
}


void pad(char *str_to_pad, int final_length, char pad_char) {
    purple_debug_info(PLUGIN_ID, "Before pad: '%s'\n", str_to_pad);

    if (final_length > strlen(str_to_pad)) {
        size_t pad_count = final_length - strlen(str_to_pad);

        purple_debug_info(PLUGIN_ID, "Pad iterations: %d\n", (int) pad_count);

        for (int i = 1; i < pad_count; i++) {
            strcat(str_to_pad, &pad_char);
            purple_debug_info(PLUGIN_ID, "Count: '%d', string is '%s'\n", i, str_to_pad);

        }
    }
    purple_debug_info(PLUGIN_ID, "After pad:  '%s'\n", str_to_pad);
}


char *get_verifier(const unsigned char *nonce, char unsigned *verifier) {
    char *padded_nonce = malloc(NONCE_SIZE+1);
    memcpy(padded_nonce, nonce, (sizeof(nonce)));
    pad(padded_nonce, NONCE_SIZE, 0xd);
    encrypt(padded_nonce, (int) strlen((char *) padded_nonce), aes_key, nonce, verifier);
    char *base64_verifier = base64_encode(verifier);
    free(padded_nonce);
    return base64_verifier;
}


static void keepass_http_associate() {
    struct json_object *associate_msg = json_object_new_object();
    json_object_object_add(associate_msg, REQUEST_TYPE, json_object_new_string(ASSOCIATE_REQUEST_TYPE));
    json_object_object_add(associate_msg, KEY, json_object_new_string((char *) aes_key));
    const unsigned char *nonce = get_nonce();

    json_object_object_add(associate_msg, NONCE, json_object_new_string((const char *) base64_encode(nonce)));
    char *verifier = malloc(NONCE_SIZE+1);
    verifier = get_verifier(nonce, verifier);
    json_object_object_add(associate_msg, VERIFIER, json_object_new_string((const char *) base64_encode(verifier)));
    const char *body = json_object_to_json_string(associate_msg);
    struct Http_Response http_response = perform_keepass_http(POST_METHOD, body);
//    free(verifier);
    bool test_success = is_association_successful(&http_response);
    if (test_success) {
        purple_debug_info(PLUGIN_ID, "KeePass association successful.\n");
    }
    else {
        purple_debug_info(PLUGIN_ID, "KeePass association failed.\n");
    }
}


static void encrypt_password(gpointer data, gpointer user_data) {
    PurpleAccount *account = (PurpleAccount *) data;

    /* Only save passwords for accounts that are remembering passwords in accounts.xml. */
    if (purple_account_get_remember_password(account)) {
//        store_password(account);
    }
}

static char *read_password(const char *key_for_account) {
    return "";
}

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
static void decrypt_password(gpointer data, gpointer user_data) {
    PurpleAccount *account = (PurpleAccount *) data;

    /* Only decrypt passwords for accounts that are not remembering passwords in accounts.xml. */
    if (!purple_account_get_remember_password(account)) {
        const char *key = key_for_account(account);
        char *password = read_password(key);
        if (!password)
            return; // Don't print an error here - it could just be that the password isn't saved.
        purple_account_set_password(account, password);
        purple_account_set_remember_password(account, true);
        g_free(password);
    }
}

static void store_password(PurpleAccount *account) {

}

static void encrypt_all_passwords(PurplePluginAction *action) {
    GList *accounts = purple_accounts_get_all();
    g_list_foreach(accounts, encrypt_password, NULL);
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
    PurplePluginPrefFrame *frame = purple_plugin_pref_frame_new();
    PurplePluginPref *pref;
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
    GList *action_list = NULL;
    PurplePluginAction *action = NULL;

    action = purple_plugin_action_new("Encrypt Passwords",
                                      encrypt_all_passwords);
    action_list = g_list_append(action_list, action);
    action = purple_plugin_action_new("Decrypt Passwords",
                                      decrypt_all_passwords);
    action_list = g_list_append(action_list, action);

    return action_list;
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
    return true;
}

static PurplePluginInfo info = {
        PURPLE_PLUGIN_MAGIC,
        PURPLE_MAJOR_VERSION,
        PURPLE_MINOR_VERSION, PURPLE_PLUGIN_STANDARD,
        NULL, 0,
        NULL,
        PURPLE_PRIORITY_DEFAULT, "core-keepass", "KeePass", PLUGIN_VERSION,
        "Use KeePass to store passwords.",
        "Store passwords encrypted within a KeePass database.",
        "Adam Delman <flyn@flyn.cc>",
        NULL, plugin_load,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        plugin_actions,
        NULL,
        NULL,
        NULL,
        NULL};

void setup_aes_key() {
    if (strcmp("", purple_prefs_get_string(PREF_KEEPASS_KEY_PATH)) == 0) {
        aes_key = malloc(AES_KEY_SIZE);
        RAND_bytes(aes_key, sizeof(aes_key));
        aes_key = (unsigned char *) g_base64_encode(aes_key, AES_KEY_SIZE);
        purple_prefs_set_string(PREF_KEEPASS_KEY_PATH, (char *) aes_key);
    }
    else {
        aes_key = (unsigned char *) purple_prefs_get_string(PREF_KEEPASS_KEY_PATH);
    }
}

static void init_plugin(PurplePlugin *plugin) {
    session = soup_session_new();
#if !GLIB_CHECK_VERSION (2, 35, 0)
    g_type_init();
#endif
    purple_debug_set_enabled(true);
    purple_debug_info(PLUGIN_ID, "Initialising KeePassHTTP Plugin.\n");
    if (strcmp("", purple_prefs_get_string(PREF_KEEPASS_HOST_PATH)) == 0) {
        purple_prefs_add_string(PREF_KEEPASS_HOST_PATH, "localhost");
    }
    if (!purple_prefs_exists(PREF_KEEPASS_PORT_PATH)) {
        purple_prefs_add_int(PREF_KEEPASS_PORT_PATH, 19455);
    }
    if (!purple_prefs_exists(PREF_KEEPASS_KEY_PATH)) {
        purple_prefs_add_string(PREF_KEEPASS_KEY_PATH, "");
    }
    setup_aes_key();

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);


    if (!purple_prefs_exists(PREF_KEEPASS_CLIENT_ID_PATH)) {
        purple_prefs_add_string(PREF_KEEPASS_CLIENT_ID_PATH, "");
    }
    bool associated = keepass_http_test_associate("", "", false);
    if (!associated) {
        keepass_http_associate();
    }

}


PURPLE_INIT_PLUGIN(keepass_pidgin, init_plugin, info)
