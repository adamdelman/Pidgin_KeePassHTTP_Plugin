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

#define PLUGIN_ID "keepasshttp"
#define PREF_PREFIX     "/plugins/gtk/" PLUGIN_ID
#define PREF_KEEPASS_HOST_PATH        PREF_PREFIX "/keepass_host"
#define PREF_KEEPASS_PORT_PATH      PREF_PREFIX "/keepass_port"
#define PREF_KEEPASS_CLIENT_ID_PATH      PREF_PREFIX "/keepass_client_id"
#define PREF_KEEPASS_KEY_PATH      PREF_PREFIX "/keepass_key"
//#define PREF_KEEPASS_HOST_LABEL "KeePass Host"
//#define PREF_KEEPASS_PORT_LABEL "KeePass Port"

#define REQUEST_TYPE_TAG "RequestType"
#define TEST_ASSOCIATE_REQUEST_TYPE "test-associate"
#define ASSOCIATE_REQUEST_TYPE "associate"
#define TRIGGER_UNLOCK_TAG "TriggerUnlock"
#define KEY_TAG "Key"
#define ID_TAG "ID"
#define NONCE_TAG "Nonce"
#define SUCCESS_TAG "Success"
#define VERIFIER_TAG "Verifier"

#define JSON_MIME_TYPE "application/json"
#define POST_METHOD "POST"
#define AES_BLOCK_LENGTH 16
#define AES_KEY_LENGTH 32
#define AES_KEY_VAR aes_key
guchar AES_KEY_VAR[AES_KEY_LENGTH];
#define AES_KEY_SIZE  sizeof AES_KEY_VAR
#define AES_IV_VAR aes_iv
#define AES_IV_LENGTH 16
guchar AES_IV_VAR[AES_IV_LENGTH];
#define AES_IV_SIZE  sizeof AES_IV_VAR

//PurplePlugin *keepass_plugin = NULL;
SoupSession *session = NULL;
char *keepass_http_client_id = NULL;

struct Http_Response {
    guint status_code;
    struct json_object *json;
};
//#define PIDGIN_KEY_STRING_MAX_SIZE 1024
//
//static const gchar *key_for_account(PurpleAccount *account) {
//    static gchar key[PIDGIN_KEY_STRING_MAX_SIZE];
//    snprintf(key, PIDGIN_KEY_STRING_MAX_SIZE, "%s:%s", purple_account_get_protocol_id(account),
//             purple_account_get_username(account));
//    return key;
//}

bool is_association_successful(struct Http_Response *http_response) {
    bool test_success = false;
    if ((*http_response).status_code == 200) {
        struct json_object *success_json = json_object_new_object();
        json_object_object_get_ex((*http_response).json, SUCCESS_TAG, &success_json);
        if (json_object_get_boolean(success_json) == true) {
            test_success = true;
        }
    }
    return test_success;
}


#define MAX_URL_LENGTH 300

static gchar *get_keepass_url() {
    const gchar *keepass_host = purple_prefs_get_string(PREF_KEEPASS_HOST_PATH);
    const int keepass_port = purple_prefs_get_int(PREF_KEEPASS_PORT_PATH);
    static gchar url_string[MAX_URL_LENGTH];
    snprintf(url_string, MAX_URL_LENGTH, "http://%s:%d", keepass_host, keepass_port);
    return url_string;
}

static void log_http_header(const gchar *name, const gchar *value, gpointer http_request_or_response) {
    purple_debug_info(PLUGIN_ID, "HTTP %s header: %s: %s \n", (char *) http_request_or_response, name, value);
}

static struct Http_Response perform_keepass_http(const gchar *method, const gchar *body) {
    gchar *url = get_keepass_url();
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


void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

static int encrypt(const guchar *plain_text, const int plaintext_len, const guchar *key, const guchar *iv,
                   guchar *cipher_text) {
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
    if (1 != EVP_EncryptUpdate(ctx, cipher_text, &len, plain_text, plaintext_len)) {
        handleErrors();
    }
    ciphertext_len = len;

    /* Finalise the encryption. Further cipher_text bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, cipher_text + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


void aes_pad(guchar *str_to_pad, size_t str_len) {
    size_t padded_length = str_len + AES_BLOCK_LENGTH - str_len % AES_BLOCK_LENGTH;
    str_to_pad = realloc(str_to_pad, padded_length);
    if (padded_length > str_len) {
        size_t pad_count = padded_length - str_len;
        memset(str_to_pad + str_len, padded_length, pad_count);
    }
}

void create_new_iv() { RAND_bytes(AES_IV_VAR, AES_IV_LENGTH); }


gchar *create_verifier(const guchar *AES_IV_VAR)
{
    guchar *padded_nonce = g_malloc(AES_IV_SIZE + AES_BLOCK_LENGTH - AES_IV_SIZE % AES_BLOCK_LENGTH);
    guchar *verifier = g_malloc(AES_IV_SIZE);
    memcpy(padded_nonce, AES_IV_VAR, AES_IV_SIZE);
    aes_pad(padded_nonce, AES_IV_SIZE);
    int cipher_len = encrypt(padded_nonce, (int) AES_IV_SIZE, AES_KEY_VAR, AES_IV_VAR, verifier);
    gchar *base64_verifier = g_base64_encode(verifier, (gsize) cipher_len);
    g_free(verifier);
    g_free(padded_nonce);
    return base64_verifier;
}

static bool keepass_http_test_associate(bool trigger_unlock) {
    struct json_object *test_associate_msg = json_object_new_object();
    json_object_object_add(test_associate_msg, REQUEST_TYPE_TAG, json_object_new_string(TEST_ASSOCIATE_REQUEST_TYPE));
    json_object_object_add(test_associate_msg, TRIGGER_UNLOCK_TAG, json_object_new_boolean(trigger_unlock));
    if (keepass_http_client_id) {
        json_object_object_add(test_associate_msg, ID_TAG, json_object_new_string(keepass_http_client_id));
    }
    create_new_iv();
    gchar *base64_aes_iv = g_base64_encode(AES_IV_VAR, AES_IV_SIZE);
    json_object_object_add(test_associate_msg, NONCE_TAG, json_object_new_string(base64_aes_iv));
    g_free(base64_aes_iv);
    gchar *base64_verifier = create_verifier(AES_IV_VAR);
    json_object_object_add(test_associate_msg, VERIFIER_TAG, json_object_new_string(base64_verifier));
    g_free(base64_verifier);
    gchar *body = (gchar *) json_object_to_json_string(test_associate_msg);
    struct Http_Response http_response = perform_keepass_http(POST_METHOD, body);
    g_free(test_associate_msg);
    bool test_success = is_association_successful(&http_response);
    if (test_success) {
        purple_debug_info(PLUGIN_ID, "KeePass test-association successful.\n");
    }
    else {
        purple_debug_info(PLUGIN_ID, "KeePass test-association failed.\n");
    }
    g_free(body);
    return test_success;

}


static void keepass_http_associate() {
    struct json_object *associate_msg = json_object_new_object();
    json_object_object_add(associate_msg, REQUEST_TYPE_TAG, json_object_new_string(ASSOCIATE_REQUEST_TYPE));
    gchar *base64_aes_key = g_base64_encode(AES_KEY_VAR, AES_KEY_SIZE);
    json_object_object_add(associate_msg, KEY_TAG, json_object_new_string(base64_aes_key));
    g_free(base64_aes_key);
    create_new_iv();
    gchar *base64_aes_iv = g_base64_encode(AES_IV_VAR, AES_IV_SIZE);
    json_object_object_add(associate_msg, NONCE_TAG, json_object_new_string(base64_aes_iv));
    g_free(base64_aes_iv);
    gchar *base64_verifier = create_verifier(AES_IV_VAR);
    json_object_object_add(associate_msg, VERIFIER_TAG, json_object_new_string(base64_verifier));
    g_free(base64_verifier);
    const gchar *body = json_object_to_json_string(associate_msg);
    struct Http_Response http_response = perform_keepass_http(POST_METHOD, body);
    bool test_success = is_association_successful(&http_response);
    if (test_success) {
        purple_debug_info(PLUGIN_ID, "KeePass association successful.\n");
    }
    else {
        purple_debug_info(PLUGIN_ID, "KeePass association failed.\n");
    }
}

//static PurplePluginPrefFrame *
//get_plugin_pref_frame(PurplePlugin *plugin) {
//    PurplePluginPrefFrame *frame = purple_plugin_pref_frame_new();
//    PurplePluginPref *pref;
//    pref = purple_plugin_pref_new_with_label(("KeePass Preferences"));
//    purple_plugin_pref_frame_add(frame, pref);
//
//    pref = purple_plugin_pref_new_with_name_and_label(PREF_KEEPASS_HOST_PATH, PREF_KEEPASS_HOST_LABEL);
//    purple_plugin_pref_frame_add(frame, pref);
//
//    pref = purple_plugin_pref_new_with_name_and_label(PREF_KEEPASS_PORT_PATH, PREF_KEEPASS_PORT_LABEL);
//    purple_plugin_pref_frame_add(frame, pref);
//
//    return frame;
//}

//static PurplePluginUiInfo prefs_info = {
//        get_plugin_pref_frame,
//        0,
//        NULL,
//        NULL,
//        NULL,
//        NULL,
//        NULL
//};


/* Register plugin actions */
//static GList *plugin_actions(PurplePlugin *plugin, gpointer context) {
//    GList *action_list = NULL;
//    PurplePluginAction *action = NULL;
//
//    action = purple_plugin_action_new("Encrypt Passwords",
//                                      encrypt_all_passwords);
//    action_list = g_list_append(action_list, action);
//    action = purple_plugin_action_new("Decrypt Passwords",
//                                      decrypt_all_passwords);
//    action_list = g_list_append(action_list, action);
//
//    return action_list;
//}

/* Called when the plugin loads(after plugin_init()) */
//static gboolean plugin_load(PurplePlugin *plugin) {
//    keepass_plugin = plugin;

//    GList *accounts = NULL;
//    accounts = purple_accounts_get_all();
//    g_list_foreach(accounts, fetch_password, NULL);
//
//    void *accounts_handle = purple_accounts_get_handle();
//    purple_signal_connect(accounts_handle, "account-added", plugin,
//                          PURPLE_CALLBACK(account_added), NULL);
//    purple_signal_connect(accounts_handle, "account-removed", plugin,
//                          PURPLE_CALLBACK(account_removed), NULL);
//    purple_signal_connect(accounts_handle, "account-set-info", plugin,
//                          PURPLE_CALLBACK(account_changed), NULL);
//    return true;
//}

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
//        NULL, plugin_load,

        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
//        plugin_actions,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL};

void setup_aes_key() {
    gchar *base64_aes_key = (gchar *) purple_prefs_get_string(PREF_KEEPASS_KEY_PATH);
    size_t base64_aes_key_length = strlen(base64_aes_key);
    purple_debug_info(PLUGIN_ID, "Stored base64 aes key is %s of length %ld.\n", base64_aes_key, base64_aes_key_length);

    if (base64_aes_key_length) {
        gsize *temp_aes_key_len = NULL;
        guchar *temp_aes_key = g_base64_decode(base64_aes_key, temp_aes_key_len);
        memcpy(AES_KEY_VAR, temp_aes_key, (size_t) temp_aes_key_len);
        g_free(base64_aes_key);

    } else {
        RAND_bytes(AES_KEY_VAR, AES_KEY_LENGTH);
        base64_aes_key = g_base64_encode(AES_KEY_VAR, AES_KEY_LENGTH);
        purple_prefs_set_string(PREF_KEEPASS_KEY_PATH, base64_aes_key);
        g_free(base64_aes_key);
    }

}

static void init_plugin(PurplePlugin *plugin) {
    session = soup_session_new();
//#if !GLIB_CHECK_VERSION (2, 35, 0)
//    g_type_init();
//#endif
    purple_debug_info(PLUGIN_ID, "Initialising KeePassHTTP Plugin from %s.\n", plugin->path);
    purple_debug_set_enabled(true);;
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
    bool associated = keepass_http_test_associate(false);
    if (!associated) {
        keepass_http_associate();
    }

}


PURPLE_INIT_PLUGIN(keepass_pidgin, init_plugin, info)
