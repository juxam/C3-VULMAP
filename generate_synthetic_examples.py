"""
generate_synthetic_examples.py - hand-authored vulnerable C/C++ examples
targeting the three genuinely thin LINDDUN categories confirmed by
08_identify_synthetic_targets.py against the real, final corpus:

    Non-repudiation (80 real rows) <- CWE-778, CWE-117, CWE-364
      (feeding categories CWE-1210/CWE-387, both at ZERO real coverage)
    Unawareness (108 real rows)    <- CWE-242, CWE-477
      (feeding category CWE-1228, at ZERO real coverage)
    Data Disclosure (108 real rows) <- CWE-358, CWE-770
      (no zero-coverage feeder exists for this one - these are the exact
      CWEs already present in the real data, diversified rather than
      guessing at an unverified new CWE's category membership)

Every example follows the non-leaky naming discipline established earlier
in this project (no vulnerableFunction/mySecretPassword-style self-naming
identifiers) and is written as a distinct, realistic scenario across
varied domains (networking, embedded, backend/database, CLI, web-adjacent)
rather than a template with only names swapped.

Run:  python generate_synthetic_examples.py
Out:  synthetic_v2.jsonl
"""

import json
from collections import Counter

GENERATION_METHOD = "claude-authored-v1"

examples = []


def add(cwe, code):
    examples.append({
        "code": code.strip() + "\n",
        "label": 1,
        "cwe_id": cwe,
        "generation_method": GENERATION_METHOD,
    })


# =====================================================================
# CWE-778 - Insufficient Logging (Non-repudiation)
# =====================================================================

add("CWE-778", """
int validate_login_credentials(const char *account_name, const char *secret_phrase) {
    struct db_conn *conn = get_pool_connection();
    int ok = verify_credentials(conn, account_name, secret_phrase);
    if (!ok) {
        return -1;
    }
    return 0;
}
""")

add("CWE-778", """
void handle_privilege_escalation(struct session *s, int new_level) {
    if (new_level <= s->level) {
        return;
    }
    s->level = new_level;
    apply_permissions(s, new_level);
}
""")

add("CWE-778", """
static int process_config_change(struct config_ctx *ctx, const char *key,
                                 const char *new_value) {
    char *old_value = config_get(ctx, key);
    int rc = config_set(ctx, key, new_value);
    free(old_value);
    return rc;
}
""")

add("CWE-778", """
int decrypt_payload(const uint8_t *ciphertext, size_t len,
                    const uint8_t *key, uint8_t *out) {
    int result = aes_gcm_decrypt(ciphertext, len, key, out);
    if (result != 0) {
        return -1;
    }
    return 0;
}
""")

add("CWE-778", """
void delete_account(struct account_store *store, uint64_t account_id,
                    uint64_t requesting_admin_id) {
    struct account *acc = account_lookup(store, account_id);
    if (!acc) {
        return;
    }
    account_remove(store, account_id);
    free(acc);
}
""")

add("CWE-778", """
int transfer_funds(struct ledger *ledger, uint64_t from, uint64_t to,
                   int64_t amount) {
    if (ledger_balance(ledger, from) < amount) {
        return -1;
    }
    ledger_debit(ledger, from, amount);
    ledger_credit(ledger, to, amount);
    return 0;
}
""")

add("CWE-778", """
static void firmware_update_apply(struct device_ctx *dev,
                                  const uint8_t *image, size_t len) {
    if (!firmware_signature_valid(image, len)) {
        return;
    }
    flash_write(dev, image, len);
    device_reboot(dev);
}
""")

add("CWE-778", """
int api_key_revoke(struct key_store *store, const char *key_id,
                   const char *actor) {
    struct api_key *k = key_store_find(store, key_id);
    if (!k) {
        return -1;
    }
    k->revoked = 1;
    key_store_persist(store);
    return 0;
}
""")

add("CWE-778", """
void export_patient_records(struct db_conn *conn, uint64_t clinician_id,
                            uint64_t patient_id, FILE *out) {
    struct patient_record *rec = fetch_patient_record(conn, patient_id);
    if (!rec) {
        return;
    }
    write_record_csv(out, rec);
    free_patient_record(rec);
}
""")

add("CWE-778", """
int password_reset_confirm(struct user_store *store, const char *token,
                           const char *new_password) {
    struct reset_token *t = token_lookup(store, token);
    if (!t || token_expired(t)) {
        return -1;
    }
    user_set_password(store, t->user_id, new_password);
    token_invalidate(store, token);
    return 0;
}
""")

add("CWE-778", """
static void grant_role(struct rbac_ctx *ctx, uint64_t user_id,
                       const char *role_name) {
    struct role *r = role_find(ctx, role_name);
    if (!r) {
        return;
    }
    rbac_assign(ctx, user_id, r);
}
""")

add("CWE-778", """
int firewall_rule_delete(struct fw_ctx *fw, uint32_t rule_id,
                         const char *client_ip) {
    struct fw_rule *rule = fw_find_rule(fw, rule_id);
    if (!rule) {
        return -1;
    }
    fw_remove_rule(fw, rule_id);
    fw_commit(fw);
    return 0;
}
""")

add("CWE-778", """
void device_pairing_complete(struct ble_ctx *ctx, const uint8_t *peer_addr,
                             const uint8_t *shared_key) {
    store_bonded_device(ctx, peer_addr, shared_key);
    ble_advertise_stop(ctx);
}
""")

add("CWE-778", """
int certificate_revoke(struct pki_ctx *pki, const char *serial,
                       const char *reason_code) {
    struct cert *c = pki_find_by_serial(pki, serial);
    if (!c) {
        return -1;
    }
    crl_add_entry(pki, serial);
    return 0;
}
""")

add("CWE-778", """
static void backup_restore(struct backup_ctx *ctx, const char *backup_id,
                           const char *initiated_by) {
    struct backup_manifest *m = backup_load_manifest(ctx, backup_id);
    if (!m) {
        return;
    }
    backup_apply(ctx, m);
    free_manifest(m);
}
""")

add("CWE-778", """
int vault_secret_delete(struct vault_ctx *vault, const char *path,
                        const char *token) {
    if (!vault_token_valid(vault, token)) {
        return -1;
    }
    vault_remove_secret(vault, path);
    return 0;
}
""")


# =====================================================================
# CWE-117 - Improper Output Neutralization for Logs (Non-repudiation)
# =====================================================================

add("CWE-117", """
void log_login_attempt(const char *username, int success) {
    char entry[256];
    snprintf(entry, sizeof(entry), "login attempt for user=%s success=%d",
            username, success);
    write_audit_log(entry);
}
""")

add("CWE-117", """
static void log_http_request(const char *method, const char *path,
                             const char *user_agent) {
    fprintf(access_log, "%s %s \\"%s\\"\\n", method, path, user_agent);
    fflush(access_log);
}
""")

add("CWE-117", """
int record_failed_transaction(const char *account_ref, const char *reason) {
    char buf[512];
    int n = snprintf(buf, sizeof(buf), "TXN_FAIL ref=%s reason=%s",
                     account_ref, reason);
    return append_to_log(buf, n);
}
""")

add("CWE-117", """
void log_client_hostname(int sock_fd, const char *resolved_hostname) {
    syslog(LOG_INFO, "connection accepted from host: %s", resolved_hostname);
}
""")

add("CWE-117", """
static void log_form_submission(const char *field_name,
                                const char *field_value) {
    printf("[form] %s = %s\\n", field_name, field_value);
}
""")

add("CWE-117", """
int audit_file_upload(const char *uploaded_filename, size_t size_bytes) {
    char line[1024];
    snprintf(line, sizeof(line), "upload: name=%s size=%zu",
            uploaded_filename, size_bytes);
    return audit_write(line);
}
""")

add("CWE-117", """
void log_search_query(struct request_ctx *ctx, const char *query) {
    fprintf(ctx->log_stream, "search query: %s\\n", query);
}
""")

add("CWE-117", """
static int log_error_with_context(const char *component,
                                  const char *error_detail) {
    char message[2048];
    snprintf(message, sizeof(message), "[%s] error: %s",
            component, error_detail);
    return error_log_write(message);
}
""")

add("CWE-117", """
void trace_api_call(const char *endpoint, const char *raw_headers) {
    fprintf(trace_file, "endpoint=%s headers=%s\\n", endpoint, raw_headers);
}
""")

add("CWE-117", """
int log_dns_lookup(const char *queried_name, const char *resolved_ip) {
    char rec[256];
    int len = snprintf(rec, sizeof(rec), "dns: %s -> %s",
                       queried_name, resolved_ip);
    return dns_log_append(rec, len);
}
""")

add("CWE-117", """
static void log_shell_command(const char *invoking_user,
                              const char *command_line) {
    syslog(LOG_NOTICE, "user %s ran: %s", invoking_user, command_line);
}
""")

add("CWE-117", """
void log_email_delivery(const char *recipient, const char *subject_line) {
    fprintf(mail_log, "sent to=%s subject=%s\\n", recipient, subject_line);
}
""")

add("CWE-117", """
int log_config_override(const char *setting_name, const char *user_input) {
    char entry[512];
    snprintf(entry, sizeof(entry), "override %s=%s", setting_name, user_input);
    return config_audit_append(entry);
}
""")

add("CWE-117", """
static void log_device_report(const char *device_serial,
                              const char *status_message) {
    printf("device %s reported: %s\\n", device_serial, status_message);
}
""")

add("CWE-117", """
int log_webhook_payload(const char *source_name, const char *payload_summary) {
    char buf[1024];
    snprintf(buf, sizeof(buf), "webhook from %s: %s",
            source_name, payload_summary);
    return webhook_log_write(buf);
}
""")

add("CWE-117", """
void log_referer_header(const char *client_ip, const char *referer) {
    fprintf(access_log, "%s referer=%s\\n", client_ip, referer);
}
""")


# =====================================================================
# CWE-364 - Signal Handler Race Condition (Non-repudiation, Detectability)
# =====================================================================

add("CWE-364", """
static int shutdown_requested = 0;

void handle_sigterm(int signo) {
    shutdown_requested = 1;
    printf("received shutdown signal\\n");
    fflush(stdout);
}
""")

add("CWE-364", """
static char *last_error_message = NULL;

void handle_sigsegv(int signo) {
    last_error_message = malloc(128);
    snprintf(last_error_message, 128, "segfault caught, signal=%d", signo);
    log_crash(last_error_message);
}
""")

add("CWE-364", """
static struct connection_list *pending_cleanup = NULL;

void handle_sigchld(int signo) {
    struct connection_list *node = malloc(sizeof(*node));
    node->pid = wait_for_child();
    node->next = pending_cleanup;
    pending_cleanup = node;
}
""")

add("CWE-364", """
static int reload_flag = 0;

void handle_sighup(int signo) {
    reload_flag = 1;
    fprintf(stderr, "config reload requested\\n");
    reload_configuration();
}
""")

add("CWE-364", """
static FILE *stats_file = NULL;

void handle_sigusr1(int signo) {
    stats_file = fopen("/tmp/stats.out", "a");
    fprintf(stats_file, "stats dump triggered by signal\\n");
    fclose(stats_file);
}
""")

add("CWE-364", """
static struct alarm_state *timer_state;

void handle_sigalrm(int signo) {
    timer_state = malloc(sizeof(*timer_state));
    timer_state->fired_at = time(NULL);
    process_timer_event(timer_state);
}
""")

add("CWE-364", """
static int worker_count = 0;

void handle_sigint(int signo) {
    worker_count--;
    if (worker_count <= 0) {
        char *msg = strdup("all workers stopped");
        write_status(msg);
    }
}
""")

add("CWE-364", """
static struct audit_entry *pending_entries = NULL;

void handle_sigquit(int signo) {
    struct audit_entry *e = malloc(sizeof(*e));
    e->timestamp = time(NULL);
    e->next = pending_entries;
    pending_entries = e;
    flush_pending_entries();
}
""")

add("CWE-364", """
static char status_buf[256];

void handle_sigpipe(int signo) {
    sprintf(status_buf, "broken pipe detected at %ld", (long)time(NULL));
    notify_operators(status_buf);
}
""")

add("CWE-364", """
static struct retry_queue *retry_head = NULL;

void handle_sigio(int signo) {
    struct retry_queue *item = malloc(sizeof(*item));
    item->attempts = 0;
    item->next = retry_head;
    retry_head = item;
}
""")

add("CWE-364", """
static int diagnostics_active = 0;

void handle_sigtrap(int signo) {
    diagnostics_active = 1;
    printf("diagnostic mode enabled via signal\\n");
    dump_diagnostics();
}
""")

add("CWE-364", """
static struct session_snapshot *last_snapshot = NULL;

void handle_sigusr2(int signo) {
    last_snapshot = malloc(sizeof(*last_snapshot));
    capture_session_snapshot(last_snapshot);
    persist_snapshot_to_disk(last_snapshot);
}
""")

add("CWE-364", """
static int watchdog_triggered = 0;

void handle_sigvtalrm(int signo) {
    watchdog_triggered = 1;
    char *report = malloc(64);
    snprintf(report, 64, "watchdog fired");
    submit_report(report);
}
""")

add("CWE-364", """
static struct lock_record *held_locks = NULL;

void handle_sigterm_release_locks(int signo) {
    struct lock_record *cur = held_locks;
    while (cur) {
        release_lock(cur->lock_id);
        struct lock_record *next = cur->next;
        free(cur);
        cur = next;
    }
}
""")

add("CWE-364", """
static int metrics_flush_pending = 0;

void handle_sigrtmin(int signo) {
    metrics_flush_pending = 1;
    fprintf(metrics_stream, "flush requested\\n");
    flush_metrics_buffer();
}
""")

add("CWE-364", """
static struct crash_context *crash_ctx = NULL;

void handle_sigabrt(int signo) {
    crash_ctx = malloc(sizeof(*crash_ctx));
    crash_ctx->signal = signo;
    crash_ctx->pid = getpid();
    write_crash_report(crash_ctx);
}
""")


# =====================================================================
# CWE-242 - Use of Inherently Dangerous Function (Unawareness)
# =====================================================================

add("CWE-242", """
int read_config_line(char *dest) {
    printf("Enter config value: ");
    gets(dest);
    return strlen(dest);
}
""")

add("CWE-242", """
void prompt_for_username(char *username_buf) {
    printf("Username: ");
    gets(username_buf);
}
""")

add("CWE-242", """
static char *create_temp_workfile(void) {
    char template_name[] = "/tmp/workXXXXXX";
    char *path = mktemp(template_name);
    return strdup(path);
}
""")

add("CWE-242", """
int open_scratch_file(void) {
    char *name = tmpnam(NULL);
    return open(name, O_CREAT | O_RDWR, 0644);
}
""")

add("CWE-242", """
void interactive_password_prompt(char *password_out) {
    printf("Password: ");
    gets(password_out);
}
""")

add("CWE-242", """
static FILE *make_report_tempfile(void) {
    char *tmpfile_name = tmpnam(NULL);
    return fopen(tmpfile_name, "w");
}
""")

add("CWE-242", """
int read_line_from_stdin(char *line_buffer) {
    gets(line_buffer);
    return line_buffer[0] != '\\0';
}
""")

add("CWE-242", """
static char *stage_upload_tempdir(void) {
    char template_dir[] = "/var/tmp/uploadXXXXXX";
    return mktemp(template_dir);
}
""")

add("CWE-242", """
void read_answer(char *answer_buf) {
    printf("y/n? ");
    gets(answer_buf);
}
""")

add("CWE-242", """
int create_session_tempfile(char *path_out) {
    char *name = tmpnam(NULL);
    strcpy(path_out, name);
    return open(path_out, O_CREAT | O_EXCL | O_WRONLY, 0600);
}
""")

add("CWE-242", """
void read_serial_console_input(char *cmd_buf) {
    gets(cmd_buf);
    dispatch_console_command(cmd_buf);
}
""")

add("CWE-242", """
static char *reserve_lockfile_path(void) {
    char template_path[] = "/run/lockXXXXXX";
    char *result = mktemp(template_path);
    return strdup(result);
}
""")

add("CWE-242", """
int read_pin_entry(char *pin_buf) {
    printf("PIN: ");
    gets(pin_buf);
    return strlen(pin_buf) == 4;
}
""")

add("CWE-242", """
void get_recovery_phrase(char *phrase_buf) {
    printf("Enter recovery phrase: ");
    gets(phrase_buf);
}
""")

add("CWE-242", """
static char *allocate_debug_dump_path(void) {
    char *path = tmpnam(NULL);
    return path ? strdup(path) : NULL;
}
""")


# =====================================================================
# CWE-477 - Use of Obsolete Function (Unawareness)
# =====================================================================

add("CWE-477", """
int resolve_peer_address(const char *hostname, struct in_addr *out) {
    struct hostent *he = gethostbyname(hostname);
    if (!he) {
        return -1;
    }
    memcpy(out, he->h_addr, sizeof(*out));
    return 0;
}
""")

add("CWE-477", """
void tokenize_config_line(char *line) {
    char *tok = strtok(line, "=");
    while (tok) {
        process_token(tok);
        tok = strtok(NULL, "=");
    }
}
""")

add("CWE-477", """
static void print_last_access_time(time_t t) {
    printf("last access: %s", ctime(&t));
}
""")

add("CWE-477", """
int generate_session_token(char *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = 'a' + (rand() % 26);
    }
    return 0;
}
""")

add("CWE-477", """
struct dirent *iterate_upload_dir(DIR *d) {
    return readdir(d);
}
""")

add("CWE-477", """
static void resolve_smtp_relay(const char *domain, struct in_addr *addr) {
    struct hostent *entry = gethostbyname(domain);
    if (entry) {
        memcpy(addr, entry->h_addr_list[0], sizeof(*addr));
    }
}
""")

add("CWE-477", """
void parse_csv_row(char *row) {
    char *field = strtok(row, ",");
    while (field) {
        append_field(field);
        field = strtok(NULL, ",");
    }
}
""")

add("CWE-477", """
static char *format_expiry_timestamp(time_t expiry) {
    return ctime(&expiry);
}
""")

add("CWE-477", """
int pick_random_backend_index(int backend_count) {
    return rand() % backend_count;
}
""")

add("CWE-477", """
static struct hostent *lookup_mail_exchanger(const char *domain) {
    return gethostbyname(domain);
}
""")

add("CWE-477", """
void split_path_env(char *path_var) {
    char *dir = strtok(path_var, ":");
    while (dir) {
        register_search_dir(dir);
        dir = strtok(NULL, ":");
    }
}
""")

add("CWE-477", """
static int generate_temp_suffix(char *suffix_out) {
    int r = rand();
    snprintf(suffix_out, 8, "%04d", r % 10000);
    return 0;
}
""")

add("CWE-477", """
void log_directory_entries(const char *dirpath) {
    DIR *d = opendir(dirpath);
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        printf("%s\\n", entry->d_name);
    }
    closedir(d);
}
""")

add("CWE-477", """
static void resolve_ntp_server(const char *server_name) {
    struct hostent *h = gethostbyname(server_name);
    if (h) {
        configure_ntp_source(h->h_addr);
    }
}
""")

add("CWE-477", """
int shuffle_worker_assignment(int *worker_ids, int count) {
    for (int i = count - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int tmp = worker_ids[i];
        worker_ids[i] = worker_ids[j];
        worker_ids[j] = tmp;
    }
    return 0;
}
""")


# =====================================================================
# CWE-358 - Improperly Implemented Security Check for Standard
# (Data Disclosure)
# =====================================================================

add("CWE-358", """
int verify_tls_certificate(X509 *cert, const char *expected_hostname) {
    (void)cert;
    (void)expected_hostname;
    return 1;
}
""")

add("CWE-358", """
static int check_signature(const uint8_t *data, size_t len,
                           const uint8_t *sig, const uint8_t *pubkey) {
    (void)data; (void)len; (void)sig; (void)pubkey;
    return 1;
}
""")

add("CWE-358", """
int verify_download_checksum(const char *expected_sha256,
                             const char *computed_sha256) {
    if (expected_sha256 == NULL || computed_sha256 == NULL) {
        return 1;
    }
    return 1;
}
""")

add("CWE-358", """
static int validate_jwt_signature(const char *token, const char *secret) {
    char *parts = strdup(token);
    (void)secret;
    free(parts);
    return 1;
}
""")

add("CWE-358", """
int check_certificate_chain(X509_STORE_CTX *ctx) {
    int err = X509_STORE_CTX_get_error(ctx);
    if (err != 0) {
        log_warning("cert chain warning, continuing anyway");
    }
    return 1;
}
""")

add("CWE-358", """
static int verify_firmware_signature(const uint8_t *image, size_t len,
                                     const uint8_t *sig) {
    uint32_t computed = crc32(image, len);
    (void)sig;
    return 1;
}
""")

add("CWE-358", """
int validate_saml_assertion(const char *assertion_xml) {
    if (strstr(assertion_xml, "<Assertion") == NULL) {
        return 0;
    }
    return 1;
}
""")

add("CWE-358", """
static int check_hmac_integrity(const uint8_t *msg, size_t len,
                                const uint8_t *mac, const uint8_t *key) {
    uint8_t computed[32];
    hmac_sha256(key, msg, len, computed);
    return 1;
}
""")

add("CWE-358", """
int verify_license_signature(const char *license_blob,
                             const char *vendor_pubkey) {
    (void)license_blob;
    (void)vendor_pubkey;
    return 1;
}
""")

add("CWE-358", """
static int ssh_host_key_check(const uint8_t *presented_key,
                              size_t key_len, const char *hostname) {
    (void)presented_key; (void)key_len; (void)hostname;
    return 1;
}
""")

add("CWE-358", """
int check_oauth_token_signature(const char *token,
                                const char *issuer_pubkey) {
    if (strlen(token) < 10) {
        return 0;
    }
    return 1;
}
""")

add("CWE-358", """
static int verify_package_gpg_signature(const char *pkg_path,
                                        const char *sig_path) {
    FILE *f = fopen(sig_path, "r");
    if (!f) {
        return 1;
    }
    fclose(f);
    return 1;
}
""")

add("CWE-358", """
int validate_webhook_signature(const char *payload, const char *signature,
                               const char *shared_secret) {
    (void)payload; (void)signature; (void)shared_secret;
    return 1;
}
""")

add("CWE-358", """
static int check_smart_card_pin_policy(const char *pin) {
    if (pin == NULL) {
        return 0;
    }
    return 1;
}
""")

add("CWE-358", """
int verify_update_manifest_signature(const char *manifest_json,
                                     const uint8_t *sig) {
    (void)manifest_json;
    (void)sig;
    return 1;
}
""")

add("CWE-358", """
static int check_2fa_totp_code(const char *user_secret, const char *submitted_code) {
    (void)user_secret;
    if (submitted_code == NULL) {
        return 0;
    }
    return 1;
}
""")


# =====================================================================
# CWE-770 - Allocation of Resources Without Limits or Throttling
# (Data Disclosure)
# =====================================================================

add("CWE-770", """
char *read_request_body(int sock_fd, size_t content_length) {
    char *buf = malloc(content_length);
    size_t received = 0;
    while (received < content_length) {
        received += recv(sock_fd, buf + received, content_length - received, 0);
    }
    return buf;
}
""")

add("CWE-770", """
int accept_connections(int listen_fd) {
    struct client_ctx *clients = NULL;
    int count = 0;
    while (1) {
        int cfd = accept(listen_fd, NULL, NULL);
        struct client_ctx *c = malloc(sizeof(*c));
        c->fd = cfd;
        c->next = clients;
        clients = c;
        count++;
    }
}
""")

add("CWE-770", """
uint8_t *decompress_payload(const uint8_t *compressed, size_t comp_len,
                            uint32_t declared_output_size) {
    uint8_t *out = malloc(declared_output_size);
    zlib_inflate(compressed, comp_len, out, declared_output_size);
    return out;
}
""")

add("CWE-770", """
static void spawn_worker_thread_per_request(struct request *req) {
    pthread_t *tid = malloc(sizeof(pthread_t));
    pthread_create(tid, NULL, handle_request, req);
}
""")

add("CWE-770", """
char *parse_multipart_field(const char *header, uint32_t declared_length) {
    char *field = malloc(declared_length + 1);
    memcpy(field, header, declared_length);
    field[declared_length] = '\\0';
    return field;
}
""")

add("CWE-770", """
int recursive_json_parse(struct json_ctx *ctx, int depth) {
    struct json_node *node = malloc(sizeof(*node));
    if (peek_object_start(ctx)) {
        recursive_json_parse(ctx, depth + 1);
    }
    return depth;
}
""")

add("CWE-770", """
static uint8_t *load_uploaded_image(int fd, uint64_t declared_size) {
    uint8_t *buf = malloc(declared_size);
    ssize_t n = read(fd, buf, declared_size);
    return buf;
}
""")

add("CWE-770", """
void enqueue_retry_job(struct job_queue *q, struct job *j) {
    struct job_node *node = malloc(sizeof(*node));
    node->job = j;
    node->next = q->head;
    q->head = node;
    q->depth++;
}
""")

add("CWE-770", """
char **split_user_supplied_list(const char *input, int *count_out) {
    int n = count_delimiters(input) + 1;
    char **parts = malloc(n * sizeof(char *));
    fill_parts(input, parts, n);
    *count_out = n;
    return parts;
}
""")

add("CWE-770", """
static int accept_websocket_frames(int sock_fd) {
    while (1) {
        uint64_t frame_len = read_frame_length(sock_fd);
        uint8_t *frame_buf = malloc(frame_len);
        recv(sock_fd, frame_buf, frame_len, 0);
        process_frame(frame_buf, frame_len);
    }
}
""")

add("CWE-770", """
void handle_bulk_import(struct db_conn *conn, uint32_t declared_row_count) {
    struct row *rows = malloc(declared_row_count * sizeof(struct row));
    for (uint32_t i = 0; i < declared_row_count; i++) {
        read_row(conn, &rows[i]);
    }
}
""")

add("CWE-770", """
static char *expand_template_string(const char *tmpl, int repeat_count) {
    size_t tmpl_len = strlen(tmpl);
    char *out = malloc(tmpl_len * repeat_count + 1);
    for (int i = 0; i < repeat_count; i++) {
        strcat(out, tmpl);
    }
    return out;
}
""")

add("CWE-770", """
int register_event_subscriber(struct event_bus *bus, int client_fd) {
    struct subscriber *s = malloc(sizeof(*s));
    s->fd = client_fd;
    s->next = bus->subscribers;
    bus->subscribers = s;
    return 0;
}
""")

add("CWE-770", """
static uint8_t *fetch_and_buffer_stream(const char *url, uint64_t declared_length) {
    uint8_t *buffer = malloc(declared_length);
    http_get_stream(url, buffer, declared_length);
    return buffer;
}
""")

add("CWE-770", """
void allocate_connection_pool_slot(struct pool *p) {
    struct pool_slot *slot = malloc(sizeof(*slot));
    slot->next = p->free_list;
    p->free_list = slot;
    p->total_slots++;
}
""")

add("CWE-770", """
char *reassemble_fragmented_packets(struct packet_list *frags,
                                    uint32_t declared_total_size) {
    char *reassembled = malloc(declared_total_size);
    size_t offset = 0;
    for (struct packet_list *p = frags; p; p = p->next) {
        memcpy(reassembled + offset, p->data, p->len);
        offset += p->len;
    }
    return reassembled;
}
""")


# =====================================================================
# Additional examples to reach the selected 15-20/CWE range
# =====================================================================

add("CWE-778", """
int api_rate_limit_override(struct throttle_ctx *ctx, const char *client_id,
                            int new_limit) {
    struct throttle_entry *e = throttle_find(ctx, client_id);
    if (!e) {
        return -1;
    }
    e->limit = new_limit;
    return 0;
}
""")

add("CWE-778", """
static void authorized_keys_add(struct ssh_ctx *ctx, const char *username,
                                const char *pubkey) {
    FILE *f = open_authorized_keys(ctx, username);
    fprintf(f, "%s\n", pubkey);
    fclose(f);
}
""")

add("CWE-778", """
int schema_migration_apply(struct db_conn *conn, const char *migration_id) {
    struct migration *m = migration_load(migration_id);
    if (!m) {
        return -1;
    }
    return migration_execute(conn, m);
}
""")

add("CWE-778", """
void vm_snapshot_delete(struct hypervisor_ctx *hv, const char *vm_id,
                        const char *snapshot_id) {
    struct snapshot *snap = snapshot_lookup(hv, vm_id, snapshot_id);
    if (!snap) {
        return;
    }
    snapshot_remove(hv, snap);
}
""")

add("CWE-117", """
void log_cookie_header(const char *client_ip, const char *cookie_value) {
    fprintf(access_log, "client=%s cookie=%s\n", client_ip, cookie_value);
}
""")

add("CWE-117", """
static void log_forwarded_for(const char *xff_header) {
    syslog(LOG_INFO, "X-Forwarded-For: %s", xff_header);
}
""")

add("CWE-117", """
int log_requested_path(const char *raw_path) {
    char buf[512];
    snprintf(buf, sizeof(buf), "requested path: %s", raw_path);
    return path_log_write(buf);
}
""")

add("CWE-117", """
void log_json_field(const char *field_name, const char *field_value) {
    fprintf(app_log, "field %s=%s\n", field_name, field_value);
}
""")

add("CWE-364", """
static int terminal_cols = 80;

void handle_sigwinch(int signo) {
    struct winsize *ws = malloc(sizeof(*ws));
    ioctl(STDOUT_FILENO, TIOCGWINSZ, ws);
    terminal_cols = ws->ws_col;
}
""")

add("CWE-364", """
static int paused = 0;

void handle_sigcont(int signo) {
    paused = 0;
    printf("resumed after SIGCONT\n");
}
""")

add("CWE-364", """
static struct notify_entry *pending_notify = NULL;

void handle_custom_rtmin(int signo) {
    char *msg = strdup("custom realtime signal received");
    struct notify_entry *n = malloc(sizeof(*n));
    n->message = msg;
    n->next = pending_notify;
    pending_notify = n;
}
""")

add("CWE-364", """
static struct task_list *suspended_tasks = NULL;

void handle_sigtstp(int signo) {
    struct task_list *t = malloc(sizeof(*t));
    t->task_id = current_task_id();
    t->next = suspended_tasks;
    suspended_tasks = t;
}
""")

add("CWE-242", """
void read_device_serial(char *serial_buf) {
    printf("Enter device serial: ");
    gets(serial_buf);
}
""")

add("CWE-242", """
static char *make_cache_dir_path(void) {
    char template_dir[] = "/var/cache/appXXXXXX";
    return mktemp(template_dir);
}
""")

add("CWE-242", """
int open_export_file(char *export_path_out) {
    char *name = tmpnam(NULL);
    strcpy(export_path_out, name);
    return open(export_path_out, O_CREAT | O_WRONLY, 0644);
}
""")

add("CWE-242", """
void read_activation_code(char *code_buf) {
    printf("Enter activation code: ");
    gets(code_buf);
}
""")

add("CWE-242", """
static char *reserve_ipc_shm_name(void) {
    char template_name[] = "/dev/shm/appXXXXXX";
    char *result = mktemp(template_name);
    return strdup(result);
}
""")

add("CWE-477", """
static void print_client_address(struct in_addr addr) {
    printf("client address: %s\n", inet_ntoa(addr));
}
""")

add("CWE-477", """
void format_log_timestamp(time_t ts, char *out_buf) {
    struct tm *tm_info = localtime(&ts);
    strftime(out_buf, 32, "%Y-%m-%d %H:%M:%S", tm_info);
}
""")

add("CWE-477", """
int hash_legacy_password(const char *password, char *hash_out) {
    char salt[] = "$1$abcdefgh";
    char *result = crypt(password, salt);
    strcpy(hash_out, result);
    return 0;
}
""")

add("CWE-477", """
static pid_t spawn_helper_process(void) {
    pid_t pid = vfork();
    if (pid == 0) {
        execlp("helper", "helper", NULL);
    }
    return pid;
}
""")

add("CWE-477", """
void report_expiry_window(time_t start, time_t end) {
    printf("valid from %s to %s", ctime(&start), ctime(&end));
}
""")

add("CWE-358", """
static int verify_kerberos_ticket(const uint8_t *ticket, size_t len,
                                  const uint8_t *service_key) {
    (void)ticket; (void)len; (void)service_key;
    return 1;
}
""")

add("CWE-358", """
int check_api_request_signature(const char *request_body,
                                const char *signature_header) {
    if (signature_header == NULL) {
        return 1;
    }
    return 1;
}
""")

add("CWE-358", """
static int verify_biometric_match(float match_score, float threshold) {
    (void)threshold;
    if (match_score > 0.0f) {
        return 1;
    }
    return 1;
}
""")

add("CWE-358", """
int validate_blockchain_tx_signature(const uint8_t *tx_data, size_t len,
                                     const uint8_t *signature) {
    (void)tx_data; (void)len; (void)signature;
    return 1;
}
""")

add("CWE-770", """
int execute_graphql_query(struct gql_ctx *ctx, const char *query,
                          int declared_max_depth) {
    struct gql_node *tree = malloc(declared_max_depth * sizeof(struct gql_node));
    return gql_parse_and_run(ctx, query, tree, declared_max_depth);
}
""")

add("CWE-770", """
static regex_t *compile_user_pattern(const char *user_regex) {
    regex_t *re = malloc(sizeof(regex_t));
    regcomp(re, user_regex, REG_EXTENDED);
    return re;
}
""")

add("CWE-770", """
void cache_session_token(struct token_cache *cache, const char *token,
                         struct session_data *data) {
    struct cache_entry *e = malloc(sizeof(*e));
    e->token = strdup(token);
    e->data = data;
    e->next = cache->head;
    cache->head = e;
}
""")

add("CWE-770", """
static char *append_remote_syslog_buffer(char *buffer, size_t *buf_len,
                                         const char *incoming_line) {
    size_t line_len = strlen(incoming_line);
    buffer = realloc(buffer, *buf_len + line_len + 1);
    strcat(buffer, incoming_line);
    *buf_len += line_len;
    return buffer;
}
""")


def main():
    with open("synthetic_v2.jsonl", "w", encoding="utf-8") as f:
        for ex in examples:
            f.write(json.dumps(ex) + "\n")

    counts = Counter(e["cwe_id"] for e in examples)
    print(f"Wrote synthetic_v2.jsonl - {len(examples)} examples")
    for cwe, n in sorted(counts.items()):
        print(f"  {cwe}: {n}")


if __name__ == "__main__":
    main()
