/*
 * server.c - Banking Management System server (CS-513 System Software mini project)
 *
 * Design in one paragraph:
 *   - TCP server; every accepted client is served by its own POSIX thread.
 *   - A counting semaphore limits the number of clients served at once.
 *   - A pthread mutex protects the in-memory table of logged-in users
 *     (one active session per user).
 *   - Data is kept in fixed-width text files under data/. Shared records are
 *     protected with fcntl() record locks (Linux "open file description" locks,
 *     which also work between threads of the same process).
 *   - A forked child process acts as a logger; worker threads send it log
 *     lines through a pipe (IPC).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <crypt.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_PORT 8080
#define MAX_CLIENTS 10
#define LINE_LEN 1024
#define RESP_LEN 16384
#define MAX_ARGS 8
#define MAX_RUPEES 10000000LL      /* largest amount accepted in one request */
#define FIRST_ACC_NO 1001          /* account number = FIRST_ACC_NO + record index */
#define HISTORY_LINES 50

#define DATA_DIR "data"
#define USERS_FILE "data/users.txt"
#define ACCOUNTS_FILE "data/accounts.txt"
#define LOANS_FILE "data/loans.txt"
#define TXN_FILE "data/transactions.txt"
#define FEEDBACK_FILE "data/feedback.txt"
#define LOG_FILE "data/server.log"

/* Fixed record lengths (including the trailing newline). Record i starts at i * LEN. */
#define USER_REC 192
#define ACC_REC 64
#define LOAN_REC 128
#define WHOLE_FILE -1

/* Role bits used by the command table for authorization. */
#define R_CUSTOMER 1
#define R_EMPLOYEE 2
#define R_MANAGER 4
#define R_ADMIN 8
#define R_ANY (R_CUSTOMER | R_EMPLOYEE | R_MANAGER | R_ADMIN)

typedef struct {
    char username[21];
    char role[9];          /* CUSTOMER, EMPLOYEE, MANAGER, ADMIN */
    char name[31];
    char phone[16];
    char hash[128];        /* crypt() SHA-512 hash, never the plain password */
} User;

typedef struct {
    int acc_no;
    char owner[21];
    char type[9];          /* SAVINGS or CURRENT */
    long long balance;     /* in paise, avoids floating point errors */
    char status[9];        /* ACTIVE, INACTIVE or CLOSED */
} Account;

typedef struct {
    int id;
    char owner[21];
    int acc_no;
    long long amount;      /* in paise */
    char purpose[41];
    char status[9];        /* PENDING, ASSIGNED, APPROVED, REJECTED */
    char assigned[21];     /* employee username or "-" */
} Loan;

typedef struct {
    int sock;
    int logged_in;
    User user;
} Client;

typedef void (*Handler)(Client *c, char **arg, char *resp);

typedef struct {
    const char *name;
    int roles;             /* which roles may run this command */
    int nargs;             /* exact number of arguments expected */
    Handler fn;
} Command;

static sem_t client_slots;                                   /* free client slots */
static pthread_mutex_t session_lock = PTHREAD_MUTEX_INITIALIZER;
static char sessions[MAX_CLIENTS][21];                       /* logged-in usernames */
static int log_pipe_fd = -1;                                 /* write end of logger pipe */
static int demo_delay = 0;                                   /* -d option, seconds */
static volatile sig_atomic_t stop_server = 0;

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

static void copy_str(char *dst, size_t size, const char *src)
{
    snprintf(dst, size, "%s", src);
}

static char *trim(char *s)
{
    while (isspace((unsigned char)*s))
        s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1]))
        *--end = '\0';
    return s;
}

/* Splits "A|B|C" in place. Used for both requests and file records. */
static int split_fields(char *line, char *fields[], int max)
{
    int n = 0;
    char *p = line;
    while (n < max) {
        char *bar = strchr(p, '|');
        if (bar)
            *bar = '\0';
        fields[n++] = trim(p);
        if (!bar)
            break;
        p = bar + 1;
    }
    return n;
}

static void now_str(char *buf, size_t size)
{
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(buf, size, "%Y-%m-%d %H:%M:%S", &tm);
}

static char *money(long long paise, char *buf)
{
    snprintf(buf, 32, "%lld.%02lld", paise / 100, paise % 100);
    return buf;
}

/* Appends formatted text to the response buffer. */
static void reply(char *resp, const char *fmt, ...)
{
    size_t used = strlen(resp);
    if (used >= RESP_LEN - 1)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(resp + used, RESP_LEN - used, fmt, ap);
    va_end(ap);
}

/* Sends one line to the logger process. Writes below PIPE_BUF are atomic,
 * so lines from different threads never get mixed. */
static void log_event(const char *fmt, ...)
{
    char msg[400], line[512], ts[32];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    now_str(ts, sizeof ts);
    int len = snprintf(line, sizeof line, "[%s] %s\n", ts, msg);
    if (log_pipe_fd >= 0 && len > 0) {
        ssize_t ignored = write(log_pipe_fd, line, strlen(line));
        (void)ignored;
    }
}

/* ------------------------------------------------------------------ */
/* Input validation                                                    */
/* ------------------------------------------------------------------ */

/* Accepts "250", "250.5", "250.75". Result is in paise. */
static int parse_amount(const char *s, long long *paise)
{
    long long rupees = 0, frac = 0;
    int i = 0, digits = 0;
    if (!isdigit((unsigned char)s[0]))
        return -1;
    while (isdigit((unsigned char)s[i])) {
        rupees = rupees * 10 + (s[i++] - '0');
        if (rupees > MAX_RUPEES)
            return -1;
    }
    if (s[i] == '.') {
        i++;
        while (isdigit((unsigned char)s[i]) && digits < 2) {
            frac = frac * 10 + (s[i++] - '0');
            digits++;
        }
        if (digits == 0)
            return -1;
        if (digits == 1)
            frac *= 10;
    }
    if (s[i] != '\0')
        return -1;
    *paise = rupees * 100 + frac;
    return (*paise > 0 && *paise <= MAX_RUPEES * 100) ? 0 : -1;
}

static int parse_number(const char *s, int min, int *out)
{
    char *end;
    long v = strtol(s, &end, 10);
    if (*s == '\0' || *end != '\0' || v < min || v > 999999)
        return -1;
    *out = (int)v;
    return 0;
}

static int parse_acc(const char *s, int *acc_no)
{
    return parse_number(s, FIRST_ACC_NO, acc_no);
}

static int valid_username(const char *s)
{
    size_t n = strlen(s);
    if (n < 3 || n > 20)
        return 0;
    for (size_t i = 0; i < n; i++)
        if (!isalnum((unsigned char)s[i]) && s[i] != '_')
            return 0;
    return 1;
}

static int valid_text(const char *s, size_t max)
{
    size_t n = strlen(s);
    if (n == 0 || n > max)
        return 0;
    for (size_t i = 0; i < n; i++)
        if (iscntrl((unsigned char)s[i]))
            return 0;
    return 1;
}

static int valid_password(const char *s)
{
    return strlen(s) >= 4 && valid_text(s, 30);
}

static int valid_phone(const char *s)
{
    size_t n = strlen(s);
    if (n < 7 || n > 15)
        return 0;
    for (size_t i = 0; i < n; i++)
        if (!isdigit((unsigned char)s[i]) && !(i == 0 && s[i] == '+'))
            return 0;
    return 1;
}

static int valid_acc_type(const char *s)
{
    return strcmp(s, "SAVINGS") == 0 || strcmp(s, "CURRENT") == 0;
}

static int valid_staff_role(const char *s)
{
    return strcmp(s, "EMPLOYEE") == 0 || strcmp(s, "MANAGER") == 0;
}

static int role_bit(const char *role)
{
    if (strcmp(role, "CUSTOMER") == 0) return R_CUSTOMER;
    if (strcmp(role, "EMPLOYEE") == 0) return R_EMPLOYEE;
    if (strcmp(role, "MANAGER") == 0) return R_MANAGER;
    if (strcmp(role, "ADMIN") == 0) return R_ADMIN;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Password hashing with the system crypt library (SHA-512, random salt) */
/* ------------------------------------------------------------------ */

static void make_hash(const char *password, char *out, size_t size)
{
    const char *chars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    unsigned char rnd[12] = {0};
    char salt[32] = "$6$";
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t ignored = read(fd, rnd, sizeof rnd);
        (void)ignored;
        close(fd);
    }
    for (int i = 0; i < 12; i++)
        salt[3 + i] = chars[rnd[i] % 64];
    salt[15] = '$';
    salt[16] = '\0';

    struct crypt_data cd;               /* crypt_r is the thread-safe version */
    memset(&cd, 0, sizeof cd);
    char *hash = crypt_r(password, salt, &cd);
    copy_str(out, size, hash ? hash : "");
}

static int check_password(const char *password, const char *hash)
{
    struct crypt_data cd;
    memset(&cd, 0, sizeof cd);
    char *h = crypt_r(password, hash, &cd);
    return h != NULL && strcmp(h, hash) == 0;
}

/* ------------------------------------------------------------------ */
/* Fixed-width record I/O and file locking                             */
/* ------------------------------------------------------------------ */

/* Locks one record (idx >= 0) or the whole file (idx == WHOLE_FILE).
 * type is F_RDLCK (shared), F_WRLCK (exclusive) or F_UNLCK.
 * F_OFD_SETLKW blocks until the lock is granted. */
static int lock_record(int fd, int idx, int reclen, short type)
{
    struct flock fl;
    memset(&fl, 0, sizeof fl);
    fl.l_type = type;
    fl.l_whence = SEEK_SET;
    fl.l_start = (idx == WHOLE_FILE) ? 0 : (off_t)idx * reclen;
    fl.l_len = (idx == WHOLE_FILE) ? 0 : reclen;     /* 0 means "to end of file" */
    int rc;
    while ((rc = fcntl(fd, F_OFD_SETLKW, &fl)) == -1 && errno == EINTR)
        ;
    return rc;
}

static void make_record(char *rec, int reclen, const char *content)
{
    size_t len = strlen(content);
    if (len > (size_t)reclen - 1)
        len = reclen - 1;
    memset(rec, ' ', reclen - 1);
    memcpy(rec, content, len);
    rec[reclen - 1] = '\n';
    rec[reclen] = '\0';
}

static int read_record(int fd, int idx, int reclen, char *rec)
{
    if (idx < 0 || pread(fd, rec, reclen, (off_t)idx * reclen) != reclen)
        return -1;
    rec[reclen] = '\0';
    return 0;
}

static int write_record(int fd, int idx, int reclen, const char *rec)
{
    if (pwrite(fd, rec, reclen, (off_t)idx * reclen) != reclen)
        return -1;
    return fsync(fd);
}

static int record_count(int fd, int reclen)
{
    struct stat st;
    if (fstat(fd, &st) < 0)
        return 0;
    return (int)(st.st_size / reclen);
}

/* Appends one text line to a log-style file under an exclusive lock. */
static void append_line(const char *path, const char *line)
{
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd < 0)
        return;
    lock_record(fd, WHOLE_FILE, 0, F_WRLCK);
    ssize_t ignored = write(fd, line, strlen(line));
    (void)ignored;
    fsync(fd);
    lock_record(fd, WHOLE_FILE, 0, F_UNLCK);
    close(fd);
}

/* ---- users.txt : username|role|name|phone|hash| ---- */

static void encode_user(const User *u, char *rec)
{
    char tmp[256];
    snprintf(tmp, sizeof tmp, "%-20s|%-8s|%-30s|%-15s|%s|",
             u->username, u->role, u->name, u->phone, u->hash);
    make_record(rec, USER_REC, tmp);
}

static int decode_user(char *rec, User *u)
{
    char *f[6];
    if (split_fields(rec, f, 6) < 5)
        return -1;
    copy_str(u->username, sizeof u->username, f[0]);
    copy_str(u->role, sizeof u->role, f[1]);
    copy_str(u->name, sizeof u->name, f[2]);
    copy_str(u->phone, sizeof u->phone, f[3]);
    copy_str(u->hash, sizeof u->hash, f[4]);
    return 0;
}

/* Linear search; the caller must already hold a lock on fd. */
static int scan_user(int fd, const char *username, User *out)
{
    char rec[USER_REC + 1];
    int n = record_count(fd, USER_REC);
    for (int i = 0; i < n; i++) {
        User u;
        if (read_record(fd, i, USER_REC, rec) == 0 && decode_user(rec, &u) == 0 &&
            strcmp(u.username, username) == 0) {
            if (out)
                *out = u;
            return i;
        }
    }
    return -1;
}

static int find_user(const char *username, User *out)
{
    int fd = open(USERS_FILE, O_RDONLY);
    if (fd < 0)
        return -1;
    lock_record(fd, WHOLE_FILE, 0, F_RDLCK);
    int idx = scan_user(fd, username, out);
    lock_record(fd, WHOLE_FILE, 0, F_UNLCK);
    close(fd);
    return idx;
}

/* Returns 0 on success, -2 if the username exists, -1 on I/O error. */
static int add_user(const User *u)
{
    int fd = open(USERS_FILE, O_RDWR);
    if (fd < 0)
        return -1;
    lock_record(fd, WHOLE_FILE, 0, F_WRLCK);   /* no one may append at the same time */
    int rc = -2;
    if (scan_user(fd, u->username, NULL) < 0) {
        char rec[USER_REC + 1];
        encode_user(u, rec);
        rc = write_record(fd, record_count(fd, USER_REC), USER_REC, rec);
    }
    lock_record(fd, WHOLE_FILE, 0, F_UNLCK);
    close(fd);
    return rc;
}

/* Write-locks one user's record and loads it. Returns an fd, or -1.
 * Must be followed by save_user_unlock(). */
static int lock_user(const char *username, int *idx, User *u)
{
    char rec[USER_REC + 1];
    int i = find_user(username, NULL);     /* records are never deleted, so idx is stable */
    if (i < 0)
        return -1;
    int fd = open(USERS_FILE, O_RDWR);
    if (fd < 0)
        return -1;
    lock_record(fd, i, USER_REC, F_WRLCK);
    if (read_record(fd, i, USER_REC, rec) != 0 || decode_user(rec, u) != 0) {
        lock_record(fd, i, USER_REC, F_UNLCK);
        close(fd);
        return -1;
    }
    *idx = i;
    return fd;
}

/* Saves u (if not NULL), releases the record lock and closes fd. */
static int save_user_unlock(int fd, int idx, const User *u)
{
    int rc = 0;
    if (u) {
        char rec[USER_REC + 1];
        encode_user(u, rec);
        rc = write_record(fd, idx, USER_REC, rec);
    }
    lock_record(fd, idx, USER_REC, F_UNLCK);
    close(fd);
    return rc;
}

/* ---- accounts.txt : acc_no|owner|type|balance_paise|status| ---- */

static void encode_account(const Account *a, char *rec)
{
    char tmp[128];
    snprintf(tmp, sizeof tmp, "%6d|%-20s|%-8s|%15lld|%-8s|",
             a->acc_no, a->owner, a->type, a->balance, a->status);
    make_record(rec, ACC_REC, tmp);
}

static int decode_account(char *rec, Account *a)
{
    char *f[6];
    if (split_fields(rec, f, 6) < 5)
        return -1;
    a->acc_no = atoi(f[0]);
    copy_str(a->owner, sizeof a->owner, f[1]);
    copy_str(a->type, sizeof a->type, f[2]);
    a->balance = atoll(f[3]);
    copy_str(a->status, sizeof a->status, f[4]);
    return 0;
}

/* acc_no must already be validated with parse_acc() (>= FIRST_ACC_NO). */
static void lock_account(int fd, int acc_no, short type)
{
    lock_record(fd, acc_no - FIRST_ACC_NO, ACC_REC, type);
}

static int load_account(int fd, int acc_no, Account *a)
{
    char rec[ACC_REC + 1];
    if (read_record(fd, acc_no - FIRST_ACC_NO, ACC_REC, rec) != 0)
        return -1;
    return decode_account(rec, a);
}

static int save_account(int fd, const Account *a)
{
    char rec[ACC_REC + 1];
    encode_account(a, rec);
    return write_record(fd, a->acc_no - FIRST_ACC_NO, ACC_REC, rec);
}

/* Reads one account under a shared (read) lock. */
static int get_account(int acc_no, Account *a)
{
    int fd = open(ACCOUNTS_FILE, O_RDONLY);
    if (fd < 0)
        return -1;
    lock_account(fd, acc_no, F_RDLCK);
    int rc = load_account(fd, acc_no, a);
    lock_account(fd, acc_no, F_UNLCK);
    close(fd);
    return rc;
}

/* Returns the customer's account number that is not CLOSED, or -1. */
static int find_customer_account(const char *owner)
{
    int fd = open(ACCOUNTS_FILE, O_RDONLY), found = -1;
    if (fd < 0)
        return -1;
    lock_record(fd, WHOLE_FILE, 0, F_RDLCK);
    int n = record_count(fd, ACC_REC);
    for (int i = 0; i < n && found < 0; i++) {
        Account a;
        if (load_account(fd, FIRST_ACC_NO + i, &a) == 0 &&
            strcmp(a.owner, owner) == 0 && strcmp(a.status, "CLOSED") != 0)
            found = a.acc_no;
    }
    lock_record(fd, WHOLE_FILE, 0, F_UNLCK);
    close(fd);
    return found;
}

static void add_transaction(int acc_no, const char *type, long long amount,
                            long long balance, const char *details)
{
    char line[256], ts[32], m1[32], m2[32];
    now_str(ts, sizeof ts);
    snprintf(line, sizeof line, "%s|%d|%s|%s|%s|%s\n", ts, acc_no, type,
             money(amount, m1), money(balance, m2), details);
    append_line(TXN_FILE, line);
}

/* Opens a new account. Returns the account number, -2 if the customer
 * already has an open account, or -1 on error. */
static int create_account(const char *owner, const char *type, long long balance)
{
    int fd = open(ACCOUNTS_FILE, O_RDWR);
    if (fd < 0)
        return -1;
    lock_record(fd, WHOLE_FILE, 0, F_WRLCK);
    int n = record_count(fd, ACC_REC), result = 0;
    for (int i = 0; i < n; i++) {
        Account old;
        if (load_account(fd, FIRST_ACC_NO + i, &old) == 0 &&
            strcmp(old.owner, owner) == 0 && strcmp(old.status, "CLOSED") != 0)
            result = -2;
    }
    if (result == 0) {
        Account a;
        memset(&a, 0, sizeof a);
        a.acc_no = FIRST_ACC_NO + n;
        a.balance = balance;
        copy_str(a.owner, sizeof a.owner, owner);
        copy_str(a.type, sizeof a.type, type);
        copy_str(a.status, sizeof a.status, "ACTIVE");
        result = (save_account(fd, &a) == 0) ? a.acc_no : -1;
    }
    lock_record(fd, WHOLE_FILE, 0, F_UNLCK);
    close(fd);
    if (result > 0 && balance > 0)
        add_transaction(result, "OPENING", balance, balance, "Initial deposit");
    return result;
}

/* Used with "-d N": keeps the lock held for N seconds so that a second
 * client visibly waits. Shows that the critical section is serialized. */
static void demo_pause(int acc_no)
{
    if (demo_delay > 0) {
        log_event("DEMO: account %d is locked, sleeping %d s inside critical section",
                  acc_no, demo_delay);
        sleep(demo_delay);
    }
}

/* Adds delta (negative for a debit) to one account as a single critical
 * section. Returns NULL on success or an error message. */
static const char *change_balance(int acc_no, long long delta, const char *type,
                                  const char *details, long long *new_balance)
{
    const char *err = NULL;
    Account a;
    int fd = open(ACCOUNTS_FILE, O_RDWR);
    if (fd < 0)
        return "Could not open accounts file";

    lock_account(fd, acc_no, F_WRLCK);                 /* ---- critical section ---- */
    if (load_account(fd, acc_no, &a) != 0)
        err = "Account not found";
    else if (strcmp(a.status, "ACTIVE") != 0)
        err = "Account is not active";
    else if (a.balance + delta < 0)
        err = "Insufficient balance";
    else {
        demo_pause(acc_no);
        a.balance += delta;
        if (save_account(fd, &a) != 0)
            err = "Could not save account";
        else {
            add_transaction(acc_no, type, delta < 0 ? -delta : delta, a.balance, details);
            *new_balance = a.balance;
        }
    }
    lock_account(fd, acc_no, F_UNLCK);                 /* ---- end critical section ---- */
    close(fd);
    return err;
}

/* ---- loans.txt : id|owner|acc_no|amount_paise|purpose|status|assigned| ---- */

static void encode_loan(const Loan *l, char *rec)
{
    char tmp[256];
    snprintf(tmp, sizeof tmp, "%6d|%-20s|%6d|%15lld|%-40s|%-8s|%-20s|",
             l->id, l->owner, l->acc_no, l->amount, l->purpose, l->status, l->assigned);
    make_record(rec, LOAN_REC, tmp);
}

static int decode_loan(char *rec, Loan *l)
{
    char *f[8];
    if (split_fields(rec, f, 8) < 7)
        return -1;
    l->id = atoi(f[0]);
    copy_str(l->owner, sizeof l->owner, f[1]);
    l->acc_no = atoi(f[2]);
    l->amount = atoll(f[3]);
    copy_str(l->purpose, sizeof l->purpose, f[4]);
    copy_str(l->status, sizeof l->status, f[5]);
    copy_str(l->assigned, sizeof l->assigned, f[6]);
    return 0;
}

static int load_loan(int fd, int id, Loan *l)
{
    char rec[LOAN_REC + 1];
    if (read_record(fd, id - 1, LOAN_REC, rec) != 0)
        return -1;
    return decode_loan(rec, l);
}

static int save_loan(int fd, const Loan *l)
{
    char rec[LOAN_REC + 1];
    encode_loan(l, rec);
    return write_record(fd, l->id - 1, LOAN_REC, rec);
}

/* Prints all loans, or only those assigned to `employee` (status ASSIGNED). */
static void list_loans(char *resp, const char *employee)
{
    char m[32];
    int fd = open(LOANS_FILE, O_RDONLY), shown = 0;
    if (fd < 0) {
        reply(resp, "ERR Could not open loans file\n");
        return;
    }
    reply(resp, "OK Loan applications\n%-4s %-12s %-6s %12s %-9s %-10s %s\n",
          "ID", "Customer", "Acc", "Amount", "Status", "Assigned", "Purpose");
    lock_record(fd, WHOLE_FILE, 0, F_RDLCK);
    int n = record_count(fd, LOAN_REC);
    for (int i = 1; i <= n; i++) {
        Loan l;
        if (load_loan(fd, i, &l) != 0)
            continue;
        if (employee && (strcmp(l.assigned, employee) != 0 || strcmp(l.status, "ASSIGNED") != 0))
            continue;
        reply(resp, "%-4d %-12s %-6d %12s %-9s %-10s %s\n", l.id, l.owner, l.acc_no,
              money(l.amount, m), l.status, l.assigned, l.purpose);
        shown++;
    }
    lock_record(fd, WHOLE_FILE, 0, F_UNLCK);
    close(fd);
    if (shown == 0)
        reply(resp, "(no loan applications)\n");
}

/* Prints the latest HISTORY_LINES transactions of one account. */
static void show_passbook(int acc_no, char *resp)
{
    char recent[HISTORY_LINES][160], line[256];
    int count = 0;
    int fd = open(TXN_FILE, O_RDONLY);
    if (fd < 0) {
        reply(resp, "ERR Could not open transactions file\n");
        return;
    }
    lock_record(fd, WHOLE_FILE, 0, F_RDLCK);
    FILE *fp = fdopen(fd, "r");
    while (fp && fgets(line, sizeof line, fp)) {
        char *f[6];
        if (split_fields(line, f, 6) == 6 && atoi(f[1]) == acc_no) {
            snprintf(recent[count % HISTORY_LINES], sizeof recent[0],
                     "%-19s  %-12s %12s %12s  %.40s", f[0], f[2], f[3], f[4], f[5]);
            count++;
        }
    }
    if (fp)
        fclose(fp);          /* closes fd, which also releases the lock */
    else
        close(fd);

    reply(resp, "OK Passbook of account %d (latest %d entries)\n", acc_no, HISTORY_LINES);
    reply(resp, "%-19s  %-12s %12s %12s  %s\n", "Date/Time", "Type", "Amount", "Balance", "Details");
    int start = count > HISTORY_LINES ? count - HISTORY_LINES : 0;
    for (int i = start; i < count; i++)
        reply(resp, "%s\n", recent[i % HISTORY_LINES]);
    if (count == 0)
        reply(resp, "(no transactions)\n");
}

/* ------------------------------------------------------------------ */
/* Sessions: one active session per user (protected by a mutex)        */
/* ------------------------------------------------------------------ */

static int session_start(const char *username)
{
    int rc = 0, free_slot = -1;
    pthread_mutex_lock(&session_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (sessions[i][0] == '\0') {
            if (free_slot < 0)
                free_slot = i;
        } else if (strcmp(sessions[i], username) == 0) {
            rc = -1;                               /* already logged in elsewhere */
        }
    }
    if (rc == 0 && free_slot >= 0)
        copy_str(sessions[free_slot], sizeof sessions[0], username);
    else
        rc = -1;
    pthread_mutex_unlock(&session_lock);
    return rc;
}

static void session_end(const char *username)
{
    pthread_mutex_lock(&session_lock);
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (strcmp(sessions[i], username) == 0)
            sessions[i][0] = '\0';
    pthread_mutex_unlock(&session_lock);
}

/* ------------------------------------------------------------------ */
/* Common commands                                                     */
/* ------------------------------------------------------------------ */

static void cmd_login(Client *c, char **arg, int nargs, char *resp)
{
    User u;
    if (c->logged_in) {
        reply(resp, "ERR Already logged in. Logout first.\n");
        return;
    }
    if (nargs != 2 && nargs != 3) {
        reply(resp, "ERR Usage: LOGIN|username|password[|role]\n");
        return;
    }
    if (find_user(arg[0], &u) < 0 || !check_password(arg[1], u.hash)) {
        log_event("Failed login for '%.20s'", arg[0]);
        reply(resp, "ERR Invalid username or password\n");
        return;
    }
    /* The role chosen on the client is only a claim; the stored role decides. */
    if (nargs == 3 && strcmp(arg[2], u.role) != 0) {
        log_event("Role mismatch login for '%.20s' (chose %.10s)", arg[0], arg[2]);
        reply(resp, "ERR This account is not registered for the selected login type\n");
        return;
    }
    if (strcmp(u.role, "CUSTOMER") == 0) {
        Account a;
        int acc = find_customer_account(u.username);
        if (acc > 0 && get_account(acc, &a) == 0 && strcmp(a.status, "INACTIVE") == 0) {
            reply(resp, "ERR Your account is deactivated. Please contact the bank.\n");
            return;
        }
    }
    if (session_start(u.username) != 0) {
        reply(resp, "ERR User '%s' is already logged in from another client\n", u.username);
        return;
    }
    c->user = u;
    c->logged_in = 1;
    log_event("LOGIN %s (%s)", u.username, u.role);
    reply(resp, "OK %s\nWelcome, %s!\n", u.role, u.name);
}

static void cmd_logout(Client *c, char **arg, char *resp)
{
    (void)arg;
    session_end(c->user.username);
    c->logged_in = 0;
    log_event("LOGOUT %s", c->user.username);
    reply(resp, "OK Logged out\n");
}

static void cmd_passwd(Client *c, char **arg, char *resp)
{
    User u;
    int idx;
    if (!valid_password(arg[1])) {
        reply(resp, "ERR New password must be 4-30 characters\n");
        return;
    }
    int fd = lock_user(c->user.username, &idx, &u);
    if (fd < 0) {
        reply(resp, "ERR Could not load user\n");
        return;
    }
    if (!check_password(arg[0], u.hash)) {
        save_user_unlock(fd, idx, NULL);
        reply(resp, "ERR Old password is incorrect\n");
        return;
    }
    make_hash(arg[1], u.hash, sizeof u.hash);
    if (save_user_unlock(fd, idx, &u) != 0)
        reply(resp, "ERR Could not save password\n");
    else
        reply(resp, "OK Password changed\n");
}

/* ------------------------------------------------------------------ */
/* Customer commands                                                   */
/* ------------------------------------------------------------------ */

static int my_account(Client *c, char *resp)
{
    int acc = find_customer_account(c->user.username);
    if (acc < 0)
        reply(resp, "ERR You do not have an open account\n");
    return acc;
}

static void cmd_balance(Client *c, char **arg, char *resp)
{
    Account a;
    char m[32];
    (void)arg;
    int acc = my_account(c, resp);
    if (acc < 0)
        return;
    if (get_account(acc, &a) != 0)
        reply(resp, "ERR Could not read account\n");
    else
        reply(resp, "OK Account %d (%s, %s)\nBalance: Rs %s\n",
              a.acc_no, a.type, a.status, money(a.balance, m));
}

static void cash_operation(Client *c, const char *amount_str, int deposit, char *resp)
{
    long long amount, balance = 0;
    char m1[32], m2[32];
    if (parse_amount(amount_str, &amount) != 0) {
        reply(resp, "ERR Invalid amount (positive, max 2 decimals, up to %lld)\n", MAX_RUPEES);
        return;
    }
    int acc = my_account(c, resp);
    if (acc < 0)
        return;
    const char *err = change_balance(acc, deposit ? amount : -amount,
                                     deposit ? "DEPOSIT" : "WITHDRAW", "Self", &balance);
    if (err) {
        reply(resp, "ERR %s\n", err);
        return;
    }
    log_event("%s %s Rs %s on account %d", c->user.username,
              deposit ? "deposited" : "withdrew", money(amount, m1), acc);
    reply(resp, "OK %s of Rs %s successful\nNew balance: Rs %s\n",
          deposit ? "Deposit" : "Withdrawal", money(amount, m1), money(balance, m2));
}

static void cmd_deposit(Client *c, char **arg, char *resp)
{
    cash_operation(c, arg[0], 1, resp);
}

static void cmd_withdraw(Client *c, char **arg, char *resp)
{
    cash_operation(c, arg[0], 0, resp);
}

/* Transfer = debit + credit inside ONE critical section. Both records are
 * locked in ascending account order so two opposite transfers cannot deadlock. */
static void cmd_transfer(Client *c, char **arg, char *resp)
{
    long long amount;
    int to;
    Account src, dst;
    char m1[32], m2[32], note[40];
    const char *err = NULL;

    if (parse_acc(arg[0], &to) != 0 || parse_amount(arg[1], &amount) != 0) {
        reply(resp, "ERR Invalid account number or amount\n");
        return;
    }
    int from = my_account(c, resp);
    if (from < 0)
        return;
    if (from == to) {
        reply(resp, "ERR Cannot transfer to the same account\n");
        return;
    }
    int fd = open(ACCOUNTS_FILE, O_RDWR);
    if (fd < 0) {
        reply(resp, "ERR Could not open accounts file\n");
        return;
    }
    int first = from < to ? from : to, second = from < to ? to : from;
    lock_account(fd, first, F_WRLCK);                  /* ---- critical section ---- */
    lock_account(fd, second, F_WRLCK);

    if (load_account(fd, from, &src) != 0 || load_account(fd, to, &dst) != 0)
        err = "Destination account not found";
    else if (strcmp(src.status, "ACTIVE") != 0 || strcmp(dst.status, "ACTIVE") != 0)
        err = "Source or destination account is not active";
    else if (src.balance < amount)
        err = "Insufficient balance";
    else {
        Account old_src = src;
        demo_pause(from);
        src.balance -= amount;
        dst.balance += amount;
        if (save_account(fd, &src) != 0)
            err = "Could not save source account";
        else if (save_account(fd, &dst) != 0) {
            save_account(fd, &old_src);                /* undo the debit */
            err = "Could not save destination account";
        } else {
            snprintf(note, sizeof note, "To acc %d", to);
            add_transaction(from, "TRANSFER_OUT", amount, src.balance, note);
            snprintf(note, sizeof note, "From acc %d", from);
            add_transaction(to, "TRANSFER_IN", amount, dst.balance, note);
        }
    }
    lock_account(fd, second, F_UNLCK);
    lock_account(fd, first, F_UNLCK);                  /* ---- end critical section ---- */
    close(fd);

    if (err) {
        reply(resp, "ERR %s\n", err);
        return;
    }
    log_event("%s transferred Rs %s from %d to %d", c->user.username, money(amount, m1), from, to);
    reply(resp, "OK Transferred Rs %s to account %d\nNew balance: Rs %s\n",
          money(amount, m1), to, money(src.balance, m2));
}

static void cmd_apply_loan(Client *c, char **arg, char *resp)
{
    long long amount;
    Account a;
    Loan l;
    char rec[LOAN_REC + 1];
    if (parse_amount(arg[0], &amount) != 0 || !valid_text(arg[1], 40)) {
        reply(resp, "ERR Invalid amount or purpose (purpose: 1-40 characters)\n");
        return;
    }
    int acc = my_account(c, resp);
    if (acc < 0)
        return;
    if (get_account(acc, &a) != 0 || strcmp(a.status, "ACTIVE") != 0) {
        reply(resp, "ERR Your account is not active\n");
        return;
    }
    int fd = open(LOANS_FILE, O_RDWR);
    if (fd < 0) {
        reply(resp, "ERR Could not open loans file\n");
        return;
    }
    memset(&l, 0, sizeof l);
    copy_str(l.owner, sizeof l.owner, c->user.username);
    copy_str(l.purpose, sizeof l.purpose, arg[1]);
    copy_str(l.status, sizeof l.status, "PENDING");
    copy_str(l.assigned, sizeof l.assigned, "-");
    l.acc_no = acc;
    l.amount = amount;

    lock_record(fd, WHOLE_FILE, 0, F_WRLCK);           /* new id must be unique */
    l.id = record_count(fd, LOAN_REC) + 1;
    encode_loan(&l, rec);
    int rc = write_record(fd, l.id - 1, LOAN_REC, rec);
    lock_record(fd, WHOLE_FILE, 0, F_UNLCK);
    close(fd);

    if (rc != 0) {
        reply(resp, "ERR Could not save loan application\n");
        return;
    }
    log_event("%s applied for loan #%d", c->user.username, l.id);
    reply(resp, "OK Loan application #%d submitted (status: PENDING)\n", l.id);
}

static void cmd_feedback(Client *c, char **arg, char *resp)
{
    char line[400], ts[32];
    if (!valid_text(arg[0], 200)) {
        reply(resp, "ERR Feedback must be 1-200 characters\n");
        return;
    }
    now_str(ts, sizeof ts);
    snprintf(line, sizeof line, "%s|%s|%s\n", ts, c->user.username, arg[0]);
    append_line(FEEDBACK_FILE, line);
    reply(resp, "OK Thank you for your feedback\n");
}

static void cmd_history(Client *c, char **arg, char *resp)
{
    (void)arg;
    int acc = my_account(c, resp);
    if (acc > 0)
        show_passbook(acc, resp);
}

/* ------------------------------------------------------------------ */
/* Employee commands                                                   */
/* ------------------------------------------------------------------ */

/* arg = username, password, name, phone. Returns 0 if the user was added. */
static int create_user(char **arg, const char *role, char *resp)
{
    User u;
    if (!valid_username(arg[0]) || !valid_password(arg[1]) ||
        !valid_text(arg[2], 30) || !valid_phone(arg[3])) {
        reply(resp, "ERR Invalid input (username 3-20 letters/digits/_, password 4-30, "
                    "name 1-30, phone 7-15 digits)\n");
        return -1;
    }
    memset(&u, 0, sizeof u);
    copy_str(u.username, sizeof u.username, arg[0]);
    copy_str(u.role, sizeof u.role, role);
    copy_str(u.name, sizeof u.name, arg[2]);
    copy_str(u.phone, sizeof u.phone, arg[3]);
    make_hash(arg[1], u.hash, sizeof u.hash);
    int rc = add_user(&u);
    if (rc == -2)
        reply(resp, "ERR Username '%s' already exists\n", u.username);
    else if (rc != 0)
        reply(resp, "ERR Could not save user\n");
    return rc;
}

/* arg = username, name, phone. */
static void update_user_details(Client *c, char **arg, int customers_only, char *resp)
{
    User u;
    int idx;
    if (!valid_text(arg[1], 30) || !valid_phone(arg[2])) {
        reply(resp, "ERR Invalid name (1-30 chars) or phone (7-15 digits)\n");
        return;
    }
    int fd = lock_user(arg[0], &idx, &u);
    if (fd < 0) {
        reply(resp, "ERR User not found\n");
        return;
    }
    if (customers_only && strcmp(u.role, "CUSTOMER") != 0) {
        save_user_unlock(fd, idx, NULL);
        reply(resp, "ERR '%s' is not a customer\n", u.username);
        return;
    }
    copy_str(u.name, sizeof u.name, arg[1]);
    copy_str(u.phone, sizeof u.phone, arg[2]);
    if (save_user_unlock(fd, idx, &u) != 0) {
        reply(resp, "ERR Could not save user\n");
        return;
    }
    log_event("%s modified details of %s", c->user.username, u.username);
    reply(resp, "OK Details of %s updated\n", u.username);
}

static void cmd_add_customer(Client *c, char **arg, char *resp)
{
    if (!valid_acc_type(arg[4])) {
        reply(resp, "ERR Account type must be SAVINGS or CURRENT\n");
        return;
    }
    if (create_user(arg, "CUSTOMER", resp) != 0)
        return;
    int acc = create_account(arg[0], arg[4], 0);
    log_event("%s added customer %s with account %d", c->user.username, arg[0], acc);
    if (acc < 0)
        reply(resp, "ERR Customer created but account could not be opened\n");
    else
        reply(resp, "OK Customer '%s' created with %s account %d\n", arg[0], arg[4], acc);
}

static void cmd_modify_customer(Client *c, char **arg, char *resp)
{
    update_user_details(c, arg, 1, resp);
}

static void cmd_open_account(Client *c, char **arg, char *resp)
{
    User u;
    if (!valid_acc_type(arg[1])) {
        reply(resp, "ERR Account type must be SAVINGS or CURRENT\n");
        return;
    }
    if (find_user(arg[0], &u) < 0 || strcmp(u.role, "CUSTOMER") != 0) {
        reply(resp, "ERR No such customer\n");
        return;
    }
    int acc = create_account(u.username, arg[1], 0);
    if (acc == -2)
        reply(resp, "ERR Customer already has an open account\n");
    else if (acc < 0)
        reply(resp, "ERR Could not open account\n");
    else {
        log_event("%s opened account %d for %s", c->user.username, acc, u.username);
        reply(resp, "OK Opened %s account %d for %s\n", arg[1], acc, u.username);
    }
}

/* Shared by modify/close account and manager activate/deactivate.
 * field is "TYPE" or "STATUS". */
static void update_account(Client *c, const char *acc_str, const char *field,
                           const char *value, char *resp)
{
    int acc_no;
    Account a;
    const char *err = NULL;
    if (parse_acc(acc_str, &acc_no) != 0) {
        reply(resp, "ERR Invalid account number\n");
        return;
    }
    int fd = open(ACCOUNTS_FILE, O_RDWR);
    if (fd < 0) {
        reply(resp, "ERR Could not open accounts file\n");
        return;
    }
    lock_account(fd, acc_no, F_WRLCK);
    if (load_account(fd, acc_no, &a) != 0)
        err = "Account not found";
    else if (strcmp(a.status, "CLOSED") == 0)
        err = "Account is closed";
    else if (strcmp(value, "CLOSED") == 0 && a.balance != 0)
        err = "Balance must be zero before closing (withdraw first)";
    else {
        if (strcmp(field, "TYPE") == 0)
            copy_str(a.type, sizeof a.type, value);
        else
            copy_str(a.status, sizeof a.status, value);
        if (save_account(fd, &a) != 0)
            err = "Could not save account";
    }
    lock_account(fd, acc_no, F_UNLCK);
    close(fd);
    if (err) {
        reply(resp, "ERR %s\n", err);
        return;
    }
    log_event("%s set %s of account %d to %s", c->user.username, field, acc_no, value);
    reply(resp, "OK Account %d %s is now %s\n", acc_no, field, value);
}

static void cmd_modify_account(Client *c, char **arg, char *resp)
{
    if (!valid_acc_type(arg[1]))
        reply(resp, "ERR Account type must be SAVINGS or CURRENT\n");
    else
        update_account(c, arg[0], "TYPE", arg[1], resp);
}

static void cmd_close_account(Client *c, char **arg, char *resp)
{
    update_account(c, arg[0], "STATUS", "CLOSED", resp);
}

static void cmd_list_accounts(Client *c, char **arg, char *resp)
{
    char m[32];
    (void)c;
    (void)arg;
    int fd = open(ACCOUNTS_FILE, O_RDONLY);
    if (fd < 0) {
        reply(resp, "ERR Could not open accounts file\n");
        return;
    }
    reply(resp, "OK All accounts\n%-6s %-20s %-8s %15s %s\n", "Acc", "Owner", "Type", "Balance", "Status");
    lock_record(fd, WHOLE_FILE, 0, F_RDLCK);
    int n = record_count(fd, ACC_REC);
    for (int i = 0; i < n; i++) {
        Account a;
        if (load_account(fd, FIRST_ACC_NO + i, &a) == 0)
            reply(resp, "%-6d %-20s %-8s %15s %s\n", a.acc_no, a.owner, a.type,
                  money(a.balance, m), a.status);
    }
    lock_record(fd, WHOLE_FILE, 0, F_UNLCK);
    close(fd);
}

static void cmd_my_loans(Client *c, char **arg, char *resp)
{
    (void)arg;
    list_loans(resp, c->user.username);
}

/* Lock order everywhere: loans -> accounts -> transactions (no cycles). */
static void cmd_decide_loan(Client *c, char **arg, char *resp)
{
    int id;
    Loan l;
    long long balance;
    char note[40];
    const char *err = NULL;
    int approve = strcmp(arg[1], "APPROVE") == 0;
    if (parse_number(arg[0], 1, &id) != 0 || (!approve && strcmp(arg[1], "REJECT") != 0)) {
        reply(resp, "ERR Usage: loan id and APPROVE or REJECT\n");
        return;
    }
    int fd = open(LOANS_FILE, O_RDWR);
    if (fd < 0) {
        reply(resp, "ERR Could not open loans file\n");
        return;
    }
    lock_record(fd, id - 1, LOAN_REC, F_WRLCK);
    if (load_loan(fd, id, &l) != 0)
        err = "Loan not found";
    else if (strcmp(l.assigned, c->user.username) != 0 || strcmp(l.status, "ASSIGNED") != 0)
        err = "This loan is not assigned to you for processing";
    else if (approve) {
        snprintf(note, sizeof note, "Loan #%d approved", id);
        err = change_balance(l.acc_no, l.amount, "LOAN_CREDIT", note, &balance);
    }
    if (!err) {
        copy_str(l.status, sizeof l.status, approve ? "APPROVED" : "REJECTED");
        if (save_loan(fd, &l) != 0)
            err = "Could not save loan";
    }
    lock_record(fd, id - 1, LOAN_REC, F_UNLCK);
    close(fd);
    if (err) {
        reply(resp, "ERR %s\n", err);
        return;
    }
    log_event("%s %s loan #%d", c->user.username, approve ? "approved" : "rejected", id);
    reply(resp, "OK Loan #%d %s%s\n", id, approve ? "APPROVED" : "REJECTED",
          approve ? " and amount credited to customer account" : "");
}

static void cmd_passbook(Client *c, char **arg, char *resp)
{
    int acc_no;
    Account a;
    (void)c;
    if (parse_acc(arg[0], &acc_no) != 0 || get_account(acc_no, &a) != 0) {
        reply(resp, "ERR Account not found\n");
        return;
    }
    show_passbook(acc_no, resp);
}

/* ------------------------------------------------------------------ */
/* Manager commands                                                    */
/* ------------------------------------------------------------------ */

static void cmd_set_status(Client *c, char **arg, char *resp)
{
    if (strcmp(arg[1], "ACTIVE") != 0 && strcmp(arg[1], "INACTIVE") != 0)
        reply(resp, "ERR Status must be ACTIVE or INACTIVE\n");
    else
        update_account(c, arg[0], "STATUS", arg[1], resp);
}

static void cmd_all_loans(Client *c, char **arg, char *resp)
{
    (void)c;
    (void)arg;
    list_loans(resp, NULL);
}

static void cmd_assign_loan(Client *c, char **arg, char *resp)
{
    int id;
    Loan l;
    User emp;
    const char *err = NULL;
    if (parse_number(arg[0], 1, &id) != 0) {
        reply(resp, "ERR Invalid loan id\n");
        return;
    }
    if (find_user(arg[1], &emp) < 0 || strcmp(emp.role, "EMPLOYEE") != 0) {
        reply(resp, "ERR '%s' is not an employee\n", arg[1]);
        return;
    }
    int fd = open(LOANS_FILE, O_RDWR);
    if (fd < 0) {
        reply(resp, "ERR Could not open loans file\n");
        return;
    }
    lock_record(fd, id - 1, LOAN_REC, F_WRLCK);
    if (load_loan(fd, id, &l) != 0)
        err = "Loan not found";
    else if (strcmp(l.status, "PENDING") != 0 && strcmp(l.status, "ASSIGNED") != 0)
        err = "Loan has already been decided";
    else {
        copy_str(l.assigned, sizeof l.assigned, emp.username);
        copy_str(l.status, sizeof l.status, "ASSIGNED");
        if (save_loan(fd, &l) != 0)
            err = "Could not save loan";
    }
    lock_record(fd, id - 1, LOAN_REC, F_UNLCK);
    close(fd);
    if (err) {
        reply(resp, "ERR %s\n", err);
        return;
    }
    log_event("%s assigned loan #%d to %s", c->user.username, id, emp.username);
    reply(resp, "OK Loan #%d assigned to %s\n", id, emp.username);
}

static void cmd_view_feedback(Client *c, char **arg, char *resp)
{
    char line[400];
    int count = 0;
    (void)c;
    (void)arg;
    int fd = open(FEEDBACK_FILE, O_RDONLY);
    if (fd < 0) {
        reply(resp, "ERR Could not open feedback file\n");
        return;
    }
    reply(resp, "OK Customer feedback\n");
    lock_record(fd, WHOLE_FILE, 0, F_RDLCK);
    FILE *fp = fdopen(fd, "r");
    while (fp && fgets(line, sizeof line, fp)) {
        char *f[3];
        if (split_fields(line, f, 3) == 3) {
            reply(resp, "[%s] %s: %s\n", f[0], f[1], f[2]);
            count++;
        }
    }
    if (fp)
        fclose(fp);
    else
        close(fd);
    if (count == 0)
        reply(resp, "(no feedback yet)\n");
}

/* ------------------------------------------------------------------ */
/* Administrator commands                                              */
/* ------------------------------------------------------------------ */

static void cmd_add_employee(Client *c, char **arg, char *resp)
{
    if (!valid_staff_role(arg[4])) {
        reply(resp, "ERR Role must be EMPLOYEE or MANAGER\n");
        return;
    }
    if (create_user(arg, arg[4], resp) == 0) {
        log_event("%s added %s %s", c->user.username, arg[4], arg[0]);
        reply(resp, "OK %s '%s' added\n", arg[4], arg[0]);
    }
}

static void cmd_modify_user(Client *c, char **arg, char *resp)
{
    update_user_details(c, arg, 0, resp);
}

static void cmd_set_role(Client *c, char **arg, char *resp)
{
    User u;
    int idx;
    if (!valid_staff_role(arg[1])) {
        reply(resp, "ERR Role must be EMPLOYEE or MANAGER\n");
        return;
    }
    int fd = lock_user(arg[0], &idx, &u);
    if (fd < 0) {
        reply(resp, "ERR User not found\n");
        return;
    }
    if (!valid_staff_role(u.role)) {
        save_user_unlock(fd, idx, NULL);
        reply(resp, "ERR Only EMPLOYEE/MANAGER roles can be changed\n");
        return;
    }
    copy_str(u.role, sizeof u.role, arg[1]);
    if (save_user_unlock(fd, idx, &u) != 0) {
        reply(resp, "ERR Could not save user\n");
        return;
    }
    log_event("%s changed role of %s to %s", c->user.username, u.username, u.role);
    reply(resp, "OK Role of %s is now %s\n", u.username, u.role);
}

static void cmd_list_users(Client *c, char **arg, char *resp)
{
    char rec[USER_REC + 1];
    (void)c;
    (void)arg;
    int fd = open(USERS_FILE, O_RDONLY);
    if (fd < 0) {
        reply(resp, "ERR Could not open users file\n");
        return;
    }
    reply(resp, "OK All users\n%-20s %-9s %-30s %s\n", "Username", "Role", "Name", "Phone");
    lock_record(fd, WHOLE_FILE, 0, F_RDLCK);
    int n = record_count(fd, USER_REC);
    for (int i = 0; i < n; i++) {
        User u;
        if (read_record(fd, i, USER_REC, rec) == 0 && decode_user(rec, &u) == 0)
            reply(resp, "%-20s %-9s %-30s %s\n", u.username, u.role, u.name, u.phone);
    }
    lock_record(fd, WHOLE_FILE, 0, F_UNLCK);
    close(fd);
}

/* ------------------------------------------------------------------ */
/* Request dispatch with server-side role-based authorization          */
/* ------------------------------------------------------------------ */

static const Command commands[] = {
    {"LOGOUT", R_ANY, 0, cmd_logout},
    {"PASSWD", R_ANY, 2, cmd_passwd},
    {"BALANCE", R_CUSTOMER, 0, cmd_balance},
    {"DEPOSIT", R_CUSTOMER, 1, cmd_deposit},
    {"WITHDRAW", R_CUSTOMER, 1, cmd_withdraw},
    {"TRANSFER", R_CUSTOMER, 2, cmd_transfer},
    {"APPLY_LOAN", R_CUSTOMER, 2, cmd_apply_loan},
    {"FEEDBACK", R_CUSTOMER, 1, cmd_feedback},
    {"HISTORY", R_CUSTOMER, 0, cmd_history},
    {"ADD_CUSTOMER", R_EMPLOYEE, 5, cmd_add_customer},
    {"MODIFY_CUSTOMER", R_EMPLOYEE, 3, cmd_modify_customer},
    {"OPEN_ACCOUNT", R_EMPLOYEE, 2, cmd_open_account},
    {"MODIFY_ACCOUNT", R_EMPLOYEE, 2, cmd_modify_account},
    {"CLOSE_ACCOUNT", R_EMPLOYEE, 1, cmd_close_account},
    {"LIST_ACCOUNTS", R_EMPLOYEE | R_MANAGER, 0, cmd_list_accounts},
    {"MY_LOANS", R_EMPLOYEE, 0, cmd_my_loans},
    {"DECIDE_LOAN", R_EMPLOYEE, 2, cmd_decide_loan},
    {"PASSBOOK", R_EMPLOYEE, 1, cmd_passbook},
    {"SET_STATUS", R_MANAGER, 2, cmd_set_status},
    {"ALL_LOANS", R_MANAGER, 0, cmd_all_loans},
    {"ASSIGN_LOAN", R_MANAGER, 2, cmd_assign_loan},
    {"VIEW_FEEDBACK", R_MANAGER, 0, cmd_view_feedback},
    {"ADD_EMPLOYEE", R_ADMIN, 5, cmd_add_employee},
    {"MODIFY_USER", R_ADMIN, 3, cmd_modify_user},
    {"SET_ROLE", R_ADMIN, 2, cmd_set_role},
    {"LIST_USERS", R_ADMIN, 0, cmd_list_users},
};

static void handle_request(Client *c, char *line, char *resp)
{
    char *args[MAX_ARGS];
    int n = split_fields(line, args, MAX_ARGS);
    resp[0] = '\0';

    if (n == 0 || args[0][0] == '\0') {
        reply(resp, "ERR Empty request\n");
        return;
    }
    if (strcmp(args[0], "LOGIN") == 0) {
        cmd_login(c, args + 1, n - 1, resp);
        return;
    }
    const Command *cmd = NULL;
    for (size_t i = 0; i < sizeof commands / sizeof commands[0]; i++)
        if (strcmp(commands[i].name, args[0]) == 0)
            cmd = &commands[i];
    if (!cmd) {
        reply(resp, "ERR Unknown command\n");
        return;
    }
    if (!c->logged_in) {
        reply(resp, "ERR Please login first\n");
        return;
    }
    find_user(c->user.username, &c->user);     /* re-read role: admin may have changed it */
    if (!(cmd->roles & role_bit(c->user.role))) {
        log_event("DENIED %s (%s) tried %s", c->user.username, c->user.role, cmd->name);
        reply(resp, "ERR Permission denied for role %s\n", c->user.role);
        return;
    }
    if (n - 1 != cmd->nargs) {
        reply(resp, "ERR %s expects %d argument(s)\n", cmd->name, cmd->nargs);
        return;
    }
    cmd->fn(c, args + 1, resp);
}

/* ------------------------------------------------------------------ */
/* Networking, threads, logger process, startup                        */
/* ------------------------------------------------------------------ */

/* Reads one '\n'-terminated line. Returns length, or -1 on disconnect. */
static int recv_line(int sock, char *buf, int size)
{
    int len = 0;
    char ch;
    while (1) {
        ssize_t n = recv(sock, &ch, 1, 0);
        if (n <= 0)
            return -1;
        if (ch == '\n')
            break;
        if (ch != '\r' && len < size - 1)
            buf[len++] = ch;              /* extra characters are dropped */
    }
    buf[len] = '\0';
    return len;
}

static int send_all(int sock, const char *data)
{
    size_t left = strlen(data);
    while (left > 0) {
        ssize_t n = send(sock, data, left, MSG_NOSIGNAL);
        if (n <= 0)
            return -1;
        data += n;
        left -= (size_t)n;
    }
    return 0;
}

static void *client_thread(void *arg)
{
    Client *c = arg;
    char line[LINE_LEN];
    char *resp = malloc(RESP_LEN);
    sigset_t set;

    sigemptyset(&set);                   /* Ctrl+C is handled by the main thread only */
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    log_event("Client connected (socket %d)", c->sock);
    while (resp && recv_line(c->sock, line, sizeof line) >= 0) {
        handle_request(c, line, resp);
        size_t len = strlen(resp);
        if (len == 0 || resp[len - 1] != '\n')
            reply(resp, "\n");
        if (send_all(c->sock, resp) < 0 || send_all(c->sock, "END\n") < 0)
            break;
    }
    if (c->logged_in) {
        session_end(c->user.username);
        log_event("Session of %s ended (disconnect)", c->user.username);
    }
    log_event("Client disconnected (socket %d)", c->sock);
    close(c->sock);
    free(resp);
    free(c);
    sem_post(&client_slots);             /* release one client slot */
    return NULL;
}

/* Child process: copies log lines from the pipe to data/server.log and the console. */
static void run_logger(int read_fd)
{
    char buf[1024];
    ssize_t n;
    signal(SIGINT, SIG_IGN);             /* exit only when the parent closes the pipe */
    int out = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
    while ((n = read(read_fd, buf, sizeof buf)) > 0) {
        ssize_t ignored = write(out, buf, n);
        ignored = write(STDOUT_FILENO, buf, n);
        (void)ignored;
    }
    close(out);
    close(read_fd);
    _exit(0);
}

static void touch_file(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT, 0644);
    if (fd >= 0)
        close(fd);
}

static void seed_user(const char *username, const char *password, const char *name,
                      const char *phone, const char *role)
{
    User u;
    memset(&u, 0, sizeof u);
    copy_str(u.username, sizeof u.username, username);
    copy_str(u.role, sizeof u.role, role);
    copy_str(u.name, sizeof u.name, name);
    copy_str(u.phone, sizeof u.phone, phone);
    make_hash(password, u.hash, sizeof u.hash);
    add_user(&u);
}

/* Creates data/ and the demo records the first time the server runs. */
static void init_data(void)
{
    mkdir(DATA_DIR, 0755);
    int fresh = access(USERS_FILE, F_OK) != 0;
    touch_file(USERS_FILE);
    touch_file(ACCOUNTS_FILE);
    touch_file(LOANS_FILE);
    touch_file(TXN_FILE);
    touch_file(FEEDBACK_FILE);
    if (!fresh)
        return;
    seed_user("admin", "admin123", "System Administrator", "9000000001", "ADMIN");
    seed_user("manager", "manager123", "Meera Manager", "9000000002", "MANAGER");
    seed_user("emp1", "emp123", "Ravi Employee", "9000000003", "EMPLOYEE");
    seed_user("emp2", "emp123", "Sita Employee", "9000000004", "EMPLOYEE");
    seed_user("alice", "alice123", "Alice Sharma", "9000000005", "CUSTOMER");
    seed_user("bob", "bob123", "Bob Kumar", "9000000006", "CUSTOMER");
    create_account("alice", "SAVINGS", 500000);    /* Rs 5000.00 -> account 1001 */
    create_account("bob", "SAVINGS", 300000);      /* Rs 3000.00 -> account 1002 */
    printf("Created demo data in %s/\n", DATA_DIR);
}

static void on_signal(int sig)
{
    (void)sig;
    stop_server = 1;
}

static int create_server_socket(int port)
{
    struct sockaddr_in addr;
    int opt = 1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    if (listen(fd, 16) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char *argv[])
{
    int port = DEFAULT_PORT, pipe_fds[2];

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 && i + 1 < argc)
            demo_delay = atoi(argv[++i]);
        else
            port = atoi(argv[i]);
    }
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Usage: %s [port] [-d delay_seconds]\n", argv[0]);
        return 1;
    }

    init_data();

    /* IPC + process management: fork a logger child connected by a pipe. */
    if (pipe(pipe_fds) < 0) {
        perror("pipe");
        return 1;
    }
    pid_t logger_pid = fork();
    if (logger_pid < 0) {
        perror("fork");
        return 1;
    }
    if (logger_pid == 0) {
        close(pipe_fds[1]);
        run_logger(pipe_fds[0]);
    }
    close(pipe_fds[0]);
    log_pipe_fd = pipe_fds[1];

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;           /* no SA_RESTART: accept() returns EINTR */
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    sem_init(&client_slots, 0, MAX_CLIENTS);
    int server_fd = create_server_socket(port);
    if (server_fd < 0)
        stop_server = 1;
    else
        log_event("Server started on port %d (pid %d, logger pid %d, max %d clients%s)",
                  port, getpid(), logger_pid, MAX_CLIENTS, demo_delay ? ", DEMO delay on" : "");

    while (!stop_server) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno != EINTR)
                perror("accept");
            continue;
        }
        if (sem_trywait(&client_slots) != 0) {      /* no free slot */
            send_all(client_fd, "ERR Server busy, try again later\nEND\n");
            close(client_fd);
            continue;
        }
        Client *c = calloc(1, sizeof *c);
        pthread_t tid;
        if (!c) {
            close(client_fd);
            sem_post(&client_slots);
            continue;
        }
        c->sock = client_fd;
        if (pthread_create(&tid, NULL, client_thread, c) != 0) {
            close(client_fd);
            free(c);
            sem_post(&client_slots);
            continue;
        }
        pthread_detach(tid);
    }

    log_event("Server shutting down");
    if (server_fd >= 0)
        close(server_fd);
    close(log_pipe_fd);                  /* EOF tells the logger to exit */
    waitpid(logger_pid, NULL, 0);
    sem_destroy(&client_slots);
    printf("Server stopped.\n");
    return 0;
}
