/*
 * client.c - text-menu client for the Banking Management System.
 *
 * Protocol: the client sends one line "COMMAND|arg1|arg2...\n".
 * The server answers with one or more lines; the first starts with "OK" or
 * "ERR", and the reply ends with a line containing only "END".
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_PORT 8080
#define LINE_LEN 1024
#define FIELD_LEN 220

static int sock = -1;

static void quit(int code)
{
    if (sock >= 0)
        close(sock);
    exit(code);
}

/* Reads a non-empty line from stdin. '|' is rejected because it is the
 * protocol field separator. */
static void ask(const char *prompt, char *buf, size_t size)
{
    while (1) {
        printf("%s", prompt);
        fflush(stdout);
        if (!fgets(buf, (int)size, stdin)) {
            printf("\nInput closed. Exiting.\n");
            quit(0);
        }
        if (!strchr(buf, '\n')) {            /* line too long: discard the rest */
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF)
                ;
        }
        buf[strcspn(buf, "\r\n")] = '\0';
        if (strchr(buf, '|'))
            printf("The character '|' is not allowed.\n");
        else if (buf[0] == '\0')
            printf("Input cannot be empty.\n");
        else
            return;
    }
}

/* Basic client-side check; the server validates again. */
static void ask_amount(const char *prompt, char *buf, size_t size)
{
    while (1) {
        ask(prompt, buf, size);
        char *end;
        double v = strtod(buf, &end);
        if (*end == '\0' && v > 0 && strspn(buf, "0123456789.") == strlen(buf))
            return;
        printf("Enter a positive amount, e.g. 500 or 250.50\n");
    }
}

static void ask_number(const char *prompt, char *buf, size_t size)
{
    while (1) {
        ask(prompt, buf, size);
        if (strspn(buf, "0123456789") == strlen(buf))
            return;
        printf("Enter digits only.\n");
    }
}

/* Asks until the user picks one of the allowed words (e.g. SAVINGS/CURRENT). */
static void ask_choice(const char *prompt, const char *a, const char *b, char *buf, size_t size)
{
    while (1) {
        ask(prompt, buf, size);
        for (char *p = buf; *p; p++)
            if (*p >= 'a' && *p <= 'z')
                *p = (char)(*p - 'a' + 'A');
        if (strcmp(buf, a) == 0 || strcmp(buf, b) == 0)
            return;
        printf("Please type %s or %s\n", a, b);
    }
}

static int send_all(const char *data)
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

static int recv_line(char *buf, int size)
{
    int len = 0;
    char ch;
    while (1) {
        ssize_t n = recv(sock, &ch, 1, 0);
        if (n <= 0)
            return -1;
        if (ch == '\n')
            break;
        if (len < size - 1)
            buf[len++] = ch;
    }
    buf[len] = '\0';
    return len;
}

/* Sends one request, prints the reply and returns 1 if it was "OK".
 * The first reply line is copied to first_line when it is not NULL. */
static int request(const char *req, char *first_line)
{
    char line[LINE_LEN], out[LINE_LEN + 2];
    int ok = 0, first = 1;

    snprintf(out, sizeof out, "%s\n", req);
    if (send_all(out) < 0) {
        printf("Connection to server lost.\n");
        quit(1);
    }
    printf("\n");
    while (1) {
        if (recv_line(line, sizeof line) < 0) {
            printf("Connection to server lost.\n");
            quit(1);
        }
        if (strcmp(line, "END") == 0)
            break;
        if (first) {
            ok = strncmp(line, "OK", 2) == 0;
            if (first_line)
                snprintf(first_line, LINE_LEN, "%s", line);
            printf("%s%s\n", ok ? "[OK]" : "[ERROR]", line + (ok ? 2 : 3));
            first = 0;
        } else {
            printf("  %s\n", line);
        }
    }
    return ok;
}

static void change_password(void)
{
    char old_pw[FIELD_LEN], new_pw[FIELD_LEN], req[LINE_LEN];
    ask("Old password: ", old_pw, sizeof old_pw);
    ask("New password (4-30 chars): ", new_pw, sizeof new_pw);
    snprintf(req, sizeof req, "PASSWD|%s|%s", old_pw, new_pw);
    request(req, NULL);
}

/* Each role menu returns 0 for logout and 1 for exit. */

static int customer_menu(void)
{
    char choice[16], a[FIELD_LEN], b[FIELD_LEN], req[LINE_LEN];
    while (1) {
        printf("\n------ CUSTOMER MENU ------\n"
               " 1. View balance\n 2. Deposit\n 3. Withdraw\n 4. Transfer funds\n"
               " 5. Apply for loan\n 6. Change password\n 7. Add feedback\n"
               " 8. View transaction history\n 9. Logout\n10. Exit\n");
        ask("Choice: ", choice, sizeof choice);
        switch (atoi(choice)) {
        case 1:
            request("BALANCE", NULL);
            break;
        case 2:
            ask_amount("Amount to deposit: ", a, sizeof a);
            snprintf(req, sizeof req, "DEPOSIT|%s", a);
            request(req, NULL);
            break;
        case 3:
            ask_amount("Amount to withdraw: ", a, sizeof a);
            snprintf(req, sizeof req, "WITHDRAW|%s", a);
            request(req, NULL);
            break;
        case 4:
            ask_number("Destination account number: ", a, sizeof a);
            ask_amount("Amount to transfer: ", b, sizeof b);
            snprintf(req, sizeof req, "TRANSFER|%s|%s", a, b);
            request(req, NULL);
            break;
        case 5:
            ask_amount("Loan amount: ", a, sizeof a);
            ask("Purpose (max 40 chars): ", b, sizeof b);
            snprintf(req, sizeof req, "APPLY_LOAN|%s|%s", a, b);
            request(req, NULL);
            break;
        case 6:
            change_password();
            break;
        case 7:
            ask("Your feedback (max 200 chars): ", a, sizeof a);
            snprintf(req, sizeof req, "FEEDBACK|%s", a);
            request(req, NULL);
            break;
        case 8:
            request("HISTORY", NULL);
            break;
        case 9:
            request("LOGOUT", NULL);
            return 0;
        case 10:
            request("LOGOUT", NULL);
            return 1;
        default:
            printf("Invalid choice.\n");
        }
    }
}

static int employee_menu(void)
{
    char choice[16], user[FIELD_LEN], pw[FIELD_LEN], name[FIELD_LEN], phone[FIELD_LEN];
    char a[FIELD_LEN], b[FIELD_LEN], req[LINE_LEN];
    while (1) {
        printf("\n------ EMPLOYEE MENU ------\n"
               " 1. Add new customer\n 2. Modify customer details\n 3. Open account for customer\n"
               " 4. Modify account type\n 5. Close account\n 6. List all accounts\n"
               " 7. View assigned loan applications\n 8. Process loan (approve/reject)\n"
               " 9. View customer passbook\n10. Change password\n11. Logout\n12. Exit\n");
        ask("Choice: ", choice, sizeof choice);
        switch (atoi(choice)) {
        case 1:
            ask("New username: ", user, sizeof user);
            ask("Initial password: ", pw, sizeof pw);
            ask("Full name: ", name, sizeof name);
            ask_number("Phone: ", phone, sizeof phone);
            ask_choice("Account type (SAVINGS/CURRENT): ", "SAVINGS", "CURRENT", a, sizeof a);
            snprintf(req, sizeof req, "ADD_CUSTOMER|%s|%s|%s|%s|%s", user, pw, name, phone, a);
            request(req, NULL);
            break;
        case 2:
            ask("Customer username: ", user, sizeof user);
            ask("New full name: ", name, sizeof name);
            ask_number("New phone: ", phone, sizeof phone);
            snprintf(req, sizeof req, "MODIFY_CUSTOMER|%s|%s|%s", user, name, phone);
            request(req, NULL);
            break;
        case 3:
            ask("Customer username: ", user, sizeof user);
            ask_choice("Account type (SAVINGS/CURRENT): ", "SAVINGS", "CURRENT", a, sizeof a);
            snprintf(req, sizeof req, "OPEN_ACCOUNT|%s|%s", user, a);
            request(req, NULL);
            break;
        case 4:
            ask_number("Account number: ", a, sizeof a);
            ask_choice("New type (SAVINGS/CURRENT): ", "SAVINGS", "CURRENT", b, sizeof b);
            snprintf(req, sizeof req, "MODIFY_ACCOUNT|%s|%s", a, b);
            request(req, NULL);
            break;
        case 5:
            ask_number("Account number to close: ", a, sizeof a);
            snprintf(req, sizeof req, "CLOSE_ACCOUNT|%s", a);
            request(req, NULL);
            break;
        case 6:
            request("LIST_ACCOUNTS", NULL);
            break;
        case 7:
            request("MY_LOANS", NULL);
            break;
        case 8:
            ask_number("Loan id: ", a, sizeof a);
            ask_choice("Decision (APPROVE/REJECT): ", "APPROVE", "REJECT", b, sizeof b);
            snprintf(req, sizeof req, "DECIDE_LOAN|%s|%s", a, b);
            request(req, NULL);
            break;
        case 9:
            ask_number("Account number: ", a, sizeof a);
            snprintf(req, sizeof req, "PASSBOOK|%s", a);
            request(req, NULL);
            break;
        case 10:
            change_password();
            break;
        case 11:
            request("LOGOUT", NULL);
            return 0;
        case 12:
            request("LOGOUT", NULL);
            return 1;
        default:
            printf("Invalid choice.\n");
        }
    }
}

static int manager_menu(void)
{
    char choice[16], a[FIELD_LEN], b[FIELD_LEN], req[LINE_LEN];
    while (1) {
        printf("\n------ MANAGER MENU ------\n"
               " 1. Activate/Deactivate customer account\n 2. List all accounts\n"
               " 3. View all loan applications\n 4. Assign loan to employee\n"
               " 5. Review customer feedback\n 6. Change password\n 7. Logout\n 8. Exit\n");
        ask("Choice: ", choice, sizeof choice);
        switch (atoi(choice)) {
        case 1:
            ask_number("Account number: ", a, sizeof a);
            ask_choice("New status (ACTIVE/INACTIVE): ", "ACTIVE", "INACTIVE", b, sizeof b);
            snprintf(req, sizeof req, "SET_STATUS|%s|%s", a, b);
            request(req, NULL);
            break;
        case 2:
            request("LIST_ACCOUNTS", NULL);
            break;
        case 3:
            request("ALL_LOANS", NULL);
            break;
        case 4:
            ask_number("Loan id: ", a, sizeof a);
            ask("Employee username: ", b, sizeof b);
            snprintf(req, sizeof req, "ASSIGN_LOAN|%s|%s", a, b);
            request(req, NULL);
            break;
        case 5:
            request("VIEW_FEEDBACK", NULL);
            break;
        case 6:
            change_password();
            break;
        case 7:
            request("LOGOUT", NULL);
            return 0;
        case 8:
            request("LOGOUT", NULL);
            return 1;
        default:
            printf("Invalid choice.\n");
        }
    }
}

static int admin_menu(void)
{
    char choice[16], user[FIELD_LEN], pw[FIELD_LEN], name[FIELD_LEN], phone[FIELD_LEN];
    char a[FIELD_LEN], req[LINE_LEN];
    while (1) {
        printf("\n------ ADMINISTRATOR MENU ------\n"
               " 1. Add new bank employee/manager\n 2. Modify customer/employee details\n"
               " 3. Change user role (EMPLOYEE/MANAGER)\n 4. List all users\n"
               " 5. Change password\n 6. Logout\n 7. Exit\n");
        ask("Choice: ", choice, sizeof choice);
        switch (atoi(choice)) {
        case 1:
            ask("New username: ", user, sizeof user);
            ask("Initial password: ", pw, sizeof pw);
            ask("Full name: ", name, sizeof name);
            ask_number("Phone: ", phone, sizeof phone);
            ask_choice("Role (EMPLOYEE/MANAGER): ", "EMPLOYEE", "MANAGER", a, sizeof a);
            snprintf(req, sizeof req, "ADD_EMPLOYEE|%s|%s|%s|%s|%s", user, pw, name, phone, a);
            request(req, NULL);
            break;
        case 2:
            ask("Username: ", user, sizeof user);
            ask("New full name: ", name, sizeof name);
            ask_number("New phone: ", phone, sizeof phone);
            snprintf(req, sizeof req, "MODIFY_USER|%s|%s|%s", user, name, phone);
            request(req, NULL);
            break;
        case 3:
            ask("Username: ", user, sizeof user);
            ask_choice("New role (EMPLOYEE/MANAGER): ", "EMPLOYEE", "MANAGER", a, sizeof a);
            snprintf(req, sizeof req, "SET_ROLE|%s|%s", user, a);
            request(req, NULL);
            break;
        case 4:
            request("LIST_USERS", NULL);
            break;
        case 5:
            change_password();
            break;
        case 6:
            request("LOGOUT", NULL);
            return 0;
        case 7:
            request("LOGOUT", NULL);
            return 1;
        default:
            printf("Invalid choice.\n");
        }
    }
}

/* Shows the menu that matches the role sent by the server after login. */
static int role_menu(const char *role)
{
    if (strcmp(role, "CUSTOMER") == 0) return customer_menu();
    if (strcmp(role, "EMPLOYEE") == 0) return employee_menu();
    if (strcmp(role, "MANAGER") == 0) return manager_menu();
    if (strcmp(role, "ADMIN") == 0) return admin_menu();
    printf("Unknown role '%s'\n", role);
    return 0;
}

int main(int argc, char *argv[])
{
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    int port = argc > 2 ? atoi(argv[2]) : DEFAULT_PORT;
    struct sockaddr_in addr;
    static const char *roles[] = { "CUSTOMER", "EMPLOYEE", "MANAGER", "ADMIN" };
    char choice[16], user[FIELD_LEN], pw[FIELD_LEN], req[LINE_LEN], first[LINE_LEN];

    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (port <= 0 || port > 65535 || inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "Usage: %s [server_ip] [port]\n", argv[0]);
        return 1;
    }
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0 || connect(sock, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("Could not connect to server");
        quit(1);
    }
    printf("Connected to bank server %s:%d\n", host, port);

    while (1) {
        printf("\n====== BANKING MANAGEMENT SYSTEM ======\n"
               " 1. Customer Login\n 2. Employee Login\n 3. Manager Login\n"
               " 4. Administrator Login\n 5. Exit\n");
        ask("Choice: ", choice, sizeof choice);
        if (strcmp(choice, "5") == 0)
            break;
        if (strlen(choice) != 1 || choice[0] < '1' || choice[0] > '4') {
            printf("Invalid choice.\n");
            continue;
        }
        ask("Username: ", user, sizeof user);
        ask("Password: ", pw, sizeof pw);
        snprintf(req, sizeof req, "LOGIN|%s|%s|%s", user, pw, roles[choice[0] - '1']);
        if (request(req, first) && role_menu(first + 3) == 1)
            break;
    }
    printf("Goodbye!\n");
    quit(0);
    return 0;
}
