# Banking Management System —  System Software Project

Design and Development of Banking Management System

A small client–server banking system written in C for Linux. A multithreaded TCP server (`server.c`) keeps the bank's data in plain text files. Text-menu clients (`client.c`) connect over TCP and log in as one of four roles: Customer, Employee, Manager or Administrator.

The project shows sockets, threads, a semaphore, a mutex, `fcntl` record locking, `fork()` and a pipe (IPC). It also shows consistent handling of concurrent deposits, withdrawals and transfers.

---

## 1. Files

| File | Purpose |
|---|---|
| `server.c` | Complete server: sockets, threads, auth, authorization, file storage, locking, logger process |
| `client.c` | Complete client: TCP connection and role-based text menus |
| `Makefile` | `make`, `make clean`, `make reset` |
| `block_diagram.mmd` / `block_diagram.png` | System architecture diagram (Mermaid source and rendered image) |
| `Viva_Notes.md` / `Viva_Notes.pdf` | Detailed viva preparation notes |
| `data/` | Created automatically by the server on first start |

## 2. Features by role

**Customer:** login (one session per user), view balance, deposit, withdraw, transfer funds, apply for a loan, change password, add feedback, view transaction history, logout, exit.

**Employee:** login, add a new customer (this also opens their account), modify customer details, open/modify (type)/close accounts, list accounts, view assigned loan applications, process loans (approve → amount credited, or reject), view any customer's passbook, change password, logout, exit.

**Manager:** login, activate/deactivate customer accounts, list accounts, view all loan applications, assign a loan application to an employee, review customer feedback, change password, logout, exit.

**Administrator:** login, add a new employee or manager, modify customer/employee details (name, phone), change roles (EMPLOYEE ↔ MANAGER), list users, change password, logout, exit.

## 3. Architecture overview

```
 client ──TCP──►  main thread: accept()
 client ──TCP──►     │ sem_trywait() (max 10 clients)
 client ──TCP──►     ▼
                 one pthread per client ──► handle_request()
                     │  login: crypt_r() password check + session table (mutex)
                     │  command table: role bit check (server-side authorization)
                     ▼
                 banking operation ──fcntl(F_OFD_SETLKW) locks──► data/*.txt
                     │
                     └─ log_event() ──pipe──► logger child process (fork) ──► data/server.log
```

See `block_diagram.png` for the full diagram.

**Protocol.** The client sends one line: `COMMAND|arg1|arg2...`. The server replies with one or more lines. The first line starts with `OK` or `ERR`, and the reply ends with a line containing only `END`. Example: `TRANSFER|1002|250.00` → `OK Transferred Rs 250.00 to account 1002` / `New balance: Rs 4750.00` / `END`.

## 4. System calls and concepts used

| Concept | Where (in `server.c` unless noted) |
|---|---|
| TCP sockets | `socket`, `setsockopt`, `bind`, `listen`, `accept`, `recv`, `send`, `close`; client uses `socket`, `connect` |
| Multithreading | `pthread_create` + `pthread_detach`: one thread per client (`client_thread`) |
| Semaphore | `sem_t client_slots`: `sem_init(.., 10)`, `sem_trywait` on accept, `sem_post` when a client leaves |
| Mutex (thread synchronization) | `session_lock` protects the logged-in user table (`session_start`, `session_end`) |
| File locking | `fcntl(F_OFD_SETLKW)`: shared read locks / exclusive write locks on single records or whole files (`lock_record`) |
| File management (system calls) | `open`, `pread`, `pwrite`, `fstat`, `fsync`, `write` with `O_APPEND`, `mkdir`, `access`, `close` |
| Process management | `fork()` creates a logger child; `waitpid()` reaps it on shutdown; `_exit()` in the child |
| IPC | `pipe()`: worker threads `write()` log lines and the logger child `read()`s them |
| Signals | `sigaction(SIGINT/SIGTERM)` for graceful shutdown, `SIGPIPE` ignored, `pthread_sigmask` in workers |
| Password security | `crypt_r()` with SHA-512 (`$6$`) and a random salt from `/dev/urandom`. No plaintext passwords are stored. |

## 5. Build

Requirements: Linux (or WSL), `gcc`, `make`, and libcrypt (`libcrypt-dev` on Ubuntu/Debian).

```bash
make          # builds ./server and ./client
make clean    # removes the binaries
make reset    # deletes data/ (demo data is recreated on next server start)
```

## 6. Run

Terminal 1 (server):

```bash
./server              # listens on port 8080
./server 9000         # custom port
./server -d 5         # DEMO mode: holds account locks for 5 s inside each money operation
```

Terminal 2, 3, ... (clients):

```bash
./client                      # connects to 127.0.0.1:8080
./client 127.0.0.1 9000       # custom server ip and port
```

Stop the server with **Ctrl+C**. The main thread closes the pipe, the logger process exits and the server reaps it with `waitpid()`.

On first start the server creates `data/` with the demo records below.

## 7. Demo credentials

| Username | Password | Role | Account |
|---|---|---|---|
| `admin` | `admin123` | ADMIN | — |
| `manager` | `manager123` | MANAGER | — |
| `emp1` | `emp123` | EMPLOYEE | — |
| `emp2` | `emp123` | EMPLOYEE | — |
| `alice` | `alice123` | CUSTOMER | 1001, SAVINGS, Rs 5000.00 |
| `bob` | `bob123` | CUSTOMER | 1002, SAVINGS, Rs 3000.00 |

New customers get the next account number (1003, 1004, ...).

## 8. Running multiple clients

Open several terminals and run `./client` in each one. Log in as different users at the same time, for example alice, bob, emp1 and manager. The server log, printed on the server console and saved to `data/server.log`, shows each connection and operation.

- **One session per user:** log in as `alice` in two terminals. The second login gets `User 'alice' is already logged in from another client`.
- **Client limit (semaphore):** a client beyond the 10th gets `Server busy`.

## 9. Demonstrating file locking and concurrency

1. Start the server in demo mode: `./server -d 8`.
2. Terminal A: log in as **alice** → Deposit 100. The server prints `DEMO: account 1001 is locked, sleeping 8 s...`
3. Terminal B, within 8 s: log in as **bob** → Transfer 50 to account 1001. Bob's request **waits** until alice's deposit releases the lock, then completes.
4. Both balances are correct (no lost update). Check them with the Balance and History options.

**Opposite transfers / deadlock-avoidance test.** Run two scripted clients at once, alice → 1002 and bob → 1001, for 40 transfers of Rs 1 each:

```bash
gen(){ printf '1\n%s\n%s\n' $1 $2; for i in $(seq 40); do printf '4\n%s\n1\n' $3; done; printf '10\n'; }
gen alice alice123 1002 | ./client > a.out &
gen bob   bob123   1001 | ./client > b.out &
wait; grep -c Transferred a.out b.out
```

All 80 transfers complete and the total money (alice + bob) stays the same. Both accounts are always locked in ascending account order, so the two transfers cannot deadlock.

**Advisory lock check from the shell.** `cat data/accounts.txt` still works while a lock is held, because `fcntl` locks are *advisory*. They only stop processes that also ask for the lock, which the server always does.

## 10. Data file formats (`data/`)

Fixed-width records (record *i* starts at byte `i × length`) allow `pread`/`pwrite` in place and per-record locks:

- `users.txt` (192 bytes/record): `username|role|name|phone|sha512_crypt_hash|`
- `accounts.txt` (64 bytes/record): `acc_no|owner|type|balance_in_paise|status|`. Status is ACTIVE, INACTIVE or CLOSED. Account number = 1001 + record index.
- `loans.txt` (128 bytes/record): `id|customer|acc_no|amount_in_paise|purpose|status|assigned_employee|`. Status is PENDING, ASSIGNED, APPROVED or REJECTED.

Append-only lines:

- `transactions.txt`: `date time|acc_no|type|amount|balance_after|details`
- `feedback.txt`: `date time|username|text`
- `server.log`: written only by the logger process

Money is stored as integer **paise** to avoid floating-point rounding errors.

## 11. Known limitations

- The fixed-width text files are simple storage, not a database. There is no crash-recovery log. If the machine crashes between the two `pwrite`s of a transfer, the files could be inconsistent. (A failed second write *is* rolled back in code, and every write is followed by `fsync`.)
- `fcntl` locks are advisory. Editing the data files by hand while the server runs bypasses them.
- `F_OFD_SETLKW` (open-file-description locks) is Linux-specific (kernel ≥ 3.15). It is used because classic `F_SETLKW` locks do not separate threads of the same process.
- Each customer has at most one open account. Closing an account requires a zero balance.
- Records are never physically deleted. Closed accounts stay in the file with status CLOSED.
- The protocol is plain text without TLS, and passwords travel unencrypted on the network. This is acceptable for a localhost demo, not for production.
- Passwords are echoed while typing (no terminal tricks, to keep the client simple).
- The passbook shows the latest 50 transactions of an account.
