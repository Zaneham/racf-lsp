# ADDUSER Command Grammar

## Syntax

```
[subsystem-prefix]{ADDUSER | AU} (userid ...) [keywords...]
```

## Required

| Parameter | Type | Rules |
|-----------|------|-------|
| `userid` | identifier | 1-8 chars, alphanumeric + national (@#$), must be unique |

## Base Segment Keywords

| Keyword | Alias | Value Type | Default | Notes |
|---------|-------|------------|---------|-------|
| `ADDCATEGORY` | - | (category-name ...) | - | list of security categories |
| `ADSP` | - | flag | `NOADSP` | auto data set protection |
| `NOADSP` | - | flag | default | |
| `AUDITOR` | - | flag | `NOAUDITOR` | full audit authority |
| `NOAUDITOR` | - | flag | default | |
| `AUTHORITY` | - | (group-authority) | `USE` | USE, CREATE, CONNECT, JOIN |
| `CLAUTH` | - | (class-name ...) | - | class authority |
| `NOCLAUTH` | - | flag | default | |
| `DATA` | - | ('string') | - | up to 255 chars, quoted |
| `DFLTGRP` | - | (group-name) | current connect group | |
| `GRPACC` | - | flag | `NOGRPACC` | group access for datasets |
| `NOGRPACC` | - | flag | default | |
| `MODEL` | - | (dsname) | - | model dataset profile |
| `NAME` | - | (user-name) | `'####################'` | up to 20 chars |
| `OIDCARD` | - | flag | `NOOIDCARD` | require operator ID card |
| `NOOIDCARD` | - | flag | default | |
| `OPERATIONS` | - | flag | `NOOPERATIONS` | operations authority |
| `NOOPERATIONS` | - | flag | default | |
| `OWNER` | - | (userid or group-name) | issuer | profile owner |
| `PASSWORD` | - | (password) | - | initial password |
| `NOPASSWORD` | - | flag | - | no password required |
| `PHRASE` | - | ('password-phrase') | - | passphrase, quoted |
| `RESTRICTED` | - | flag | `NORESTRICTED` | restricted user |
| `NORESTRICTED` | - | flag | default | |
| `ROAUDIT` | - | flag | `NOROAUDIT` | read-only auditor |
| `NOROAUDIT` | - | flag | default | |
| `SECLABEL` | - | (seclabel-name) | - | security label |
| `SECLEVEL` | - | (seclevel-name) | - | security level |
| `SPECIAL` | - | flag | `NOSPECIAL` | SPECIAL authority |
| `NOSPECIAL` | - | flag | default | |
| `UACC` | - | (access-authority) | - | NONE, READ, UPDATE, CONTROL, ALTER |
| `WHEN` | - | segment | - | time/day restrictions |

## Segments

### CICS Segment

```
CICS(
    [OPCLASS(operator-class ...)]    /* 1-24, two digits */
    [OPIDENT(operator-id)]           /* 1-3 chars */
    [OPPRTY(operator-priority)]      /* 0-255 */
    [RSLKEY(rslkey ... | 0 | 99)]    /* 1-24, or 0=none, 99=all */
    [TIMEOUT(timeout-value)]         /* hmm or hhmm format */
    [TSLKEY(tslkey ... | 0 | 1 | 99)] /* 1-64, or 0, 1, 99 */
    [XRFSOFF(FORCE | NOFORCE)]
)
```

### DFP Segment

```
DFP(
    [DATAAPPL(application-name)]     /* 8 chars max */
    [DATACLAS(data-class-name)]      /* 8 chars max */
    [MGMTCLAS(management-class-name)] /* 8 chars max */
    [STORCLAS(storage-class-name)]   /* 8 chars max */
)
```

### OMVS Segment (z/OS UNIX)

```
OMVS(
    [ASSIZEMAX(address-space-size)]  /* 10485760 - 2147483647 */
    [AUTOUID | UID(user-identifier) [SHARED]]  /* 0 - 2147483647 */
    [CPUTIMEMAX(cpu-time)]           /* seconds */
    [FILEPROCMAX(files-per-process)]
    [HOME(initial-directory-name)]   /* quoted path */
    [MEMLIMIT(size) | NOMEMLIMIT]
    [MMAPAREAMAX(memory-map-size)]
    [PROCUSERMAX(processes-per-UID)]
    [PROGRAM(program-name)]          /* quoted path */
    [SHMEMMAX(size) | NOSHMEMMAX]
    [THREADSMAX(threads-per-process)]
)
```

### TSO Segment

```
TSO(
    [ACCTNUM(account-number)]
    [COMMAND(command-issued-at-logon)]
    [DEST(destination-id)]
    [HOLDCLASS(hold-class)]          /* single char */
    [JOBCLASS(job-class)]            /* single char */
    [MAXSIZE(maximum-region-size)]   /* in KB */
    [MSGCLASS(message-class)]        /* single char */
    [PROC(logon-procedure-name)]
    [SECLABEL(security-label)]
    [SIZE(default-region-size)]      /* in KB */
    [SYS(sysout-class)]              /* single char */
    [UNIT(unit-name)]
    [USERDATA(user-data)]
)
```

### KERB Segment (Kerberos)

```
KERB(
    [ENCRYPT(
        [DES | NODES]
        [DES3 | NODES3]
        [DESD | NODESD]
        [AES128 | NOAES128]
        [AES256 | NOAES256]
        [AES128SHA2 | NOAES128SHA2]
        [AES256SHA2 | NOAES256SHA2]
    )]
    [KERBNAME(kerberos-principal-name)]  /* no @ allowed */
    [MAXTKTLFE(max-ticket-life)]         /* seconds, 1-2147483647 */
)
```

### LANGUAGE Segment

```
LANGUAGE(
    [PRIMARY(language)]      /* 3 char code or 24 char name */
    [SECONDARY(language)]
)
```

### WHEN Segment

```
WHEN(
    [DAYS(day-info)]         /* ANYDAY, WEEKDAYS, or specific days */
    [TIME(time-info)]        /* hhmm:hhmm format */
)
```

### WORKATTR Segment

```
WORKATTR(
    [WAACCNT(account-number)]
    [WAADDR1(address-line-1)]
    [WAADDR2(address-line-2)]
    [WAADDR3(address-line-3)]
    [WAADDR4(address-line-4)]
    [WABLDG(building)]
    [WADEPT(department)]
    [WANAME(name)]
    [WAROOM(room)]
    [WAEMAIL(e-mail)]
)
```

## Examples

### Minimal
```
ADDUSER (JSMITH)
```

### With name and group
```
ADDUSER (JSMITH) NAME('John Smith') DFLTGRP(PAYROLL)
```

### With OMVS (UNIX)
```
ADDUSER (JSMITH) NAME('John Smith') DFLTGRP(PAYROLL) -
    OMVS(UID(1000) HOME('/u/jsmith') PROGRAM('/bin/sh'))
```

### Full TSO user
```
ADDUSER (JSMITH) NAME('John Smith') DFLTGRP(PAYROLL) -
    PASSWORD(TEMP123) -
    TSO(ACCTNUM(ACCT01) PROC(IKJACCNT) SIZE(4096)) -
    OMVS(AUTOUID HOME('/u/jsmith'))
```

### With security attributes
```
ADDUSER (SECADMIN) NAME('Security Admin') DFLTGRP(SYS1) -
    SPECIAL AUDITOR OPERATIONS -
    CLAUTH(USER GROUP DATASET)
```

## Line Continuation

RACF uses `-` at end of line for continuation:
```
ADDUSER (JSMITH) NAME('John Smith') -
    DFLTGRP(PAYROLL) -
    PASSWORD(TEMP123)
```


