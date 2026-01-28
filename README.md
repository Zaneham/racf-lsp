# RACF Language Server

> **Status: Building in Public**
>
> This LSP does not work yet. I am writing it in the open because the alternative is writing it alone in a folder that nobody sees until it's "ready," and projects that wait until they're ready often never become ready at all.
>
> If you're here, you're watching someone figure out how to parse 50 years of IBM security command syntax. Contributions, suggestions, and gentle corrections are welcome. Harsh corrections are also welcome. I am learning.

Language Server Protocol (LSP) implementation for **IBM RACF** (Resource Access Control Facility), the security system that has been deciding who gets to touch mainframe data since 1976.

If you have a bank account, RACF probably knows about it. If you've filed taxes electronically, RACF was involved. If you've ever wondered why the mainframe is still running, it's partly because replacing RACF would require explaining to auditors what you're doing, and nobody wants that conversation.

## Current State

What exists right now:

| Component | Status |
|-----------|--------|
| README with good intentions | You're reading it |
| ADDUSER grammar specification | Done |
| ADDUSER parser prototype | Works on my machine |
| Actual LSP server | Not yet |
| VS Code extension | Not yet |
| Everything else | Wishful thinking |

What I'm working on:
1. Getting the command parser to handle the full ADDUSER syntax
2. Extending to ALTUSER, PERMIT, RDEFINE
3. Building the actual language server
4. Pretending I know what I'm doing

## What is RACF?

RACF is IBM's security software for z/OS. It controls access to datasets, programs, transactions, and basically everything else on the mainframe. It answers the fundamental questions of computing: Who are you? What do you want? Are you allowed to have it? And most importantly: did we log that?

First released in 1976, RACF predates:
- The IBM PC (1981)
- MS-DOS (1981)
- The World Wide Web (1991)
- Most of the people who now have to maintain it

### Who Uses RACF

| Sector | Why They Care |
|--------|---------------|
| **Banking** | Regulatory compliance. All of it. |
| **Insurance** | Customer data protection |
| **Government** | Everything is classified until proven otherwise |
| **Healthcare** | HIPAA exists and auditors are watching |
| **Airlines** | Reservation systems, loyalty programmes |
| **Retail** | Payment processing, inventory systems |

Every Fortune 500 company with a mainframe has RACF administrators. These people hold the keys to everything. They are simultaneously the most important and least understood members of IT. When something goes wrong with access, everyone knows their name. When everything works, nobody remembers they exist.

## Planned Features

These will exist eventually. Probably.

- **Syntax highlighting** for RACF commands
- **Code completion** for commands, operands, and segment keywords
- **Hover information** with operand descriptions
- **Go to definition** for profiles and resources
- **Diagnostics** for syntax errors and common mistakes
- **Document outline** showing command structure

## RACF Command Overview

RACF commands look like someone tried to fit an entire database schema into a single line. This is because they did.

```racf
/* Create a user who can access OMVS (Unix) */
ADDUSER NEWGUY NAME('New Person') -
    DFLTGRP(USERS) -
    PASSWORD(INITIAL) -
    OMVS(UID(1001) HOME('/u/newguy') PROGRAM('/bin/sh')) -
    TSO(ACCTNUM(ACCT01) PROC(IKJACCNT))

/* Let them read a dataset */
PERMIT 'SYS1.PARMLIB' ID(NEWGUY) ACCESS(READ)

/* Define a new resource class */
RDEFINE FACILITY BPX.SUPERUSER UACC(NONE)

/* Grant superuser access (carefully) */
PERMIT BPX.SUPERUSER CLASS(FACILITY) ID(NEWGUY) ACCESS(READ)
```

The hyphen at the end of a line means "I'm not done yet." RACF commands can span dozens of lines. The `SETROPTS` command, which controls system-wide security options, has over 100 operands. Nobody knows all of them. The documentation is 1,400 pages. This is not an exaggeration.

### Command Categories

| Command | Purpose | Complexity |
|---------|---------|------------|
| `ADDUSER` | Create a user | Medium (many segments) |
| `ALTUSER` | Modify a user | Same as ADDUSER |
| `LISTUSER` | Display user info | Simple (but verbose output) |
| `DELUSER` | Delete a user | Simple (but terrifying) |
| `ADDGROUP` | Create a group | Simple |
| `PERMIT` | Grant access | Medium |
| `RDEFINE` | Define a resource | Medium |
| `RALTER` | Modify a resource | Medium |
| `SETROPTS` | System options | Complex (and dangerous) |

The `DELUSER` command is simple to type. The consequences of typing it incorrectly are not.

## Segments

RACF commands use "segments" to organise related operands. A user can have:

- **BASE** segment: Name, default group, password rules
- **TSO** segment: Time Sharing Option settings
- **OMVS** segment: Unix System Services (UID, home directory)
- **CICS** segment: CICS transaction settings
- **KERB** segment: Kerberos authentication
- **PROXY** segment: LDAP proxy settings
- **EIM** segment: Enterprise Identity Mapping

And about twenty more. Each segment has its own operands. Each operand has its own syntax. The ADDUSER command alone has over 150 possible operands across all segments.

This is what happens when a security system evolves for 50 years without breaking backwards compatibility.

## Documentation Sources

This LSP is being developed using official IBM documentation:

| Document | Description |
|----------|-------------|
| **RACF Command Language Reference** | Every command, every operand, every edge case |
| **RACF Security Administrator's Guide** | Concepts and best practices |
| **RACF Messages and Codes** | What went wrong and why |
| **RACF Auditor's Guide** | What the auditors are looking for |

The Command Language Reference is the primary source. It is comprehensive. It is thorough. It assumes you already know what you're doing. This is the IBM way.

## Why This Matters

RACF administrators are a dying breed. The people who built these systems in the 1980s are retiring. The documentation assumes knowledge that was common forty years ago and is now archaeological. The commands haven't changed, but the people who understand them are leaving.

Meanwhile, the mainframes keep running. The banks still need access control. The auditors still need reports. Someone has to maintain the security infrastructure, and increasingly that someone is a person who learned z/OS from YouTube videos and prayer.

This LSP will exist because if you're going to be that person, you should at least have syntax highlighting.

## Project Structure

```
racf-lsp/
├── grammar/           # Command grammar specifications
│   └── ADDUSER.md     # ADDUSER command reference
├── examples/          # Parser prototypes
│   └── adduser_parser.py
├── src/               # The LSP (eventually)
├── test/              # Test files
│   └── sample.racf    # Sample commands
└── README.md          # Ambitious claims
```

## Related Projects

Other LSPs for languages that predate their maintainers:

- **[OS/360 Assembler LSP](https://github.com/Zaneham/os360-lsp)** for when you need to read what RACF is actually doing underneath
- **[MUMPS LSP](https://github.com/Zaneham/mumps-lsp)** for the healthcare systems that RACF is probably protecting
- **[JOVIAL LSP](https://github.com/Zaneham/jovial-lsp)** for the aircraft systems that... actually, hopefully those have their own security
- **[HAL/S LSP](https://github.com/Zaneham/hals-lsp)** for the Space Shuttle, which did not use RACF, being in space

## Contributing

This is a work in progress. Contributions are welcome, particularly:

- Grammar specifications for other commands
- Real-world RACF command examples (sanitised, please)
- Corrections from actual RACF administrators
- Suggestions for how to structure the parser
- Encouragement

If you've been doing RACF since the Reagan administration, your knowledge is invaluable. Please share it before it's lost. If you're like me and learned RACF from PDFs and determination, solidarity.

## Licence

Apache License 2.0. See LICENSE for details.

Copyright 2025 Zane Hambly

## Contact

Questions? Suggestions? Want to watch this project slowly take shape?

zanehambly@gmail.com

Response time variable. Currently learning how RACF handles nested parentheses. Send help.
