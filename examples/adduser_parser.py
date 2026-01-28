"""
ADDUSER Parser Example
======================
Hello! if you follow my work you may be wondering; "this is familiar?!" 
well thank you fan or passerby. This is because i'm basically using all my other LSP's as a format for this one so this one looks similar to all others.

over time this will be added on and youll see more files in this folder.
"""

import re
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum, auto


# =============================================================================
# Token Types
# =============================================================================

class TokenType(Enum):
    COMMAND = auto()      # ADDUSER, AU
    KEYWORD = auto()      # NAME, DFLTGRP, SPECIAL, etc.
    LPAREN = auto()       # (
    RPAREN = auto()       # )
    STRING = auto()       # 'quoted string'
    IDENTIFIER = auto()   # JSMITH, PAYROLL, etc.
    NUMBER = auto()       # 1000, 2147483647
    CONTINUATION = auto() # - at end of line
    EOF = auto()


@dataclass
class Token:
    type: TokenType
    value: str
    line: int
    column: int


# =============================================================================
# Lexer (Tokenizer)
# =============================================================================

# Keywords for ADDUSER (expand this for other commands)
ADDUSER_KEYWORDS = {
    # Command
    'ADDUSER', 'AU',
    # Base segment - flags
    'ADSP', 'NOADSP', 'AUDITOR', 'NOAUDITOR', 'GRPACC', 'NOGRPACC',
    'OIDCARD', 'NOOIDCARD', 'OPERATIONS', 'NOOPERATIONS',
    'RESTRICTED', 'NORESTRICTED', 'ROAUDIT', 'NOROAUDIT',
    'SPECIAL', 'NOSPECIAL', 'NOPASSWORD', 'NOCLAUTH',
    # Base segment - with values
    'ADDCATEGORY', 'AUTHORITY', 'CLAUTH', 'DATA', 'DFLTGRP',
    'MODEL', 'NAME', 'OWNER', 'PASSWORD', 'PHRASE',
    'SECLABEL', 'SECLEVEL', 'UACC',
    # Segment names
    'CICS', 'DCE', 'DFP', 'EIM', 'KERB', 'LANGUAGE', 'LNOTES',
    'NDS', 'NETVIEW', 'OMVS', 'OPERPARM', 'OVM', 'PROXY',
    'TSO', 'WHEN', 'WORKATTR',
    # OMVS segment keywords
    'ASSIZEMAX', 'AUTOUID', 'UID', 'SHARED', 'CPUTIMEMAX',
    'FILEPROCMAX', 'HOME', 'MEMLIMIT', 'NOMEMLIMIT',
    'MMAPAREAMAX', 'PROCUSERMAX', 'PROGRAM', 'SHMEMMAX',
    'NOSHMEMMAX', 'THREADSMAX',
    # TSO segment keywords
    'ACCTNUM', 'COMMAND', 'DEST', 'HOLDCLASS', 'JOBCLASS',
    'MAXSIZE', 'MSGCLASS', 'PROC', 'SIZE', 'SYS', 'UNIT', 'USERDATA',
    # DFP segment keywords
    'DATAAPPL', 'DATACLAS', 'MGMTCLAS', 'STORCLAS',
    # WHEN segment keywords
    'DAYS', 'TIME',
    # KERB segment keywords
    'ENCRYPT', 'KERBNAME', 'MAXTKTLFE',
    'DES', 'NODES', 'DES3', 'NODES3', 'DESD', 'NODESD',
    'AES128', 'NOAES128', 'AES256', 'NOAES256',
    'AES128SHA2', 'NOAES128SHA2', 'AES256SHA2', 'NOAES256SHA2',
    # LANGUAGE segment keywords
    'PRIMARY', 'SECONDARY',
    # CICS segment keywords
    'OPCLASS', 'OPIDENT', 'OPPRTY', 'RSLKEY', 'TIMEOUT', 'TSLKEY',
    'XRFSOFF', 'FORCE', 'NOFORCE',
    # Access authorities (used with UACC, AUTHORITY)
    'NONE', 'READ', 'UPDATE', 'CONTROL', 'ALTER',
    'USE', 'CREATE', 'CONNECT', 'JOIN',
}


class Lexer:
    def __init__(self, source: str):
        self.source = source
        self.pos = 0
        self.line = 1
        self.column = 1
        self.tokens: list[Token] = []

    def current_char(self) -> Optional[str]:
        if self.pos >= len(self.source):
            return None
        return self.source[self.pos]

    def peek(self, offset: int = 1) -> Optional[str]:
        pos = self.pos + offset
        if pos >= len(self.source):
            return None
        return self.source[pos]

    def advance(self) -> Optional[str]:
        char = self.current_char()
        self.pos += 1
        if char == '\n':
            self.line += 1
            self.column = 1
        else:
            self.column += 1
        return char

    def skip_whitespace(self):
        while self.current_char() and self.current_char() in ' \t\n\r':
            self.advance()

    def skip_comment(self):
        """Skip /* ... */ comments"""
        if self.current_char() == '/' and self.peek() == '*':
            self.advance()  # /
            self.advance()  # *
            while self.current_char():
                if self.current_char() == '*' and self.peek() == '/':
                    self.advance()  # *
                    self.advance()  # /
                    return
                self.advance()

    def read_string(self) -> Token:
        """Read 'quoted string' - handles '' for embedded quotes"""
        start_line = self.line
        start_col = self.column
        self.advance()  # opening quote

        value = ""
        while self.current_char():
            if self.current_char() == "'":
                if self.peek() == "'":
                    # Embedded quote
                    value += "'"
                    self.advance()
                    self.advance()
                else:
                    # End of string
                    self.advance()
                    break
            else:
                value += self.advance()

        return Token(TokenType.STRING, value, start_line, start_col)

    def read_identifier_or_keyword(self) -> Token:
        """Read identifier or keyword"""
        start_line = self.line
        start_col = self.column

        value = ""
        while self.current_char() and (self.current_char().isalnum()
                                        or self.current_char() in '@#$_'):
            value += self.advance()

        upper = value.upper()
        if upper in ADDUSER_KEYWORDS:
            if upper in ('ADDUSER', 'AU'):
                return Token(TokenType.COMMAND, upper, start_line, start_col)
            return Token(TokenType.KEYWORD, upper, start_line, start_col)

        # Check if it's a number
        if value.isdigit():
            return Token(TokenType.NUMBER, value, start_line, start_col)

        return Token(TokenType.IDENTIFIER, value.upper(), start_line, start_col)

    def tokenize(self) -> list[Token]:
        while self.current_char():
            # Skip whitespace
            if self.current_char() in ' \t\n\r':
                self.skip_whitespace()
                continue

            # Skip comments
            if self.current_char() == '/' and self.peek() == '*':
                self.skip_comment()
                continue

            # Line continuation
            if self.current_char() == '-' and (self.peek() is None
                                                or self.peek() in '\n\r'):
                self.tokens.append(Token(TokenType.CONTINUATION, '-',
                                        self.line, self.column))
                self.advance()
                continue

            # Parentheses
            if self.current_char() == '(':
                self.tokens.append(Token(TokenType.LPAREN, '(',
                                        self.line, self.column))
                self.advance()
                continue

            if self.current_char() == ')':
                self.tokens.append(Token(TokenType.RPAREN, ')',
                                        self.line, self.column))
                self.advance()
                continue

            # Quoted string
            if self.current_char() == "'":
                self.tokens.append(self.read_string())
                continue

            # Identifier, keyword, or number
            if self.current_char().isalnum() or self.current_char() in '@#$':
                self.tokens.append(self.read_identifier_or_keyword())
                continue

            # Unknown character - skip it (or you could error)
            self.advance()

        self.tokens.append(Token(TokenType.EOF, '', self.line, self.column))
        return self.tokens


# =============================================================================
# AST (Abstract Syntax Tree)
# =============================================================================

@dataclass
class Segment:
    """A segment like OMVS(...) or TSO(...)"""
    name: str
    keywords: dict[str, any] = field(default_factory=dict)


@dataclass
class AddUserCommand:
    """Parsed ADDUSER command"""
    userids: list[str] = field(default_factory=list)
    keywords: dict[str, any] = field(default_factory=dict)
    segments: dict[str, Segment] = field(default_factory=dict)
    flags: set[str] = field(default_factory=set)


# =============================================================================
# Parser
# =============================================================================

SEGMENT_NAMES = {
    'CICS', 'DCE', 'DFP', 'EIM', 'KERB', 'LANGUAGE', 'LNOTES',
    'NDS', 'NETVIEW', 'OMVS', 'OPERPARM', 'OVM', 'PROXY',
    'TSO', 'WHEN', 'WORKATTR', 'ENCRYPT'  # ENCRYPT is nested in KERB
}

FLAG_KEYWORDS = {
    'ADSP', 'NOADSP', 'AUDITOR', 'NOAUDITOR', 'GRPACC', 'NOGRPACC',
    'OIDCARD', 'NOOIDCARD', 'OPERATIONS', 'NOOPERATIONS',
    'RESTRICTED', 'NORESTRICTED', 'ROAUDIT', 'NOROAUDIT',
    'SPECIAL', 'NOSPECIAL', 'NOPASSWORD', 'NOCLAUTH',
    'AUTOUID', 'SHARED', 'NOMEMLIMIT', 'NOSHMEMMAX',
    'DES', 'NODES', 'DES3', 'NODES3', 'DESD', 'NODESD',
    'AES128', 'NOAES128', 'AES256', 'NOAES256',
    'AES128SHA2', 'NOAES128SHA2', 'AES256SHA2', 'NOAES256SHA2',
    'FORCE', 'NOFORCE',
}


class Parser:
    def __init__(self, tokens: list[Token]):
        self.tokens = [t for t in tokens if t.type != TokenType.CONTINUATION]
        self.pos = 0

    def current(self) -> Token:
        if self.pos >= len(self.tokens):
            return self.tokens[-1]  # EOF
        return self.tokens[self.pos]

    def advance(self) -> Token:
        token = self.current()
        self.pos += 1
        return token

    def expect(self, token_type: TokenType) -> Token:
        token = self.current()
        if token.type != token_type:
            raise SyntaxError(
                f"Expected {token_type.name}, got {token.type.name} "
                f"at line {token.line}, column {token.column}"
            )
        return self.advance()

    def parse_value_list(self) -> list[str]:
        """Parse (value1 value2 value3)"""
        self.expect(TokenType.LPAREN)
        values = []

        while self.current().type != TokenType.RPAREN:
            token = self.current()
            if token.type in (TokenType.IDENTIFIER, TokenType.STRING,
                             TokenType.NUMBER, TokenType.KEYWORD):
                values.append(token.value)
                self.advance()
            else:
                break

        self.expect(TokenType.RPAREN)
        return values

    def parse_single_value(self) -> str:
        """Parse (value) and return the single value"""
        values = self.parse_value_list()
        if len(values) == 1:
            return values[0]
        return values  # Return list if multiple

    def parse_segment(self, name: str) -> Segment:
        """Parse a segment like OMVS(UID(100) HOME('/u/x'))"""
        segment = Segment(name=name)
        self.expect(TokenType.LPAREN)

        while self.current().type != TokenType.RPAREN:
            if self.current().type == TokenType.KEYWORD:
                kw = self.advance().value

                if kw in FLAG_KEYWORDS:
                    segment.keywords[kw] = True
                elif self.current().type == TokenType.LPAREN:
                    if kw in SEGMENT_NAMES:
                        # Nested segment (like ENCRYPT inside KERB)
                        segment.keywords[kw] = self.parse_segment(kw)
                    else:
                        segment.keywords[kw] = self.parse_single_value()
            elif self.current().type == TokenType.EOF:
                break
            else:
                self.advance()  # Skip unexpected tokens

        self.expect(TokenType.RPAREN)
        return segment

    def parse(self) -> AddUserCommand:
        """Parse ADDUSER command"""
        cmd = AddUserCommand()

        # Expect ADDUSER or AU
        token = self.current()
        if token.type != TokenType.COMMAND:
            raise SyntaxError(f"Expected ADDUSER command at line {token.line}")
        self.advance()

        # Expect (userid ...)
        cmd.userids = self.parse_value_list()

        # Parse keywords
        while self.current().type not in (TokenType.EOF,):
            if self.current().type == TokenType.KEYWORD:
                kw = self.advance().value

                if kw in FLAG_KEYWORDS:
                    cmd.flags.add(kw)
                elif kw in SEGMENT_NAMES:
                    cmd.segments[kw] = self.parse_segment(kw)
                elif self.current().type == TokenType.LPAREN:
                    cmd.keywords[kw] = self.parse_single_value()
            else:
                # Skip unexpected tokens
                self.advance()

        return cmd


# =============================================================================
# Main - Test it out
# =============================================================================

def parse_adduser(source: str) -> AddUserCommand:
    """Convenience function to parse ADDUSER command"""
    lexer = Lexer(source)
    tokens = lexer.tokenize()
    parser = Parser(tokens)
    return parser.parse()


if __name__ == '__main__':
    # Test cases
    examples = [
        # Minimal
        "ADDUSER (JSMITH)",

        # With name and group
        "ADDUSER (JSMITH) NAME('John Smith') DFLTGRP(PAYROLL)",

        # Short form
        "AU (JSMITH) NAME('John Smith')",

        # With flags
        "ADDUSER (SECADMIN) SPECIAL AUDITOR OPERATIONS",

        # With OMVS segment
        """ADDUSER (JSMITH) NAME('John Smith') -
           OMVS(UID(1000) HOME('/u/jsmith') PROGRAM('/bin/sh'))""",

        # With TSO segment
        """ADDUSER (JSMITH) NAME('John Smith') -
           TSO(ACCTNUM(ACCT01) PROC(IKJACCNT) SIZE(4096))""",

        # Complex example
        """ADDUSER (JSMITH) NAME('John Smith') DFLTGRP(PAYROLL) -
           SPECIAL AUDITOR -
           OMVS(AUTOUID HOME('/u/jsmith')) -
           TSO(ACCTNUM(ACCT01) PROC(IKJACCNT))""",

        # Multiple users
        "ADDUSER (USER1 USER2 USER3) DFLTGRP(BATCH)",
    ]

    for example in examples:
        print("=" * 60)
        print("INPUT:")
        print(example)
        print()

        try:
            result = parse_adduser(example)
            print("PARSED:")
            print(f"  userids: {result.userids}")
            print(f"  keywords: {result.keywords}")
            print(f"  flags: {result.flags}")
            print(f"  segments: {list(result.segments.keys())}")

            for name, seg in result.segments.items():
                print(f"    {name}: {seg.keywords}")
        except Exception as e:
            print(f"ERROR: {e}")

        print()
