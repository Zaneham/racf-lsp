#!/usr/bin/env python3
"""
RACF Language Server Protocol Implementation

The security system that decides who touches what on the mainframe.
Since 1976. Your bank account depends on this.

Apache 2.0 License - Zane Hambly 2025
"""

import re
import json
import sys
import os
from pathlib import Path
from urllib.parse import urlparse, unquote
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum, auto


# ============================================================================
# RACF Command Definitions
# From the RACF Command Language Reference (SA22-7687)
# ============================================================================

# Command categories and their descriptions
RACF_COMMANDS = {
    # User Administration
    'ADDUSER': ('AU', 'Create a new user profile'),
    'ALTUSER': ('ALU', 'Modify an existing user profile'),
    'DELUSER': ('DU', 'Delete a user profile'),
    'LISTUSER': ('LU', 'Display user profile information'),
    'PASSWORD': ('PW', 'Change user password'),

    # Group Administration
    'ADDGROUP': ('AG', 'Create a new group profile'),
    'ALTGROUP': ('ALG', 'Modify an existing group profile'),
    'DELGROUP': ('DG', 'Delete a group profile'),
    'LISTGRP': ('LG', 'Display group profile information'),

    # Connect/Remove
    'CONNECT': ('CO', 'Connect a user to a group'),
    'REMOVE': ('RE', 'Remove a user from a group'),

    # Dataset Profiles
    'ADDSD': ('AD', 'Add a dataset profile'),
    'ALTDSD': ('ALD', 'Alter a dataset profile'),
    'DELDSD': ('DD', 'Delete a dataset profile'),
    'LISTDSD': ('LD', 'List dataset profile'),

    # General Resources
    'RDEFINE': ('RDEF', 'Define a general resource profile'),
    'RALTER': ('RALT', 'Alter a general resource profile'),
    'RDELETE': ('RDEL', 'Delete a general resource profile'),
    'RLIST': ('RL', 'List a general resource profile'),

    # Permissions
    'PERMIT': ('PE', 'Add/change/delete access to a resource'),

    # System Options
    'SETROPTS': ('SETR', 'Set RACF system options'),

    # Search
    'SEARCH': ('SR', 'Search the RACF database'),

    # Digital Certificates
    'RACDCERT': ('', 'Administer digital certificates'),
}

# Base segment keywords for ADDUSER/ALTUSER
BASE_KEYWORDS = {
    # Flags (boolean, no value)
    'ADSP': 'Automatic dataset protection',
    'NOADSP': 'No automatic dataset protection',
    'AUDITOR': 'User has auditor authority',
    'NOAUDITOR': 'User does not have auditor authority',
    'GRPACC': 'Group access for datasets',
    'NOGRPACC': 'No group access',
    'OIDCARD': 'Require operator ID card',
    'NOOIDCARD': 'No operator ID card required',
    'OPERATIONS': 'Operations authority',
    'NOOPERATIONS': 'No operations authority',
    'RESTRICTED': 'Restricted user',
    'NORESTRICTED': 'Not restricted',
    'ROAUDIT': 'Read-only auditor',
    'NOROAUDIT': 'Not read-only auditor',
    'SPECIAL': 'SPECIAL authority (full admin)',
    'NOSPECIAL': 'No SPECIAL authority',
    'NOPASSWORD': 'No password required',
    'NOCLAUTH': 'No class authority',

    # Keywords with values
    'ADDCATEGORY': 'Security category list',
    'AUTHORITY': 'Group authority (USE, CREATE, CONNECT, JOIN)',
    'CLAUTH': 'Class authority list',
    'DATA': 'Installation-defined data (quoted string)',
    'DFLTGRP': 'Default group',
    'MODEL': 'Model dataset profile',
    'NAME': 'User name (quoted string)',
    'OWNER': 'Profile owner (userid or group)',
    'PASSWORD': 'Initial password',
    'PHRASE': 'Password phrase (quoted string)',
    'SECLABEL': 'Security label',
    'SECLEVEL': 'Security level',
    'UACC': 'Universal access (NONE, READ, UPDATE, CONTROL, ALTER)',
}

# Segment names
SEGMENTS = {
    'CICS': 'CICS segment - transaction processing settings',
    'DCE': 'DCE segment - Distributed Computing Environment',
    'DFP': 'DFP segment - Data Facility Product settings',
    'EIM': 'EIM segment - Enterprise Identity Mapping',
    'KERB': 'KERB segment - Kerberos authentication',
    'LANGUAGE': 'LANGUAGE segment - language preferences',
    'LNOTES': 'LNOTES segment - Lotus Notes',
    'NDS': 'NDS segment - Novell Directory Services',
    'NETVIEW': 'NETVIEW segment - network management',
    'OMVS': 'OMVS segment - z/OS UNIX settings',
    'OPERPARM': 'OPERPARM segment - operator parameters',
    'OVM': 'OVM segment - OpenExtensions',
    'PROXY': 'PROXY segment - LDAP proxy',
    'TSO': 'TSO segment - Time Sharing Option settings',
    'WHEN': 'WHEN segment - time/day restrictions',
    'WORKATTR': 'WORKATTR segment - work attributes',
}

# OMVS segment keywords
OMVS_KEYWORDS = {
    'ASSIZEMAX': 'Maximum address space size',
    'AUTOUID': 'Automatically assign UID',
    'UID': 'User identifier (0-2147483647)',
    'SHARED': 'UID can be shared',
    'CPUTIMEMAX': 'Maximum CPU time (seconds)',
    'FILEPROCMAX': 'Maximum files per process',
    'HOME': 'Home directory path (quoted)',
    'MEMLIMIT': 'Memory limit',
    'NOMEMLIMIT': 'No memory limit',
    'MMAPAREAMAX': 'Maximum memory map area',
    'PROCUSERMAX': 'Maximum processes per UID',
    'PROGRAM': 'Initial program (shell path, quoted)',
    'SHMEMMAX': 'Maximum shared memory',
    'NOSHMEMMAX': 'No shared memory limit',
    'THREADSMAX': 'Maximum threads per process',
}

# TSO segment keywords
TSO_KEYWORDS = {
    'ACCTNUM': 'Account number',
    'COMMAND': 'Command issued at logon',
    'DEST': 'Destination ID',
    'HOLDCLASS': 'Hold class (single char)',
    'JOBCLASS': 'Job class (single char)',
    'MAXSIZE': 'Maximum region size (KB)',
    'MSGCLASS': 'Message class (single char)',
    'PROC': 'Logon procedure name',
    'SECLABEL': 'Security label',
    'SIZE': 'Default region size (KB)',
    'UNIT': 'Unit name',
    'USERDATA': 'User data',
}

# Access authorities
ACCESS_LEVELS = {
    'NONE': 'No access',
    'READ': 'Read access',
    'UPDATE': 'Read and write access',
    'CONTROL': 'Control access (VSAM)',
    'ALTER': 'Full control including delete',
}

# Group authorities
GROUP_AUTHORITIES = {
    'USE': 'Use group datasets',
    'CREATE': 'Create datasets for group',
    'CONNECT': 'Connect users to group',
    'JOIN': 'Full group administration',
}

# Resource classes (common ones)
RESOURCE_CLASSES = {
    'DATASET': 'Dataset profiles',
    'FACILITY': 'Facility class (system resources)',
    'PROGRAM': 'Program profiles',
    'TERMINAL': 'Terminal profiles',
    'SDSF': 'SDSF class',
    'TAPEVOL': 'Tape volume profiles',
    'DASDVOL': 'DASD volume profiles',
    'JESSPOOL': 'JES spool profiles',
    'JESJOBS': 'JES job profiles',
    'SURROGAT': 'Surrogate class',
    'OPERCMDS': 'Operator commands',
    'CONSOLE': 'Console class',
}

# All keywords combined for lexer
ALL_KEYWORDS = set()
ALL_KEYWORDS.update(RACF_COMMANDS.keys())
ALL_KEYWORDS.update(k for k, _ in RACF_COMMANDS.values() if k)  # Abbreviations
ALL_KEYWORDS.update(BASE_KEYWORDS.keys())
ALL_KEYWORDS.update(SEGMENTS.keys())
ALL_KEYWORDS.update(OMVS_KEYWORDS.keys())
ALL_KEYWORDS.update(TSO_KEYWORDS.keys())
ALL_KEYWORDS.update(ACCESS_LEVELS.keys())
ALL_KEYWORDS.update(GROUP_AUTHORITIES.keys())
ALL_KEYWORDS.update(RESOURCE_CLASSES.keys())
ALL_KEYWORDS.update(['CLASS', 'ID', 'ACCESS', 'AUDIT', 'ALL', 'MASK', 'REFRESH',
                     'HISTORY', 'INTERVAL', 'CLASSACT', 'RACLIST', 'GID', 'SUPGROUP'])


# ============================================================================
# Token Types
# ============================================================================

class TokenType(Enum):
    COMMAND = auto()
    KEYWORD = auto()
    SEGMENT = auto()
    LPAREN = auto()
    RPAREN = auto()
    STRING = auto()
    IDENTIFIER = auto()
    NUMBER = auto()
    CONTINUATION = auto()
    COMMENT = auto()
    EOF = auto()


@dataclass
class Token:
    type: TokenType
    value: str
    line: int
    column: int
    end_column: int = 0

    def __post_init__(self):
        if self.end_column == 0:
            self.end_column = self.column + len(self.value)


# ============================================================================
# Lexer
# ============================================================================

class Lexer:
    def __init__(self, source: str):
        self.source = source
        self.pos = 0
        self.line = 0
        self.column = 0
        self.tokens: List[Token] = []

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
            self.column = 0
        else:
            self.column += 1
        return char

    def skip_whitespace(self):
        while self.current_char() and self.current_char() in ' \t':
            self.advance()

    def read_comment(self) -> Token:
        """Read /* ... */ comment"""
        start_line = self.line
        start_col = self.column
        value = ""
        self.advance()  # /
        self.advance()  # *
        value = "/*"
        while self.current_char():
            if self.current_char() == '*' and self.peek() == '/':
                value += "*/"
                self.advance()
                self.advance()
                break
            value += self.advance()
        return Token(TokenType.COMMENT, value, start_line, start_col)

    def read_string(self) -> Token:
        """Read 'quoted string' - handles '' for embedded quotes"""
        start_line = self.line
        start_col = self.column
        self.advance()  # opening quote
        value = ""
        while self.current_char():
            if self.current_char() == "'":
                if self.peek() == "'":
                    value += "'"
                    self.advance()
                    self.advance()
                else:
                    self.advance()
                    break
            else:
                value += self.advance()
        return Token(TokenType.STRING, value, start_line, start_col)

    def read_identifier(self) -> Token:
        """Read identifier or keyword"""
        start_line = self.line
        start_col = self.column
        value = ""
        while self.current_char() and (self.current_char().isalnum()
                                        or self.current_char() in '@#$._'):
            value += self.advance()

        upper = value.upper()

        # Determine token type
        if upper in RACF_COMMANDS:
            return Token(TokenType.COMMAND, upper, start_line, start_col)
        # Check abbreviations
        for cmd, (abbrev, _) in RACF_COMMANDS.items():
            if upper == abbrev:
                return Token(TokenType.COMMAND, upper, start_line, start_col)
        if upper in SEGMENTS:
            return Token(TokenType.SEGMENT, upper, start_line, start_col)
        if upper in ALL_KEYWORDS:
            return Token(TokenType.KEYWORD, upper, start_line, start_col)
        if value.isdigit():
            return Token(TokenType.NUMBER, value, start_line, start_col)

        return Token(TokenType.IDENTIFIER, value.upper(), start_line, start_col)

    def tokenize(self) -> List[Token]:
        while self.current_char():
            # Skip whitespace (but not newlines - they matter for continuation)
            if self.current_char() in ' \t':
                self.skip_whitespace()
                continue

            # Newline
            if self.current_char() == '\n':
                self.advance()
                continue

            # Comment /* ... */
            if self.current_char() == '/' and self.peek() == '*':
                self.tokens.append(self.read_comment())
                continue

            # Line continuation (- at end of line)
            if self.current_char() == '-':
                # Check if followed by newline or end
                rest = self.source[self.pos + 1:].lstrip(' \t')
                if not rest or rest[0] == '\n':
                    self.tokens.append(Token(TokenType.CONTINUATION, '-',
                                            self.line, self.column))
                    self.advance()
                    continue
                # Otherwise it might be part of something else
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
            if self.current_char().isalnum() or self.current_char() in '@#$%':
                self.tokens.append(self.read_identifier())
                continue

            # Skip unknown characters
            self.advance()

        self.tokens.append(Token(TokenType.EOF, '', self.line, self.column))
        return self.tokens


# ============================================================================
# Document Representation
# ============================================================================

@dataclass
class RACFCommand:
    """Represents a parsed RACF command"""
    name: str
    line: int
    end_line: int
    arguments: List[str] = field(default_factory=list)
    keywords: Dict[str, Any] = field(default_factory=dict)
    segments: Dict[str, Dict] = field(default_factory=dict)
    flags: Set[str] = field(default_factory=set)


class RACFDocument:
    """Represents a parsed RACF document"""

    def __init__(self, uri: str, content: str):
        self.uri = uri
        self.content = content
        self.lines = content.split('\n')
        self.commands: List[RACFCommand] = []
        self.diagnostics: List[dict] = []
        self.tokens: List[Token] = []
        self.parse()

    def parse(self):
        """Parse the document"""
        lexer = Lexer(self.content)
        self.tokens = lexer.tokenize()

        # Simple command detection for now
        i = 0
        while i < len(self.tokens):
            token = self.tokens[i]
            if token.type == TokenType.COMMAND:
                cmd = RACFCommand(
                    name=token.value,
                    line=token.line,
                    end_line=token.line
                )
                # Find end of command (next command or EOF)
                j = i + 1
                while j < len(self.tokens):
                    if self.tokens[j].type == TokenType.COMMAND:
                        break
                    if self.tokens[j].type == TokenType.EOF:
                        break
                    cmd.end_line = self.tokens[j].line
                    j += 1
                self.commands.append(cmd)
            i += 1

    def get_token_at_position(self, line: int, character: int) -> Optional[Token]:
        """Get token at given position"""
        for token in self.tokens:
            if token.line == line:
                if token.column <= character < token.end_column:
                    return token
        return None

    def get_command_at_line(self, line: int) -> Optional[RACFCommand]:
        """Get command containing the given line"""
        for cmd in self.commands:
            if cmd.line <= line <= cmd.end_line:
                return cmd
        return None


# ============================================================================
# Language Server
# ============================================================================

def uri_to_path(uri: str) -> str:
    """Convert file URI to filesystem path."""
    parsed = urlparse(uri)
    path = unquote(parsed.path)
    if sys.platform == 'win32' and path.startswith('/') and len(path) > 2 and path[2] == ':':
        path = path[1:]
    return path


class RACFLanguageServer:
    """RACF Language Server"""

    def __init__(self):
        self.documents: Dict[str, RACFDocument] = {}
        self.running = True

    def send_message(self, message: dict):
        """Send a JSON-RPC message"""
        content = json.dumps(message)
        header = f'Content-Length: {len(content)}\r\n\r\n'
        sys.stdout.write(header + content)
        sys.stdout.flush()

    def send_response(self, request_id: Any, result: Any):
        """Send a response"""
        self.send_message({
            'jsonrpc': '2.0',
            'id': request_id,
            'result': result
        })

    def send_error(self, request_id: Any, code: int, message: str):
        """Send an error response"""
        self.send_message({
            'jsonrpc': '2.0',
            'id': request_id,
            'error': {'code': code, 'message': message}
        })

    def send_notification(self, method: str, params: dict):
        """Send a notification"""
        self.send_message({
            'jsonrpc': '2.0',
            'method': method,
            'params': params
        })

    def read_message(self) -> Optional[dict]:
        """Read a JSON-RPC message from stdin"""
        try:
            headers = {}
            while True:
                line = sys.stdin.readline()
                if not line:
                    return None
                line = line.strip()
                if not line:
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()

            content_length = int(headers.get('Content-Length', 0))
            if content_length > 0:
                content = sys.stdin.read(content_length)
                return json.loads(content)
        except Exception:
            return None
        return None

    def handle_initialize(self, params: dict) -> dict:
        """Handle initialize request"""
        return {
            'capabilities': {
                'textDocumentSync': {
                    'openClose': True,
                    'change': 1,  # Full sync
                    'save': {'includeText': True}
                },
                'completionProvider': {
                    'triggerCharacters': ['(', ' '],
                    'resolveProvider': False
                },
                'hoverProvider': True,
                'documentSymbolProvider': True,
            },
            'serverInfo': {
                'name': 'RACF Language Server',
                'version': '0.1.0'
            }
        }

    def handle_completion(self, params: dict) -> List[dict]:
        """Provide completions"""
        uri = params['textDocument']['uri']
        position = params['position']

        doc = self.documents.get(uri)
        if not doc:
            return []

        line = position['line']
        character = position['character']

        if line >= len(doc.lines):
            return []

        line_text = doc.lines[line]
        prefix = line_text[:character].upper()

        completions = []

        # Get context
        cmd = doc.get_command_at_line(line)

        # Check if we're inside parentheses (segment or value context)
        open_parens = prefix.count('(') - prefix.count(')')

        if open_parens > 0:
            # Inside parentheses - suggest segment keywords or values
            # Find what segment we're in
            last_segment = None
            for seg in SEGMENTS.keys():
                if seg + '(' in prefix:
                    last_segment = seg

            if last_segment == 'OMVS':
                for kw, desc in OMVS_KEYWORDS.items():
                    completions.append({
                        'label': kw,
                        'kind': 14,  # Keyword
                        'detail': desc,
                        'documentation': f'OMVS segment: {desc}'
                    })
            elif last_segment == 'TSO':
                for kw, desc in TSO_KEYWORDS.items():
                    completions.append({
                        'label': kw,
                        'kind': 14,
                        'detail': desc,
                        'documentation': f'TSO segment: {desc}'
                    })
            else:
                # Suggest access levels
                for level, desc in ACCESS_LEVELS.items():
                    completions.append({
                        'label': level,
                        'kind': 21,  # Constant
                        'detail': desc
                    })

        elif not cmd or prefix.strip() == '' or prefix.rstrip().endswith('\n'):
            # Start of line - suggest commands
            for cmd_name, (abbrev, desc) in RACF_COMMANDS.items():
                completions.append({
                    'label': cmd_name,
                    'kind': 14,  # Keyword
                    'detail': f'({abbrev}) {desc}' if abbrev else desc,
                    'documentation': desc
                })

        else:
            # After command - suggest keywords and segments
            for kw, desc in BASE_KEYWORDS.items():
                completions.append({
                    'label': kw,
                    'kind': 14,
                    'detail': desc
                })

            for seg, desc in SEGMENTS.items():
                completions.append({
                    'label': seg,
                    'kind': 7,  # Class (for segments)
                    'detail': desc,
                    'insertText': f'{seg}($0)',
                    'insertTextFormat': 2  # Snippet
                })

            # Common keywords
            completions.append({'label': 'CLASS', 'kind': 14, 'detail': 'Resource class'})
            completions.append({'label': 'ID', 'kind': 14, 'detail': 'User or group ID'})
            completions.append({'label': 'ACCESS', 'kind': 14, 'detail': 'Access level'})

        return completions

    def handle_hover(self, params: dict) -> Optional[dict]:
        """Provide hover information"""
        uri = params['textDocument']['uri']
        position = params['position']

        doc = self.documents.get(uri)
        if not doc:
            return None

        token = doc.get_token_at_position(position['line'], position['character'])
        if not token:
            return None

        word = token.value.upper()

        # Check commands
        if word in RACF_COMMANDS:
            abbrev, desc = RACF_COMMANDS[word]
            abbrev_str = f' (abbreviation: {abbrev})' if abbrev else ''
            return {
                'contents': {
                    'kind': 'markdown',
                    'value': f'**{word}**{abbrev_str}\n\n{desc}'
                }
            }

        # Check command abbreviations
        for cmd, (abbrev, desc) in RACF_COMMANDS.items():
            if word == abbrev:
                return {
                    'contents': {
                        'kind': 'markdown',
                        'value': f'**{word}** (full: {cmd})\n\n{desc}'
                    }
                }

        # Check base keywords
        if word in BASE_KEYWORDS:
            return {
                'contents': {
                    'kind': 'markdown',
                    'value': f'**{word}**\n\n{BASE_KEYWORDS[word]}'
                }
            }

        # Check segments
        if word in SEGMENTS:
            return {
                'contents': {
                    'kind': 'markdown',
                    'value': f'**{word}**\n\n{SEGMENTS[word]}'
                }
            }

        # Check OMVS keywords
        if word in OMVS_KEYWORDS:
            return {
                'contents': {
                    'kind': 'markdown',
                    'value': f'**{word}** (OMVS segment)\n\n{OMVS_KEYWORDS[word]}'
                }
            }

        # Check TSO keywords
        if word in TSO_KEYWORDS:
            return {
                'contents': {
                    'kind': 'markdown',
                    'value': f'**{word}** (TSO segment)\n\n{TSO_KEYWORDS[word]}'
                }
            }

        # Check access levels
        if word in ACCESS_LEVELS:
            return {
                'contents': {
                    'kind': 'markdown',
                    'value': f'**{word}**\n\nAccess level: {ACCESS_LEVELS[word]}'
                }
            }

        # Check resource classes
        if word in RESOURCE_CLASSES:
            return {
                'contents': {
                    'kind': 'markdown',
                    'value': f'**{word}**\n\nResource class: {RESOURCE_CLASSES[word]}'
                }
            }

        return None

    def handle_document_symbol(self, params: dict) -> List[dict]:
        """Provide document symbols"""
        uri = params['textDocument']['uri']
        doc = self.documents.get(uri)
        if not doc:
            return []

        symbols = []
        for cmd in doc.commands:
            # Get first argument if any
            detail = ''
            if cmd.arguments:
                detail = cmd.arguments[0]

            symbols.append({
                'name': cmd.name,
                'detail': detail,
                'kind': 12,  # Function
                'range': {
                    'start': {'line': cmd.line, 'character': 0},
                    'end': {'line': cmd.end_line, 'character': len(doc.lines[cmd.end_line]) if cmd.end_line < len(doc.lines) else 0}
                },
                'selectionRange': {
                    'start': {'line': cmd.line, 'character': 0},
                    'end': {'line': cmd.line, 'character': len(cmd.name)}
                }
            })

        return symbols

    def handle_did_open(self, params: dict):
        """Handle textDocument/didOpen"""
        uri = params['textDocument']['uri']
        text = params['textDocument']['text']
        self.documents[uri] = RACFDocument(uri, text)

    def handle_did_change(self, params: dict):
        """Handle textDocument/didChange"""
        uri = params['textDocument']['uri']
        changes = params.get('contentChanges', [])
        if changes:
            text = changes[0].get('text', '')
            self.documents[uri] = RACFDocument(uri, text)

    def handle_did_close(self, params: dict):
        """Handle textDocument/didClose"""
        uri = params['textDocument']['uri']
        if uri in self.documents:
            del self.documents[uri]

    def run(self):
        """Main server loop"""
        while self.running:
            message = self.read_message()
            if message is None:
                break

            method = message.get('method', '')
            params = message.get('params', {})
            request_id = message.get('id')

            try:
                if method == 'initialize':
                    result = self.handle_initialize(params)
                    self.send_response(request_id, result)

                elif method == 'initialized':
                    pass

                elif method == 'shutdown':
                    self.send_response(request_id, None)

                elif method == 'exit':
                    self.running = False

                elif method == 'textDocument/didOpen':
                    self.handle_did_open(params)

                elif method == 'textDocument/didChange':
                    self.handle_did_change(params)

                elif method == 'textDocument/didClose':
                    self.handle_did_close(params)

                elif method == 'textDocument/completion':
                    result = self.handle_completion(params)
                    self.send_response(request_id, result)

                elif method == 'textDocument/hover':
                    result = self.handle_hover(params)
                    self.send_response(request_id, result)

                elif method == 'textDocument/documentSymbol':
                    result = self.handle_document_symbol(params)
                    self.send_response(request_id, result)

                elif request_id is not None:
                    self.send_response(request_id, None)

            except Exception as e:
                if request_id is not None:
                    self.send_error(request_id, -32603, str(e))


if __name__ == '__main__':
    server = RACFLanguageServer()
    server.run()
