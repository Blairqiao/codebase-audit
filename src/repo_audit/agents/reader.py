"""Read/search MCP service. It accepts data, never programs or shell text."""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path, PurePosixPath
from typing import Any


class SafeReader:
    def __init__(self, root: Path, inventory: list[dict[str, Any]], *,
                 max_output_bytes: int = 32768) -> None:
        self.root = root.resolve(strict=True)
        self.inventory = {item['path']: item for item in inventory}
        self.max_output_bytes = max_output_bytes
        if max_output_bytes < 64:
            raise ValueError('Reader output budget must be at least 64 bytes')

    def _text(self, path: str) -> str:
        pure = PurePosixPath(path)
        if (not isinstance(path, str) or pure.is_absolute() or '..' in pure.parts
                or path not in self.inventory or str(pure) != path):
            raise ValueError('Path is outside the filtered inventory')
        item = self.inventory[path]
        if item['size_bytes'] > 4 * 1024 * 1024:
            raise ValueError('File exceeds bounded reader input size')
        # Walk through directory file descriptors so a replaced ancestor cannot escape the root.
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for index, part in enumerate(pure.parts):
                flags = os.O_RDONLY | os.O_NOFOLLOW
                if index < len(pure.parts) - 1:
                    flags |= os.O_DIRECTORY
                child = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = child
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                data = stream.read(item['size_bytes'] + 1)
            if (len(data) != item['size_bytes']
                    or hashlib.sha256(data).hexdigest() != item['sha256']):
                raise ValueError('Snapshot content digest changed')
            return data.decode('utf-8')
        except (OSError, UnicodeError) as exc:
            raise ValueError('Unreadable filtered snapshot file') from exc
        finally:
            os.close(fd)

    def read(self, path: str, start_line: int = 1, end_line: int | None = None) -> dict[str, Any]:
        lines = self._text(path).splitlines(keepends=True)
        end = len(lines) if end_line is None else end_line
        if (type(start_line) is not int or type(end) is not int or start_line < 1
                or end < start_line or end > len(lines)):
            raise ValueError('Invalid requested line range')
        output: list[str] = []
        size = 0
        for line in lines[start_line - 1:end]:
            if size + len(line.encode()) > self.max_output_bytes:
                break
            output.append(line)
            size += len(line.encode())
        return {'path': path, 'start_line': start_line,
                'end_line': start_line + len(output) - 1, 'text': ''.join(output),
                'truncated': len(output) != end - start_line + 1}

    def search(self, query: str) -> dict[str, Any]:
        if not isinstance(query, str) or not query or len(query) > 1024:
            raise ValueError('Search requires a bounded nonempty literal string')
        matches: list[dict[str, Any]] = []
        for path in sorted(self.inventory):
            for line, text in enumerate(self._text(path).splitlines(), 1):
                if query in text:
                    match = {'path': path, 'line': line, 'text': text}
                    proposed = {'matches': [*matches, match], 'truncated': False}
                    if len(json.dumps(proposed).encode()) > self.max_output_bytes:
                        return {'matches': matches, 'truncated': True}
                    matches.append(match)
        return {'matches': matches, 'truncated': False}

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == 'read_file' and set(arguments) <= {'path', 'start_line', 'end_line'}:
            return self.read(**arguments)
        if name == 'search' and set(arguments) == {'query'}:
            return self.search(arguments['query'])
        if name == 'list_files' and not arguments:
            paths: list[str] = []
            for path in sorted(self.inventory):
                if len(json.dumps({'paths': [*paths, path], 'truncated': False}).encode()) > self.max_output_bytes:
                    return {'paths': paths, 'truncated': True}
                paths.append(path)
            return {'paths': paths, 'truncated': False}
        raise ValueError('Unsupported read-only tool or arguments')


TOOLS = [
    {'name': 'read_file', 'description': 'Read a verified filtered snapshot line range.',
     'inputSchema': {'type': 'object', 'properties': {'path': {'type': 'string'},
       'start_line': {'type': 'integer', 'minimum': 1}, 'end_line': {'type': 'integer', 'minimum': 1}},
       'required': ['path'], 'additionalProperties': False}},
    {'name': 'search', 'description': 'Search filtered snapshot files for a literal string.',
     'inputSchema': {'type': 'object', 'properties': {'query': {'type': 'string'}},
                     'required': ['query'], 'additionalProperties': False}},
    {'name': 'list_files', 'description': 'List eligible filtered snapshot paths, not assessment.',
     'inputSchema': {'type': 'object', 'properties': {}, 'additionalProperties': False}},
]


def serve(manifest: Path) -> None:
    data = json.loads(manifest.read_text())
    reader = SafeReader(Path(data['root']), data['files'], max_output_bytes=data['max_output_bytes'])
    while True:
        raw = sys.stdin.buffer.readline(65537)
        if not raw:
            return
        if len(raw) > 65536:
            return
        request: dict[str, Any] = {}
        try:
            request = json.loads(raw)
            if 'id' not in request:
                continue
            method = request.get('method')
            if method == 'initialize':
                result: dict[str, Any] = {'protocolVersion': '2024-11-05',
                    'capabilities': {'tools': {}},
                    'serverInfo': {'name': 'repo-audit-reader', 'version': '1'}}
            elif method == 'tools/list':
                result = {'tools': TOOLS}
            elif method == 'ping':
                result = {}
            elif method == 'tools/call':
                params = request['params']
                value = reader.call(params['name'], params.get('arguments', {}))
                result = {'content': [{'type': 'text', 'text': json.dumps(value)}], 'isError': False}
            else:
                raise ValueError('Unsupported read-only protocol method')
            response = {'jsonrpc': '2.0', 'id': request['id'], 'result': result}
        except (ValueError, KeyError, TypeError) as exc:
            response = {'jsonrpc': '2.0', 'id': request.get('id'),
                        'error': {'code': -32602, 'message': str(exc)}}
        sys.stdout.write(json.dumps(response) + '\n')
        sys.stdout.flush()


if __name__ == '__main__':
    serve(Path(sys.argv[1]))
