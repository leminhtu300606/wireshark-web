"""
Application protocol decoders (FTP, SMTP, POP3, IMAP, DNS, HTTP)
"""
import struct
import re

def decode_dns(data):
    """Decode DNS packet"""
    if len(data) < 12:
        return None
    
    try:
        transaction_id = struct.unpack('!H', data[0:2])[0]
        flags = struct.unpack('!H', data[2:4])[0]
        questions = struct.unpack('!H', data[4:6])[0]
        answers = struct.unpack('!H', data[6:8])[0]
        
        is_response = (flags & 0x8000) >> 15
        opcode = (flags & 0x7800) >> 11
        
        query_name = []
        pos = 12
        while pos < len(data) and data[pos] != 0:
            length = data[pos]
            if length == 0:
                break
            pos += 1
            if pos + length <= len(data):
                query_name.append(data[pos:pos+length].decode('utf-8', errors='ignore'))
                pos += length
            else:
                break
        
        domain = '.'.join(query_name) if query_name else 'Unknown'
        
        return {
            'transaction_id': transaction_id,
            'is_response': is_response,
            'opcode': opcode,
            'questions': questions,
            'answers': answers,
            'domain': domain
        }
    except:
        return None

def decode_http(data):
    """Decode HTTP requests/responses"""
    try:
        text = data.decode('utf-8', errors='ignore').strip()
        lines = text.split('\r\n')
        
        if not lines:
            return None
        
        first_line = lines[0]
        result = {'type': 'unknown', 'raw': text[:300]}
        
        http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT']
        for method in http_methods:
            if first_line.startswith(method):
                parts = first_line.split()
                if len(parts) >= 3:
                    result['type'] = 'request'
                    result['method'] = parts[0]
                    result['uri'] = parts[1]
                    result['version'] = parts[2]
                    
                    headers = {}
                    for line in lines[1:]:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            headers[key.strip()] = value.strip()
                    
                    result['headers'] = headers
                    if 'Host' in headers:
                        result['host'] = headers['Host']
                    if 'User-Agent' in headers:
                        result['user_agent'] = headers['User-Agent'][:100]
                    
                    return result
        
        if first_line.startswith('HTTP/'):
            parts = first_line.split(None, 2)
            if len(parts) >= 2:
                result['type'] = 'response'
                result['version'] = parts[0]
                result['status_code'] = parts[1]
                result['status_message'] = parts[2] if len(parts) > 2 else ''
                
                headers = {}
                for line in lines[1:]:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()
                
                result['headers'] = headers
                if 'Content-Type' in headers:
                    result['content_type'] = headers['Content-Type']
                if 'Content-Length' in headers:
                    result['content_length'] = headers['Content-Length']
                
                return result
        
        return None
    except:
        return None

def decode_ftp(data):
    """Decode FTP commands/responses"""
    try:
        text = data.decode('utf-8', errors='ignore').strip()
        lines = text.split('\r\n')
        
        ftp_commands = ['USER', 'PASS', 'LIST', 'RETR', 'STOR', 'PWD', 'CWD', 'QUIT', 
                       'PORT', 'PASV', 'TYPE', 'ABOR', 'DELE', 'RMD', 'MKD', 'RNFR', 
                       'RNTO', 'SYST', 'STAT', 'HELP', 'NOOP', 'FEAT', 'OPTS', 'SIZE',
                       'MDTM', 'REST', 'APPE', 'ALLO', 'EPRT', 'EPSV']
        
        result = {'type': 'unknown', 'raw': text[:200]}
        
        for line in lines:
            if not line:
                continue
            
            for cmd in ftp_commands:
                if line.upper().startswith(cmd):
                    result['type'] = 'command'
                    result['command'] = cmd
                    result['full'] = line[:150]
                    
                    if cmd == 'USER':
                        result['username'] = line[5:].strip()
                    elif cmd in ['RETR', 'STOR']:
                        result['filename'] = line[5:].strip()
                    elif cmd == 'CWD':
                        result['directory'] = line[4:].strip()
                    elif cmd == 'PORT':
                        result['port_info'] = line[5:].strip()
                    
                    return result
            
            if len(line) >= 3 and line[:3].isdigit():
                result['type'] = 'response'
                result['code'] = line[:3]
                result['message'] = line[4:150] if len(line) > 4 else ''
                
                code_int = int(result['code'])
                if code_int < 200:
                    result['status'] = 'preliminary'
                elif code_int < 300:
                    result['status'] = 'success'
                elif code_int < 400:
                    result['status'] = 'intermediate'
                elif code_int < 500:
                    result['status'] = 'transient_error'
                else:
                    result['status'] = 'permanent_error'
                
                return result
        
        return result if result['type'] != 'unknown' else None
    except:
        return None

def decode_smtp(data):
    """Decode SMTP commands/responses"""
    try:
        text = data.decode('utf-8', errors='ignore').strip()
        lines = text.split('\r\n')
        
        smtp_commands = ['HELO', 'EHLO', 'MAIL FROM', 'RCPT TO', 'DATA', 'QUIT', 
                       'AUTH', 'STARTTLS', 'RSET', 'VRFY', 'EXPN', 'HELP', 'NOOP']
        
        result = {'type': 'unknown', 'raw': text[:200]}
        
        for line in lines:
            if not line:
                continue
            
            for cmd in smtp_commands:
                if line.upper().startswith(cmd):
                    result['type'] = 'command'
                    result['command'] = cmd
                    result['full'] = line[:150]
                    
                    if 'MAIL FROM' in cmd or 'RCPT TO' in cmd:
                        email_match = re.search(r'<([^>]+)>', line)
                        if email_match:
                            result['email'] = email_match.group(1)
                    elif cmd in ['HELO', 'EHLO']:
                        result['domain'] = line.split()[1] if len(line.split()) > 1 else ''
                    
                    return result
            
            if len(line) >= 3 and line[:3].isdigit():
                result['type'] = 'response'
                result['code'] = line[:3]
                result['message'] = line[4:150] if len(line) > 4 else ''
                
                code_int = int(result['code'])
                if code_int < 300:
                    result['status'] = 'success'
                elif code_int < 400:
                    result['status'] = 'intermediate'
                elif code_int < 500:
                    result['status'] = 'transient_error'
                else:
                    result['status'] = 'permanent_error'
                
                return result
        
        return result if result['type'] != 'unknown' else None
    except:
        return None

def decode_pop3(data):
    """Decode POP3 commands/responses"""
    try:
        text = data.decode('utf-8', errors='ignore').strip()
        lines = text.split('\r\n')
        
        pop3_commands = ['USER', 'PASS', 'STAT', 'LIST', 'RETR', 'DELE', 'NOOP', 
                       'RSET', 'QUIT', 'TOP', 'UIDL', 'APOP', 'AUTH', 'CAPA']
        
        result = {'type': 'unknown', 'raw': text[:200]}
        
        for line in lines:
            if not line:
                continue
            
            for cmd in pop3_commands:
                if line.upper().startswith(cmd):
                    result['type'] = 'command'
                    result['command'] = cmd
                    result['full'] = line[:150]
                    
                    if cmd == 'USER':
                        result['username'] = line[5:].strip()
                    elif cmd in ['RETR', 'DELE', 'TOP']:
                        parts = line.split()
                        if len(parts) > 1:
                            result['message_id'] = parts[1]
                    
                    return result
            
            if line.startswith('+OK') or line.startswith('-ERR'):
                result['type'] = 'response'
                result['status'] = line[:3]
                result['message'] = line[4:150] if len(line) > 4 else ''
                result['success'] = line.startswith('+OK')
                
                return result
        
        return result if result['type'] != 'unknown' else None
    except:
        return None

def decode_imap(data):
    """Decode IMAP commands/responses"""
    try:
        text = data.decode('utf-8', errors='ignore').strip()
        lines = text.split('\r\n')
        
        imap_commands = ['LOGIN', 'SELECT', 'EXAMINE', 'CREATE', 'DELETE', 'RENAME',
                       'SUBSCRIBE', 'UNSUBSCRIBE', 'LIST', 'LSUB', 'STATUS', 'APPEND',
                       'CHECK', 'CLOSE', 'EXPUNGE', 'SEARCH', 'FETCH', 'STORE', 'COPY',
                       'UID', 'LOGOUT', 'CAPABILITY', 'NOOP', 'IDLE', 'STARTTLS']
        
        result = {'type': 'unknown', 'raw': text[:200]}
        
        for line in lines:
            if not line:
                continue
            
            parts = line.split()
            if len(parts) >= 2:
                command = parts[1].upper()
                
                if command in imap_commands:
                    result['type'] = 'command'
                    result['tag'] = parts[0]
                    result['command'] = command
                    result['full'] = line[:150]
                    
                    if command == 'LOGIN' and len(parts) >= 4:
                        result['username'] = parts[2]
                    elif command in ['SELECT', 'EXAMINE'] and len(parts) >= 3:
                        result['mailbox'] = parts[2]
                    
                    return result
            
            if line.startswith('* ') or line.startswith('+ '):
                result['type'] = 'response'
                result['untagged'] = True
                result['message'] = line[2:150]
                return result
            
            if len(parts) >= 2 and parts[1] in ['OK', 'NO', 'BAD']:
                result['type'] = 'response'
                result['tag'] = parts[0]
                result['status'] = parts[1]
                result['message'] = ' '.join(parts[2:])[:150]
                return result
        
        return result if result['type'] != 'unknown' else None
    except:
        return None