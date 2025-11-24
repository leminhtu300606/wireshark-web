"""
protocol_decoder.py
Module giải mã các giao thức tầng ứng dụng (FTP, SMTP, POP3, IMAP, HTTP)
"""


class ProtocolDecoder:
    """Giải mã các giao thức tầng Application (Layer 7)"""
    
    @staticmethod
    def decode_ftp(data):
        """Decode FTP commands/responses"""
        try:
            text = data.decode('utf-8', errors='ignore').strip()
            lines = text.split('\r\n')
            
            ftp_commands = [
                'USER', 'PASS', 'LIST', 'RETR', 'STOR', 'PWD', 'CWD', 'QUIT',
                'PORT', 'PASV', 'TYPE', 'ABOR', 'DELE', 'RMD', 'MKD', 'RNFR',
                'RNTO', 'SYST', 'STAT', 'HELP', 'NOOP', 'FEAT', 'OPTS', 'SIZE',
                'MDTM', 'REST', 'APPE', 'ALLO'
            ]
            
            result = {'type': 'unknown', 'raw': text[:200]}
            
            for line in lines:
                if not line:
                    continue
                
                # Check if it's a command
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
                        
                        return result
                
                # Check if it's a response (starts with 3-digit code)
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
    
    @staticmethod
    def decode_smtp(data):
        """Decode SMTP commands/responses"""
        try:
            text = data.decode('utf-8', errors='ignore').strip()
            lines = text.split('\r\n')
            
            smtp_commands = [
                'HELO', 'EHLO', 'MAIL FROM', 'RCPT TO', 'DATA', 'QUIT',
                'AUTH', 'STARTTLS', 'RSET', 'VRFY', 'EXPN', 'HELP', 'NOOP'
            ]
            
            result = {'type': 'unknown', 'raw': text[:200]}
            
            for line in lines:
                if not line:
                    continue
                
                # Check commands
                for cmd in smtp_commands:
                    if line.upper().startswith(cmd):
                        result['type'] = 'command'
                        result['command'] = cmd
                        result['full'] = line[:150]
                        
                        if 'MAIL FROM' in cmd or 'RCPT TO' in cmd:
                            if '<' in line and '>' in line:
                                email_start = line.index('<') + 1
                                email_end = line.index('>')
                                result['email'] = line[email_start:email_end]
                        elif cmd in ['HELO', 'EHLO']:
                            result['domain'] = line.split()[1] if len(line.split()) > 1 else ''
                        
                        return result
                
                # Check response codes
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
    
    @staticmethod
    def decode_pop3(data):
        """Decode POP3 commands/responses"""
        try:
            text = data.decode('utf-8', errors='ignore').strip()
            lines = text.split('\r\n')
            
            pop3_commands = [
                'USER', 'PASS', 'STAT', 'LIST', 'RETR', 'DELE', 'NOOP',
                'RSET', 'QUIT', 'TOP', 'UIDL', 'APOP', 'AUTH', 'CAPA'
            ]
            
            result = {'type': 'unknown', 'raw': text[:200]}
            
            for line in lines:
                if not line:
                    continue
                
                # Check commands
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
                
                # Check responses (+OK, -ERR)
                if line.startswith('+OK') or line.startswith('-ERR'):
                    result['type'] = 'response'
                    result['status'] = line[:3]
                    result['message'] = line[4:150] if len(line) > 4 else ''
                    result['success'] = line.startswith('+OK')
                    
                    return result
            
            return result if result['type'] != 'unknown' else None
        except:
            return None
    
    @staticmethod
    def decode_imap(data):
        """Decode IMAP commands/responses"""
        try:
            text = data.decode('utf-8', errors='ignore').strip()
            lines = text.split('\r\n')
            
            imap_commands = [
                'LOGIN', 'SELECT', 'EXAMINE', 'CREATE', 'DELETE', 'RENAME',
                'SUBSCRIBE', 'UNSUBSCRIBE', 'LIST', 'LSUB', 'STATUS', 'APPEND',
                'CHECK', 'CLOSE', 'EXPUNGE', 'SEARCH', 'FETCH', 'STORE', 'COPY',
                'UID', 'LOGOUT', 'CAPABILITY', 'NOOP', 'IDLE'
            ]
            
            result = {'type': 'unknown', 'raw': text[:200]}
            
            for line in lines:
                if not line:
                    continue
                
                # IMAP commands have format: tag COMMAND arguments
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
                        elif command == 'SELECT' and len(parts) >= 3:
                            result['mailbox'] = parts[2]
                        
                        return result
                
                # Check untagged responses
                if line.startswith('* ') or line.startswith('+ '):
                    result['type'] = 'response'
                    result['untagged'] = True
                    result['message'] = line[2:150]
                    return result
                
                # Tagged response
                if len(parts) >= 2 and parts[1] in ['OK', 'NO', 'BAD']:
                    result['type'] = 'response'
                    result['tag'] = parts[0]
                    result['status'] = parts[1]
                    result['message'] = ' '.join(parts[2:])[:150]
                    return result
            
            return result if result['type'] != 'unknown' else None
        except:
            return None