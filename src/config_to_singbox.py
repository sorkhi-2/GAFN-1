import json
import base64
import uuid
import time
import socket
import requests
import urllib.parse
from typing import Dict, Optional, Tuple, List, Any, Union
from urllib.parse import urlparse, parse_qs

class ConfigToSingbox:
    def __init__(self, input_file='configs/proxy_configs.txt', output_file='configs/singbox_configs.json'):
        self.input_file = input_file
        self.output_file = output_file
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.location_cache = {}
        
    def get_location_from_ip_api(self, ip: str) -> Tuple[str, str]:
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', headers=self.headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success' and data.get('countryCode'):
                    return data['countryCode'].lower(), data['country']
        except Exception:
            pass
        return '', ''

    def get_location_from_ipapi_co(self, ip: str) -> Tuple[str, str]:
        try:
            response = requests.get(f'https://ipapi.co/{ip}/json/', headers=self.headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('country_code') and data.get('country_name'):
                    return data['country_code'].lower(), data['country_name']
        except Exception:
            pass
        return '', ''

    def get_location_from_ipwhois(self, ip: str) -> Tuple[str, str]:
        try:
            response = requests.get(f'https://ipwhois.app/json/{ip}', headers=self.headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('country_code') and data.get('country'):
                    return data['country_code'].lower(), data['country']
        except Exception:
            pass
        return '', ''

    def get_location_from_ipdata(self, ip: str) -> Tuple[str, str]:
        try:
            response = requests.get(f'https://api.ipdata.co/{ip}?api-key=test', headers=self.headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('country_code') and data.get('country_name'):
                    return data['country_code'].lower(), data['country_name']
        except Exception:
            pass
        return '', ''

    def get_location_from_abstractapi(self, ip: str) -> Tuple[str, str]:
        try:
            response = requests.get(f'https://ipgeolocation.abstractapi.com/v1/?api_key=test&ip_address={ip}', 
                                  headers=self.headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('country_code') and data.get('country'):
                    return data['country_code'].lower(), data['country']
        except Exception:
            pass
        return '', ''

    def get_location(self, address: str) -> tuple:
        if not address:
            return "🏳️", "Unknown"
        if address in self.location_cache:
            return self.location_cache[address]
        try:
            ip = socket.gethostbyname(address)
            apis = [
                self.get_location_from_ip_api,
                self.get_location_from_ipapi_co,
                self.get_location_from_ipwhois,
                self.get_location_from_ipdata,
                self.get_location_from_abstractapi
            ]
            for api_func in apis:
                country_code, country = api_func(ip)
                if country_code and country and len(country_code) == 2:
                    flag = ''.join(chr(ord('🇦') + ord(c.upper()) - ord('A')) for c in country_code)
                    self.location_cache[address] = (flag, country)
                    time.sleep(0.5)
                    return flag, country
                time.sleep(0.5)
        except Exception:
            pass
        self.location_cache[address] = ("🏳️", "Unknown")
        return "🏳️", "Unknown"

    def decode_base64(self, data: str) -> str:
        try:
            padding_needed = len(data) % 4
            if padding_needed > 0:
                data += '=' * (4 - padding_needed)
            return base64.b64decode(data).decode('utf-8')
        except Exception:
            try:
                return base64.b64decode(data + '==').decode('utf-8')
            except Exception:
                return ""

    def parse_vmess(self, config: str) -> Optional[Dict]:
        try:
            encoded = config.replace('vmess://', '')
            if encoded.startswith('{'):
                try:
                    return json.loads(encoded)
                except:
                    pass
            decoded = self.decode_base64(encoded)
            if decoded:
                try:
                    return json.loads(decoded)
                except:
                    pass
            return None
        except Exception:
            return None

    def parse_vless(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme != 'vless':
                return None
            username = url.username
            hostname = url.hostname
            port = url.port or 443
            params = parse_qs(url.query)
            return {
                'type': 'vless',
                'uuid': username,
                'address': hostname,
                'port': int(port),
                'flow': params.get('flow', [''])[0],
                'security': params.get('security', [''])[0],
                'sni': params.get('sni', [hostname])[0],
                'type': params.get('type', ['tcp'])[0],
                'path': params.get('path', [''])[0],
                'host': params.get('host', [''])[0],
                'alpn': params.get('alpn', [''])[0],
                'fp': params.get('fp', [''])[0],
                'pbk': params.get('pbk', [''])[0]
            }
        except Exception:
            return None

    def parse_trojan(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme != 'trojan':
                return None
            password = url.username
            hostname = url.hostname
            port = url.port or 443
            params = parse_qs(url.query)
            return {
                'type': 'trojan',
                'password': password,
                'address': hostname,
                'port': int(port),
                'sni': params.get('sni', [hostname])[0],
                'alpn': params.get('alpn', [''])[0],
                'type': params.get('type', ['tcp'])[0],
                'path': params.get('path', [''])[0]
            }
        except Exception:
            return None

    def parse_hysteria2(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme not in ['hysteria2', 'hy2']:
                return None
            username = url.username or ''
            hostname = url.hostname
            port = url.port
            if not port:
                return None
            params = parse_qs(url.query)
            return {
                'type': 'hysteria2',
                'address': hostname,
                'port': int(port),
                'password': username or params.get('password', [''])[0],
                'sni': params.get('sni', [hostname])[0]
            }
        except Exception:
            return None

    def parse_shadowsocks(self, config: str) -> Optional[Dict]:
        try:
            parts = config.replace('ss://', '').split('@')
            if len(parts) != 2:
                return None
            method_pass = self.decode_base64(parts[0])
            method, password = method_pass.split(':')
            server_parts = parts[1].split('#')[0]
            host, port = server_parts.split(':')
            return {
                'type': 'shadowsocks',
                'method': method,
                'password': password,
                'address': host,
                'port': int(port)
            }
        except Exception:
            return None

    def parse_tuic(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme != 'tuic':
                return None
            netloc = url.netloc
            if '@' not in netloc:
                return None
            user_pass, server = netloc.split('@', 1)
            if ':' not in user_pass or ':' not in server:
                return None
            uuid_val, password = user_pass.split(':', 1)
            address, port_str = server.split(':', 1)
            port = int(port_str) if port_str else 443
            params = parse_qs(url.query)
            return {
                'type': 'tuic',
                'uuid': uuid_val,
                'password': password,
                'address': address,
                'port': port,
                'sni': params.get('sni', [address])[0],
                'alpn': params.get('alpn', [''])[0],
                'congestion_control': params.get('congestion_control', [''])[0],
                'udp_relay_mode': params.get('udp_relay_mode', [''])[0]
            }
        except Exception:
            return None

    def parse_socks(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme not in ['socks', 'socks5', 'socks4', 'socks4a']:
                return None
            netloc = url.netloc
            username = ''
            password = ''
            if '@' in netloc:
                auth, server = netloc.split('@', 1)
                if ':' in auth:
                    username, password = auth.split(':', 1)
            else:
                server = netloc
            if ':' not in server:
                return None
            address, port_str = server.split(':', 1)
            port = int(port_str) if port_str else 1080
            return {
                'type': 'socks',
                'address': address,
                'port': port,
                'username': username,
                'password': password
            }
        except Exception:
            return None

    def parse_http(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme not in ['http', 'https']:
                return None
            netloc = url.netloc
            username = ''
            password = ''
            if '@' in netloc:
                auth, server = netloc.split('@', 1)
                if ':' in auth:
                    username, password = auth.split(':', 1)
            else:
                server = netloc
            if ':' not in server:
                port = 80 if url.scheme == 'http' else 443
                address = server
            else:
                address, port_str = server.split(':', 1)
                port = int(port_str) if port_str else (80 if url.scheme == 'http' else 443)
            return {
                'type': 'http',
                'address': address,
                'port': port,
                'username': username,
                'password': password,
                'tls': url.scheme == 'https'
            }
        except Exception:
            return None

    def parse_wireguard(self, config: str) -> Optional[Dict]:
        try:
            url = urlparse(config)
            if url.scheme not in ['wireguard', 'wg']:
                return None
            query_params = dict(param.split('=', 1) for param in url.query.split('&') if '=' in param) if url.query else {}
            if not query_params.get('private-key') or not url.netloc:
                return None
            parts = url.netloc.split(':')
            address = parts[0]
            port = int(parts[1]) if len(parts) > 1 else 51820
            return {
                'type': 'wireguard',
                'address': address,
                'port': port,
                'private_key': query_params.get('private-key', ''),
                'public_key': query_params.get('public-key', ''),
                'pre_shared_key': query_params.get('pre-shared-key', ''),
                'local_address': query_params.get('local-address', '').split(','),
                'mtu': int(query_params.get('mtu', 1420))
            }
        except Exception:
            return None

    def convert_to_singbox(self, parsed_config: Dict) -> Optional[Dict]:
        try:
            config_type = parsed_config['type']
            address = parsed_config['address']
            port = parsed_config['port']
            flag, country = self.get_location(address)
            tag = f"{flag} {config_type}-{str(uuid.uuid4())[:8]} ({country})"
            if config_type == 'vmess':
                transport = {}
                if parsed_config.get('net') in ['ws', 'h2']:
                    if parsed_config.get('path'):
                        transport["path"] = parsed_config['path']
                    if parsed_config.get('host'):
                        transport["headers"] = {"Host": parsed_config['host']}
                    transport["type"] = parsed_config['net']
                return {
                    "type": "vmess",
                    "tag": tag,
                    "server": address,
                    "server_port": port,
                    "uuid": parsed_config['id'],
                    "security": parsed_config.get('scy', 'auto'),
                    "alter_id": int(parsed_config.get('aid', 0)),
                    "transport": transport if transport else None,
                    "tls": {
                        "enabled": parsed_config.get('tls') == 'tls',
                        "insecure": True,
                        "server_name": parsed_config.get('sni', address)
                    } if parsed_config.get('tls') == 'tls' else None
                }
            elif config_type == 'vless':
                transport = {}
                if parsed_config['type'] == 'ws':
                    if parsed_config.get('path'):
                        transport["path"] = parsed_config['path']
                    if parsed_config.get('host'):
                        transport["headers"] = {"Host": parsed_config['host']}
                    transport["type"] = "ws"
                tls = {
                    "enabled": True,
                    "server_name": parsed_config['sni'],
                    "insecure": True
                }
                if parsed_config['security'] == 'reality':
                    tls["reality"] = {
                        "enabled": True,
                        "public_key": parsed_config['pbk'],
                        "short_id": parsed_config.get('sid', '')
                    }
                return {
                    "type": "vless",
                    "tag": tag,
                    "server": address,
                    "server_port": port,
                    "uuid": parsed_config['uuid'],
                    "flow": parsed_config['flow'],
                    "tls": tls,
                    "transport": transport if transport else None
                }
            elif config_type == 'trojan':
                transport = {}
                if parsed_config['type'] != 'tcp' and parsed_config.get('path'):
                    transport["path"] = parsed_config['path']
                    transport["type"] = parsed_config['type']
                return {
                    "type": "trojan",
                    "tag": tag,
                    "server": address,
                    "server_port": port,
                    "password": parsed_config['password'],
                    "tls": {
                        "enabled": True,
                        "server_name": parsed_config['sni'],
                        "alpn": parsed_config['alpn'].split(',') if parsed_config['alpn'] else [],
                        "insecure": True
                    },
                    "transport": transport if transport else None
                }
            elif config_type == 'hysteria2':
                return {
                    "type": "hysteria2",
                    "tag": tag,
                    "server": address,
                    "server_port": port,
                    "password": parsed_config['password'],
                    "tls": {
                        "enabled": True,
                        "insecure": True,
                        "server_name": parsed_config['sni']
                    }
                }
            elif config_type == 'shadowsocks':
                return {
                    "type": "shadowsocks",
                    "tag": tag,
                    "server": address,
                    "server_port": port,
                    "method": parsed_config['method'],
                    "password": parsed_config['password']
                }
            elif config_type == 'tuic':
                return {
                    "type": "tuic",
                    "tag": tag,
                    "server": address,
                    "server_port": port,
                    "uuid": parsed_config['uuid'],
                    "password": parsed_config['password'],
                    "congestion_control": parsed_config['congestion_control'] or "cubic",
                    "udp_relay_mode": parsed_config['udp_relay_mode'] or "native",
                    "tls": {
                        "enabled": True,
                        "server_name": parsed_config['sni'],
                        "alpn": parsed_config['alpn'].split(',') if parsed_config['alpn'] else ["h3"]
                    }
                }
            elif config_type == 'socks':
                return {
                    "type": "socks",
                    "tag": tag,
                    "server": address,
                    "server_port": port,
                    "username": parsed_config['username'],
                    "password": parsed_config['password']
                }
            elif config_type == 'http':
                return {
                    "type": "http",
                    "tag": tag,
                    "server": address,
                    "server_port": port,
                    "username": parsed_config['username'],
                    "password": parsed_config['password'],
                    "tls": {
                        "enabled": parsed_config['tls'],
                        "insecure": True
                    } if parsed_config['tls'] else None
                }
            elif config_type == 'wireguard':
                return {
                    "type": "wireguard",
                    "tag": tag,
                    "server": address,
                    "server_port": port,
                    "private_key": parsed_config['private_key'],
                    "public_key": parsed_config['public_key'],
                    "pre_shared_key": parsed_config['pre_shared_key'],
                    "local_address": parsed_config['local_address'],
                    "mtu": parsed_config['mtu']
                }
            return None
        except Exception:
            return None

    def process_configs(self):
        try:
            with open(self.input_file, 'r') as f:
                configs = f.read().strip().split('\n')
            outbounds = []
            valid_tags = []
            for config in configs:
                config = config.strip()
                if not config or config.startswith('#'):
                    continue
                parsed = None
                if config.startswith('vmess://'):
                    parsed = self.parse_vmess(config)
                elif config.startswith('vless://'):
                    parsed = self.parse_vless(config)
                elif config.startswith('trojan://'):
                    parsed = self.parse_trojan(config)
                elif config.startswith('hysteria2://') or config.startswith('hy2://'):
                    parsed = self.parse_hysteria2(config)
                elif config.startswith('ss://'):
                    parsed = self.parse_shadowsocks(config)
                elif config.startswith('tuic://'):
                    parsed = self.parse_tuic(config)
                elif config.startswith('socks'):
                    parsed = self.parse_socks(config)
                elif config.startswith('http'):
                    parsed = self.parse_http(config)
                elif config.startswith('wireguard://') or config.startswith('wg://'):
                    parsed = self.parse_wireguard(config)
                if parsed:
                    converted = self.convert_to_singbox(parsed)
                    if converted:
                        outbounds.append(converted)
                        valid_tags.append(converted['tag'])
            if not outbounds:
                return
            dns_config = {
                "dns": {
                    "final": "local-dns",
                    "rules": [
                        {"clash_mode": "Global", "server": "proxy-dns", "source_ip_cidr": ["172.19.0.0/30"]},
                        {"server": "proxy-dns", "source_ip_cidr": ["172.19.0.0/30"]},
                        {"clash_mode": "Direct", "server": "direct-dns"}
                    ],
                    "servers": [
                        {"address": "tls://208.67.222.123", "address_resolver": "local-dns", "detour": "proxy", "tag": "proxy-dns"},
                        {"address": "local", "detour": "direct", "tag": "local-dns"},
                        {"address": "rcode://success", "tag": "block"},
                        {"address": "local", "detour": "direct", "tag": "direct-dns"}
                    ],
                    "strategy": "prefer_ipv4"
                }
            }
            inbounds_config = [
                {"address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"], "auto_route": True, "endpoint_independent_nat": False, "mtu": 9000, "platform": {"http_proxy": {"enabled": True, "server": "127.0.0.1", "server_port": 2080}}, "sniff": True, "stack": "system", "strict_route": False, "type": "tun"},
                {"listen": "127.0.0.1", "listen_port": 2080, "sniff": True, "type": "mixed", "users": []}
            ]
            outbounds_config = [
                {"tag": "proxy", "type": "selector", "outbounds": ["auto"] + valid_tags + ["direct"]},
                {"tag": "auto", "type": "urltest", "outbounds": valid_tags, "url": "http://www.gstatic.com/generate_204", "interval": "10m", "tolerance": 50},
                {"tag": "direct", "type": "direct"}
            ] + outbounds
            route_config = {
                "auto_detect_interface": True,
                "final": "proxy",
                "rules": [
                    {"clash_mode": "Direct", "outbound": "direct"},
                    {"clash_mode": "Global", "outbound": "proxy"},
                    {"protocol": "dns", "action": "hijack-dns"}
                ]
            }
            singbox_config = {**dns_config, "inbounds": inbounds_config, "outbounds": outbounds_config, "route": route_config}
            with open(self.output_file, 'w') as f:
                json.dump(singbox_config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error processing configs: {str(e)}")

def main():
    converter = ConfigToSingbox()
    converter.process_configs()

if __name__ == '__main__':
    main()