# #!/usr/bin/env python3
# # agent/agent.py — COMPLETE FINAL VERSION (mTLS + JWT + HMAC + DGA + Exfil)
# import ssl, json, time, logging, threading, argparse, sys, hashlib, hmac
# from pathlib import Path

# try:
#     import websocket
#     WEBSOCKET_AVAILABLE = True
# except ImportError:
#     WEBSOCKET_AVAILABLE = False

# try:
#     import jwt as pyjwt
#     JWT_AVAILABLE = True
# except ImportError:
#     JWT_AVAILABLE = False

# try:
#     from modules.dga_module   import DGARunner
#     from modules.exfil_module import TransferEngine
#     MODULES_AVAILABLE = True
# except ImportError:
#     MODULES_AVAILABLE = False

# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
#     datefmt='%H:%M:%S',
# )
# logger = logging.getLogger('MIAT-Agent')

# CONFIG_FILE = 'agent_config.json'
# CERT_DIR    = Path(__file__).parent / 'certs'
# CA_CERT     = CERT_DIR / 'ca.crt'
# AGENT_CERT  = CERT_DIR / 'agent.crt'
# AGENT_KEY   = CERT_DIR / 'agent.key'
# TOKEN_REFRESH_BUFFER_SECS = 60


# # ── SSL Context ───────────────────────────────────────────────────────────────

# def build_ssl_context() -> ssl.SSLContext:
#     for f, name in [(CA_CERT,'CA cert'),(AGENT_CERT,'Agent cert'),(AGENT_KEY,'Agent key')]:
#         if not f.exists():
#             raise FileNotFoundError(f"{name} not found: {f}")
#     ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
#     ctx.load_verify_locations(cafile=str(CA_CERT))
#     ctx.load_cert_chain(certfile=str(AGENT_CERT), keyfile=str(AGENT_KEY))
#     ctx.check_hostname = True
#     ctx.verify_mode    = ssl.CERT_REQUIRED
#     return ctx


# # ── Secure HTTP Client ────────────────────────────────────────────────────────

# class SecureHTTPClient:
#     def __init__(self, server_url: str, config: dict):
#         self.server_url     = server_url.rstrip('/')
#         self.config         = config
#         self.ssl_ctx        = build_ssl_context()
#         self._access_token  = None
#         self._refresh_token = None
#         self._token_exp     = 0.0
#         self._token_lock    = threading.Lock()

#     def authenticate(self):
#         logger.info("Obtaining JWT tokens...")
#         data = self._raw_post('/api/agent/token/', {
#             'agent_id':         self.config['agent_id'],
#             'registration_key': self.config['registration_key'],
#         })
#         self._access_token  = data['access_token']
#         self._refresh_token = data['refresh_token']
#         self._token_exp     = self._decode_exp(self._access_token)
#         logger.info(f"JWT obtained — expires in {int(self._token_exp - time.time())}s")

#     def _refresh_jwt(self):
#         data = self._raw_post('/api/agent/token/refresh/',
#                               {'refresh_token': self._refresh_token})
#         self._access_token = data['access_token']
#         self._token_exp    = self._decode_exp(self._access_token)
#         logger.info("JWT refreshed")

#     def _ensure_token(self):
#         with self._token_lock:
#             if not self._access_token:
#                 self.authenticate(); return
#             if self._token_exp - time.time() < TOKEN_REFRESH_BUFFER_SECS:
#                 try:    self._refresh_jwt()
#                 except: self.authenticate()

#     @staticmethod
#     def _decode_exp(token: str) -> float:
#         if not JWT_AVAILABLE:
#             return time.time() + 840
#         try:
#             p = pyjwt.decode(token, options={"verify_signature": False})
#             return float(p.get('exp', time.time() + 840))
#         except Exception:
#             return time.time() + 840

#     def _sign(self, body: str) -> tuple:
#         ts  = str(time.time())
#         msg = f"{ts}:{body}".encode('utf-8')
#         sig = hmac.new(self.config['secret_key'].encode(), msg, hashlib.sha256).hexdigest()
#         return ts, sig

#     def _raw_post(self, path: str, data: dict) -> dict:
#         import urllib.request
#         body = json.dumps(data).encode('utf-8')
#         req  = urllib.request.Request(
#             f"{self.server_url}{path}", data=body,
#             headers={'Content-Type': 'application/json'}, method='POST',
#         )
#         with urllib.request.urlopen(req, context=self.ssl_ctx, timeout=10) as r:
#             return json.loads(r.read())

#     def post(self, path: str, data: dict = None) -> dict:
#         import urllib.request, urllib.error
#         self._ensure_token()
#         body    = json.dumps(data or {})
#         ts, sig = self._sign(body)
#         req = urllib.request.Request(
#             f"{self.server_url}{path}",
#             data    = body.encode('utf-8'),
#             headers = {
#                 'Content-Type':  'application/json',
#                 'Authorization': f'Bearer {self._access_token}',
#                 'X-Timestamp':   ts,
#                 'X-Signature':   sig,
#             },
#             method='POST',
#         )
#         try:
#             with urllib.request.urlopen(req, context=self.ssl_ctx, timeout=15) as r:
#                 return json.loads(r.read())
#         except urllib.error.HTTPError as exc:
#             raw = exc.read().decode()
#             try:    detail = json.loads(raw).get('detail', raw)
#             except: detail = raw
#             raise RuntimeError(f"HTTP {exc.code}: {detail}")
#         except urllib.error.URLError as exc:
#             raise RuntimeError(f"Cannot reach server: {exc.reason}")

#     def get(self, path: str) -> dict:
#         import urllib.request
#         self._ensure_token()
#         ts, sig = self._sign('')
#         req = urllib.request.Request(
#             f"{self.server_url}{path}",
#             headers={
#                 'Authorization': f'Bearer {self._access_token}',
#                 'X-Timestamp': ts, 'X-Signature': sig,
#             },
#             method='GET',
#         )
#         with urllib.request.urlopen(req, context=self.ssl_ctx, timeout=15) as r:
#             return json.loads(r.read())


# # ── WebSocket Thread ──────────────────────────────────────────────────────────

# class WebSocketThread(threading.Thread):
#     def __init__(self, server_url, agent_id, auth_token, ssl_ctx, agent_ref):
#         super().__init__(daemon=True, name='ws-thread')
#         ws_base      = server_url.replace('https://','wss://').replace('http://','ws://')
#         self.ws_url  = f"{ws_base}/ws/agent/{agent_id}/?token={auth_token}"
#         self.ssl_ctx = ssl_ctx
#         self.agent_ref = agent_ref
#         self.ws        = None
#         self.running   = True
#         self.connected = False

#     def run(self):
#         while self.running:
#             try:
#                 self.ws = websocket.WebSocketApp(
#                     self.ws_url,
#                     on_open    = self._on_open,
#                     on_message = self._on_message,
#                     on_error   = self._on_error,
#                     on_close   = self._on_close,
#                 )
#                 self.ws.run_forever(
#                     sslopt={'context': self.ssl_ctx},
#                     ping_interval=30, ping_timeout=10,
#                 )
#             except Exception as exc:
#                 logger.error(f"WS error: {exc}")
#             if self.running:
#                 logger.info("WS disconnected — reconnecting in 5s...")
#                 time.sleep(5)

#     def stop(self):
#         self.running = False
#         if self.ws: self.ws.close()

#     def _on_open(self, ws):
#         self.connected = True
#         logger.info("WebSocket connected")
#         self.send({'type': 'heartbeat', 'agent_id': self.agent_ref.agent_id})

#     def _on_message(self, ws, message):
#         try:
#             data = json.loads(message)
#         except json.JSONDecodeError:
#             return
#         t = data.get('type', '')
#         if   t == 'connected':    logger.info(f"Server: {data.get('message')}")
#         elif t == 'heartbeat_ack': logger.debug("Heartbeat ACK")
#         elif t == 'command':
#             threading.Thread(target=self._handle_command,
#                              args=(data,), daemon=True).start()
#         elif t == 'error':        logger.error(f"Server: {data.get('message')}")

#     def _on_error(self, ws, error):
#         self.connected = False
#         logger.error(f"WS error: {error}")

#     def _on_close(self, ws, code, msg):
#         self.connected = False
#         logger.warning(f"WS closed (code={code})")

#     def _handle_command(self, data: dict):
#         cmd  = data.get('command')
#         args = data.get('args', {})
#         logger.info(f"Command: {cmd}")
#         if cmd == 'run_nmap':
#             threading.Thread(target=self.agent_ref.submit_scan,
#                 args=(args.get('target','127.0.0.1'), args.get('profile','default')),
#                 daemon=True).start()
#         elif cmd == 'run_dga':
#             threading.Thread(target=self.agent_ref.run_dga,
#                 args=(args,), daemon=True).start()
#         elif cmd == 'run_exfil':
#             threading.Thread(target=self.agent_ref.run_exfil,
#                 args=(args,), daemon=True).start()
#         elif cmd == 'stop':
#             logger.info("Stop command received")
#         else:
#             logger.warning(f"Unknown command: {cmd}")

#     def send(self, data: dict):
#         if self.ws and self.connected:
#             try:    self.ws.send(json.dumps(data))
#             except Exception as exc: logger.error(f"WS send failed: {exc}")

#     def send_module_output(self, module: str, output: str):
#         self.send({'type': 'module_output', 'module': module, 'output': output})

#     def send_ids_alert(self, message: str):
#         self.send({'type': 'ids_alert', 'message': message})


# # ── MIAT Agent ────────────────────────────────────────────────────────────────

# class MIATAgent:
#     def __init__(self, config: dict):
#         self.config    = config
#         self.running   = False
#         self.agent_id  = config['agent_id']
#         self.http      = SecureHTTPClient(config['server_url'], config)
#         self.ws_thread = None

#     def start(self):
#         self.running = True
#         logger.info(f"MIAT Agent starting — ID: {self.agent_id}")
#         logger.info(f"Server: {self.config['server_url']}")
#         logger.info("Security: mTLS + JWT + HMAC")

#         self.http.authenticate()

#         if WEBSOCKET_AVAILABLE:
#             self.ws_thread = WebSocketThread(
#                 server_url = self.config['server_url'],
#                 agent_id   = self.agent_id,
#                 auth_token = self.config['auth_token'],
#                 ssl_ctx    = self.http.ssl_ctx,
#                 agent_ref  = self,
#             )
#             self.ws_thread.start()
#         else:
#             logger.warning("WebSocket not available — install websocket-client")

#         logger.info("Agent running. Press Ctrl+C to stop.")
#         try:
#             while self.running:
#                 time.sleep(1)
#         except KeyboardInterrupt:
#             self.stop()

#     def stop(self):
#         self.running = False
#         if self.ws_thread: self.ws_thread.stop()
#         logger.info("Agent stopped.")

#     # ── Nmap scan ─────────────────────────────────────────────────────────────

#     def submit_scan(self, target: str, profile: str = 'default') -> dict:
#         logger.info(f"Submitting scan: {target} ({profile})")
#         try:
#             resp = self.http.post('/api/agent/scan/submit/', {
#                 'target': target, 'scan_profile': profile,
#             })
#             logger.info(f"Scan queued — #{resp.get('scan_id')}")
#             if self.ws_thread and self.ws_thread.connected:
#                 self.ws_thread.send({
#                     'type': 'scan_submitted',
#                     'scan_id': resp.get('scan_id'),
#                     'target': target,
#                 })
#             return resp
#         except RuntimeError as exc:
#             logger.error(f"Scan failed: {exc}")
#             return {}

#     def post_results(self, module, target, findings, summary=''):
#         try:
#             resp = self.http.post('/api/agent/results/', {
#                 'module': module, 'target': target,
#                 'findings': findings, 'summary': summary,
#             })
#             logger.info(f"Results posted: {resp.get('message')}")
#         except RuntimeError as exc:
#             logger.error(f"Failed to post results: {exc}")

#     # ── DGA module ────────────────────────────────────────────────────────────

#     def run_dga(self, config: dict = None) -> dict:
#         if not MODULES_AVAILABLE:
#             logger.error("Modules not available — check agent/modules/")
#             return {}

#         dga_config = {
#             'algorithm':   'date_seed',
#             'count':       50,
#             'rate':        1.0,
#             'seed_secret': 'BARC-MIAT',
#             'tld':         '.com',
#             'dns_server':  None,
#             'randomise':   True,
#             'timeout':     3,
#         }
#         if config:
#             dga_config.update(config)

#         logger.info(
#             f"DGA starting — algorithm={dga_config['algorithm']}, "
#             f"count={dga_config['count']}, rate={dga_config['rate']}/s"
#         )

#         runner  = DGARunner(agent_ref=self, config=dga_config)
#         summary = runner.run()

#         try:
#             self.http.post('/api/agent/dga/results/', {
#                 'algorithm':      dga_config['algorithm'],
#                 'total_queries':  summary.get('total_queries', 0),
#                 'nxdomain':       summary.get('nxdomain', 0),
#                 'resolved':       summary.get('resolved', 0),
#                 'timeout':        summary.get('timeout', 0),
#                 'errors':         summary.get('errors', 0),
#                 'nxdomain_ratio': summary.get('nxdomain_ratio', 0.0),
#                 'avg_entropy':    summary.get('avg_entropy', 0.0),
#                 'max_entropy':    summary.get('max_entropy', 0.0),
#                 'min_entropy':    summary.get('min_entropy', 0.0),
#                 'duration_sec':   summary.get('duration_sec', 0.0),
#                 'rate_per_sec':   dga_config['rate'],
#                 'dns_server':     dga_config.get('dns_server') or 'system',
#                 'domains':        summary.get('domains', []),
#             })
#             logger.info("DGA results posted to server")
#         except RuntimeError as exc:
#             logger.error(f"Failed to post DGA results: {exc}")

#         return summary

#     # ── Exfiltration module ───────────────────────────────────────────────────

#     def run_exfil(self, config: dict = None) -> dict:
#         """
#         Run a data exfiltration simulation.

#         Config keys:
#           technique    : 'dns' | 'http' | 'icmp'
#           profile      : 'burst' | 'slow_drip' | 'jitter'
#           target       : IP or hostname of target
#           payload_type : 'credentials'|'pii'|'api_key'|'db_dump'|'config'|'custom'
#           payload      : custom payload string (if payload_type='custom')
#           chunk_size   : override default chunk size
#           dns_domain   : parent domain for DNS tunnel (default 'exfil-test.local')
#           dns_server   : specific DNS server IP
#           http_target  : full URL for HTTP injection (default 'http://192.168.1.1')
#           drip_interval: seconds between chunks for slow_drip (default 10)
#           jitter_min   : min seconds for jitter (default 1)
#           jitter_max   : max seconds for jitter (default 8)
#         """
#         if not MODULES_AVAILABLE:
#             logger.error("Modules not available — check agent/modules/")
#             return {}

#         exfil_config = {
#             'technique':    'dns',
#             'profile':      'burst',
#             'target':       '192.168.1.1',
#             'payload_type': 'credentials',
#             'payload':      '',
#             'chunk_size':   None,
#             'dns_domain':   'exfil-test.local',
#             'dns_server':   None,
#             'http_target':  'http://192.168.1.1',
#             'drip_interval': 10.0,
#             'jitter_min':   1.0,
#             'jitter_max':   8.0,
#         }
#         if config:
#             exfil_config.update(config)

#         logger.info(
#             f"Exfil starting — "
#             f"technique={exfil_config['technique']}, "
#             f"profile={exfil_config['profile']}, "
#             f"target={exfil_config['target']}"
#         )

#         engine  = TransferEngine(agent_ref=self, config=exfil_config)
#         summary = engine.run()

#         logger.info(
#             f"Exfil complete — "
#             f"{summary.get('successful',0)}/{summary.get('total_chunks',0)} "
#             f"chunks sent in {summary.get('duration_sec',0):.1f}s"
#         )

#         return summary


# # ── Registration ──────────────────────────────────────────────────────────────

# def register_agent(server_url, agent_id, name, reg_key):
#     import urllib.request, urllib.error
#     logger.info(f"Registering agent '{agent_id}'...")
#     ssl_ctx = build_ssl_context()
#     body    = json.dumps({
#         'agent_id': agent_id,
#         'name':     name or agent_id,
#         'registration_key': reg_key,
#     }).encode('utf-8')
#     req = urllib.request.Request(
#         f"{server_url.rstrip('/')}/api/agent/register/",
#         data=body, headers={'Content-Type': 'application/json'}, method='POST',
#     )
#     try:
#         with urllib.request.urlopen(req, context=ssl_ctx, timeout=10) as r:
#             data = json.loads(r.read())
#     except urllib.error.HTTPError as exc:
#         logger.error(f"Registration failed: {exc.code} {exc.read().decode()}")
#         sys.exit(1)
#     except urllib.error.URLError as exc:
#         logger.error(f"Cannot reach server: {exc.reason}")
#         sys.exit(1)

#     config = {
#         'server_url':       server_url,
#         'agent_id':         data['agent_id'],
#         'auth_token':       data['auth_token'],
#         'secret_key':       data['secret_key'],
#         'registration_key': reg_key,
#     }
#     with open(CONFIG_FILE, 'w') as f:
#         json.dump(config, f, indent=2)
#     logger.info(f"Registered! Config saved to {CONFIG_FILE}")


# def load_config() -> dict:
#     if not Path(CONFIG_FILE).exists():
#         logger.error(f"{CONFIG_FILE} not found. Run --register first.")
#         sys.exit(1)
#     with open(CONFIG_FILE) as f:
#         return json.load(f)


# # ── CLI ───────────────────────────────────────────────────────────────────────

# def main():
#     parser = argparse.ArgumentParser(
#         description='MIAT Security Agent — mTLS + JWT + HMAC + DGA + Exfil',
#         formatter_class=argparse.RawDescriptionHelpFormatter,
#         epilog="""
# Examples:
#   # Register:
#   python agent.py --register --agent-id barc-lab-01 --reg-key SECRET

#   # Run persistently:
#   python agent.py

#   # Nmap scan:
#   python agent.py --scan 192.168.1.1 --profile fast

#   # DGA - date seed:
#   python agent.py --dga

#   # DGA - custom:
#   python agent.py --dga --algorithm xor_lcg --count 30 --rate 2.0

#   # Exfil - DNS tunnel, burst:
#   python agent.py --exfil --technique dns --profile burst

#   # Exfil - HTTP injection, slow drip:
#   python agent.py --exfil --technique http --profile slow_drip --target http://192.168.1.1

#   # Exfil - ICMP stuffing (needs admin/root):
#   python agent.py --exfil --technique icmp --target 192.168.1.1

#   # Exfil - jitter profile:
#   python agent.py --exfil --technique dns --profile jitter --payload-type pii
#         """
#     )

#     # Core
#     parser.add_argument('--register',    action='store_true')
#     parser.add_argument('--agent-id')
#     parser.add_argument('--agent-name')
#     parser.add_argument('--reg-key')
#     parser.add_argument('--server',      default='https://127.0.0.1:8443')

#     # Nmap
#     parser.add_argument('--scan')
#     parser.add_argument('--profile',     default='default',
#                         choices=['fast','default','deep','ping'])

#     # DGA
#     parser.add_argument('--dga',         action='store_true')
#     parser.add_argument('--algorithm',   default='date_seed',
#                         choices=['date_seed','xor_lcg','wordlist'])
#     parser.add_argument('--count',       type=int,   default=50)
#     parser.add_argument('--rate',        type=float, default=1.0)
#     parser.add_argument('--dns-server',  default=None)
#     parser.add_argument('--seed-secret', default='BARC-MIAT')

#     # Exfil
#     parser.add_argument('--exfil',       action='store_true')
#     parser.add_argument('--technique',   default='dns',
#                         choices=['dns','http','icmp'])
#     parser.add_argument('--exfil-profile', default='burst',
#                         choices=['burst','slow_drip','jitter'])
#     parser.add_argument('--target',      default='192.168.1.1')
#     parser.add_argument('--payload-type', default='credentials',
#                         choices=['credentials','pii','api_key',
#                                  'db_dump','config','custom'])
#     parser.add_argument('--payload',     default='')
#     parser.add_argument('--dns-domain',  default='exfil-test.local')
#     parser.add_argument('--drip-interval', type=float, default=10.0)
#     parser.add_argument('--jitter-min',  type=float, default=1.0)
#     parser.add_argument('--jitter-max',  type=float, default=8.0)

#     args = parser.parse_args()

#     # Registration
#     if args.register:
#         if not args.agent_id or not args.reg_key:
#             parser.error('--register requires --agent-id and --reg-key')
#         register_agent(args.server, args.agent_id, args.agent_name, args.reg_key)
#         return

#     config = load_config()
#     if args.server:
#         config['server_url'] = args.server

#     agent = MIATAgent(config)

#     # Nmap scan
#     if args.scan:
#         agent.http.authenticate()
#         result = agent.submit_scan(args.scan, args.profile)
#         print(json.dumps(result, indent=2))
#         return

#     # DGA run
#     if args.dga:
#         agent.http.authenticate()
#         summary = agent.run_dga({
#             'algorithm':   args.algorithm,
#             'count':       args.count,
#             'rate':        args.rate,
#             'dns_server':  args.dns_server,
#             'seed_secret': args.seed_secret,
#         })
#         print(json.dumps(summary, indent=2, default=str))
#         return

#     # Exfil run
#     if args.exfil:
#         agent.http.authenticate()
#         summary = agent.run_exfil({
#             'technique':    args.technique,
#             'profile':      args.exfil_profile,
#             'target':       args.target,
#             'payload_type': args.payload_type,
#             'payload':      args.payload,
#             'dns_domain':   args.dns_domain,
#             'dns_server':   args.dns_server,
#             'http_target':  f"http://{args.target}" if not args.target.startswith('http') else args.target,
#             'drip_interval': args.drip_interval,
#             'jitter_min':   args.jitter_min,
#             'jitter_max':   args.jitter_max,
#         })
#         print(json.dumps(summary, indent=2, default=str))
#         return

#     # Persistent mode
#     agent.start()


# if __name__ == '__main__':
#     main()