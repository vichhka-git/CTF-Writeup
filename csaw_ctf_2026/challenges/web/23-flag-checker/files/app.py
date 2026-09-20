import arrow
import bleach
from cachetools import TTLCache
import colorlog
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import humanize
from inputval import Flag
import logging
import os
import re
from reqmeta import _store
import shortuuid
from slugify import slugify
import structlog
import user_agents as ua_lib
import validators

load_dotenv()

_handler = colorlog.StreamHandler()
_handler.setFormatter(colorlog.ColoredFormatter(
    '%(log_color)s[%(levelname)s]%(reset)s %(message)s'
))
logging.getLogger().addHandler(_handler)

structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.dev.ConsoleRenderer(),
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
)
log = structlog.get_logger()

app = Flask(__name__)
CORS(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",
)

FLAG = Flag(os.getenv('FLAG'))
_page_cache = TTLCache(maxsize=4, ttl=3600)
_request_counter = 0


def bot_check(ua):
    _store.build = 0
    _store.patch = 0

    # Reject missing or empty user agents outright
    if not ua:
        return True

    # Reject anything a structured parser identifies as a bot or crawler
    if ua_lib.parse(ua).is_bot:
        return True

    # Block known CLI tools and non-browser clients by exact match
    blocked_agents = [
        'curl/7.64.1', 'curl/7.68.0', 'curl/7.74.0', 'curl/7.81.0',
        'curl/8.0.1', 'curl/8.1.2', 'curl/8.4.0', 'curl/8.5.0',
        'Wget/1.20.3', 'Wget/1.21.1', 'Wget/1.21.3', 'Wget/1.21.4',
        'Claude-Code',
    ]
    if ua in blocked_agents:
        return True

    # Block requests whose UA begins with well-known HTTP library identifiers
    blocked_prefixes = [
        'python-requests/', 'python-urllib/', 'Python/',
        'Go-http-client/', 'Ruby/', 'PHP/',
        'Java/', 'Perl/',
    ]
    for prefix in blocked_prefixes:
        if ua.startswith(prefix):
            return True

    # Catch library fingerprints that appear anywhere in the UA string
    blocked_substrings = [
        'libcurl', 'HttpClient', 'okhttp/', 'axios/',
        'node-fetch', 'undici', 'got/', 'superagent',
        'RestSharp', 'Faraday',
    ]
    for token in blocked_substrings:
        if token in ua:
            return True

    # Block scanners, crawlers, and enumeration tools by signature pattern
    blocked_patterns = [
        r'sqlmap/\d', r'Nikto/\d', r'nmap\s',
        r'[Ss]crapy/\d', r'[Mm]echanize',
        r'aiohttp/\d', r'httpx/\d',
        r'[Dd]ir[Bb]uster', r'[Gg]o[Bb]uster', r'[Ff]fuf',
        r'[Zz][Gg]rab', r'[Mm]asscan', r'[Nn]uclei',
        r'[Hh]eadless[Cc]hrome', r'[Pp]hantom[Jj][Ss]',
    ]
    for pattern in blocked_patterns:
        if re.search(pattern, ua):
            return True

    # Validate Chrome build number plausibility — unreasonably large values
    # are a strong indicator of a synthetic or tampered UA string
    m = re.search(r'Chrome/(\d+)\.0\.(\d+)\.(\d+)', ua)
    if m:
        build, patch = int(m.group(2)), int(m.group(3))
        if build > 9999 or patch > 9999:
            return True
        _store.build = build
        _store.patch = patch

    return False


@app.route('/')
@limiter.limit("120/minute")
def index():
    if 'index' not in _page_cache:
        _page_cache['index'] = render_template('index.html')
    return _page_cache['index']


@app.route('/check', methods=['POST'])
def check():
    global _request_counter
    _request_counter += 1

    ua_string = request.headers.get('User-Agent', '')
    if bot_check(ua_string):
        return jsonify({'error': 'Access denied'}), 403

    flag = bleach.clean(request.form.get('flag', ''))
    if not validators.length(flag, min=1, max=200):
        return jsonify({'error': 'Invalid input'}), 400

    req_id = shortuuid.uuid()[:8]
    parsed_ua = ua_lib.parse(ua_string)
    log.debug('flag_check',
              req_id=req_id,
              n=humanize.ordinal(_request_counter),
              client=slugify(parsed_ua.browser.family),
              ts=arrow.utcnow().isoformat(),
              build=getattr(_store, 'build', '?'),
              patch=getattr(_store, 'patch', '?'))

    return jsonify({'correct': flag == FLAG})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
