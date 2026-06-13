"""
Генерация JS, который инжектится в каждую страницу ДО её скриптов
(через context.add_init_script). Покрывает векторы, которые playwright-stealth
сам по себе не закрывает: шум Canvas/WebGL, подмена WebGL vendor/renderer,
зачистка WebRTC и согласование navigator.* с выбранным отпечатком.

Весь шум детерминирован от seed профиля -> отпечаток стабилен между запусками
(одинаковый хэш у одного профиля, разный у разных).
"""
from __future__ import annotations

from fingerprint import Fingerprint
from geo import GeoProfile


def build_init_script(fp: Fingerprint, geo: GeoProfile) -> str:
    languages_js = ", ".join(f'"{l}"' for l in geo.languages)
    primary_lang = geo.languages[0]

    return f"""
(() => {{
  // ---- детерминированный PRNG от seed профиля --------------------------
  const SEED = {fp.seed} >>> 0;
  function noiseAt(i) {{
    // xorshift-хэш от (seed, index) -> -1 | 0 | 1
    let x = (SEED ^ ((i + 1) * 2654435761)) >>> 0;
    x ^= x << 13; x >>>= 0;
    x ^= x >> 17;
    x ^= x << 5;  x >>>= 0;
    return (x % 3) - 1;
  }}
  const clamp = (v) => v < 0 ? 0 : (v > 255 ? 255 : v);

  // ---- Canvas 2D: лёгкий стабильный шум --------------------------------
  try {{
    const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function(...args) {{
      const img = origGetImageData.apply(this, args);
      const d = img.data;
      for (let i = 0; i < d.length; i += 4) {{
        const n = noiseAt(i);
        if (n !== 0) {{
          d[i]   = clamp(d[i]   + n);
          d[i+1] = clamp(d[i+1] + n);
          d[i+2] = clamp(d[i+2] + n);
        }}
      }}
      return img;
    }};

    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(...args) {{
      try {{
        const ctx = this.getContext('2d');
        if (ctx && this.width && this.height) {{
          const d = ctx.getImageData(0, 0, this.width, this.height); // уже с шумом
          ctx.putImageData(d, 0, 0);
        }}
      }} catch (e) {{}}
      return origToDataURL.apply(this, args);
    }};
  }} catch (e) {{}}

  // ---- WebGL: подмена vendor/renderer + шум readPixels -----------------
  try {{
    const VENDOR = {fp.webgl_vendor!r};
    const RENDERER = {fp.webgl_renderer!r};
    const patchGL = (proto) => {{
      if (!proto) return;
      const origGetParameter = proto.getParameter;
      proto.getParameter = function(p) {{
        if (p === 37445) return VENDOR;    // UNMASKED_VENDOR_WEBGL
        if (p === 37446) return RENDERER;  // UNMASKED_RENDERER_WEBGL
        return origGetParameter.call(this, p);
      }};
      const origReadPixels = proto.readPixels;
      proto.readPixels = function(x, y, w, h, fmt, type, pixels) {{
        origReadPixels.call(this, x, y, w, h, fmt, type, pixels);
        if (pixels && pixels.length) {{
          for (let i = 0; i < pixels.length; i += 17) {{   // редкий стабильный шум
            const n = noiseAt(i);
            if (typeof pixels[i] === 'number') pixels[i] = clamp(pixels[i] + n);
          }}
        }}
      }};
    }};
    patchGL(window.WebGLRenderingContext && WebGLRenderingContext.prototype);
    patchGL(window.WebGL2RenderingContext && WebGL2RenderingContext.prototype);
  }} catch (e) {{}}

  // ---- WebRTC: убрать host(локальные) ICE-кандидаты --------------------
  // Основную защиту даёт флаг --force-webrtc-ip-handling-policy (см. browser.py).
  // Здесь подчищаем host-кандидаты как defense-in-depth.
  try {{
    const OrigRTC = window.RTCPeerConnection || window.webkitRTCPeerConnection;
    if (OrigRTC) {{
      const isLeaky = (cand) => cand && /typ host/.test(cand) &&
                                !/\\.local/.test(cand); // mDNS .local оставляем
      const Patched = function(config, ...rest) {{
        const pc = new OrigRTC(config, ...rest);
        const origAdd = pc.addEventListener.bind(pc);
        pc.addEventListener = function(type, listener, ...a) {{
          if (type === 'icecandidate' && typeof listener === 'function') {{
            const wrapped = function(ev) {{
              if (ev && ev.candidate && isLeaky(ev.candidate.candidate)) return;
              return listener.call(this, ev);
            }};
            return origAdd('icecandidate', wrapped, ...a);
          }}
          return origAdd(type, listener, ...a);
        }};
        return pc;
      }};
      Patched.prototype = OrigRTC.prototype;
      window.RTCPeerConnection = Patched;
      if (window.webkitRTCPeerConnection) window.webkitRTCPeerConnection = Patched;
    }}
  }} catch (e) {{}}

  // ---- navigator / screen: согласовать с выбранным отпечатком ----------
  const define = (obj, prop, value) => {{
    try {{ Object.defineProperty(obj, prop, {{ get: () => value, configurable: true }}); }}
    catch (e) {{}}
  }};

  define(navigator, 'languages', [{languages_js}]);
  define(navigator, 'language', {primary_lang!r});
  define(navigator, 'platform', {fp.nav_platform!r});
  define(navigator, 'hardwareConcurrency', {fp.hardware_concurrency});
  define(navigator, 'deviceMemory', {fp.device_memory});

  // screen / window согласуем с разрешением профиля
  define(screen, 'width', {fp.screen_w});
  define(screen, 'height', {fp.screen_h});
  define(screen, 'availWidth', {fp.screen_w});
  define(screen, 'availHeight', {fp.screen_h - 40});
  define(screen, 'colorDepth', 24);
  define(screen, 'pixelDepth', 24);

  // navigator.userAgentData (Client Hints на стороне JS) — дублирует CDP-оверрайд
  try {{
    const brands = [
      {{ brand: 'Not(A:Brand', version: '99' }},
      {{ brand: 'Google Chrome', version: {fp.chrome_major!r} }},
      {{ brand: 'Chromium', version: {fp.chrome_major!r} }},
    ];
    const uaData = {{
      brands,
      mobile: false,
      platform: {fp.ch_platform!r},
      getHighEntropyValues: (hints) => Promise.resolve({{
        architecture: 'x86',
        bitness: '64',
        brands,
        fullVersionList: [
          {{ brand: 'Not(A:Brand', version: '99.0.0.0' }},
          {{ brand: 'Google Chrome', version: {fp.chrome_full_version!r} }},
          {{ brand: 'Chromium', version: {fp.chrome_full_version!r} }},
        ],
        mobile: false,
        model: '',
        platform: {fp.ch_platform!r},
        platformVersion: {fp.ch_platform_version!r},
        uaFullVersion: {fp.chrome_full_version!r},
      }}),
      toJSON: () => ({{ brands, mobile: false, platform: {fp.ch_platform!r} }}),
    }};
    define(navigator, 'userAgentData', uaData);
  }} catch (e) {{}}
}})();
"""
