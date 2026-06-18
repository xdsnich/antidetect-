"""
Локальный прокси-релей — как в Dolphin Anty / Octo и прочих антидетектах.

ЗАЧЕМ. Chromium (через Playwright) ненадёжно отправляет Proxy-Authorization на
HTTP-прокси с логином/паролем: окно открывается, а страницы висят бесконечно
(известный баг microsoft/playwright#13848 и др.). Антидетект-браузеры обходят
это так: поднимают ЛОКАЛЬНЫЙ прокси без авторизации на 127.0.0.1:<порт>, который
проксирует трафик на ваш реальный (upstream) прокси, сам подставляя авторизацию.
Chromium видит «прокси без пароля» — и проблема исчезает.

АРХИТЕКТУРА — поток на соединение, и КАЖДЫЙ поток селектит только свои 2 сокета.
Почему именно так (это критично на Windows):
  • Один общий select() на все сокеты (selectors) на Windows ПАДАЕТ при >512 fd
    («too many file descriptors in select()»). Браузер с вкладками и keep-alive
    HTTP/2 легко открывает 250+ соединений = 500+ сокетов в релее → поток-цикл
    умирает → ВСЁ ВСТАЁТ. Это и был баг «грузит, потом перестаёт».
  • select на 2 сокетах одного туннеля лимита не имеет вовсе.
Плюс: таймаут на чтение заголовка (пустые preconnect-сокеты не копят потоки),
длинный idle-таймаут на сам туннель (долгоживущие HTTP/2 и WebSocket не рвутся),
TCP keepalive. Зависимостей нет — чистый stdlib.
"""
from __future__ import annotations

import base64
import select
import socket
import struct
import sys
import threading
import time
from typing import Optional

from profile import ProxyConfig

# SO_LINGER со временем 0 -> close() шлёт RST вместо FIN, и сокет НЕ уходит в
# TIME_WAIT. Это критично: при реальном сёрфинге (сотни разных CDN-доменов) релей
# открывает тысячи коротких соединений к прокси; с обычным закрытием каждое висит
# в TIME_WAIT 120с -> за ~2 минуты их накапливаются сотни, забивая стек/NAT-таблицу
# роутера -> «через 2 минуты ничего не грузит». RST убирает эту утечку начисто.
_LINGER_RST = struct.pack("ii", 1, 0)

_MAX_HEAD = 64 << 10        # потолок на размер заголовка запроса
_HEAD_TIMEOUT = 30          # сек на присылку запроса (иначе это мёртвый preconnect)
_IDLE_TIMEOUT = 350         # сек простоя туннеля -> уборка (h2/ws шлют ping чаще)
_HIGH_WATER = 256 << 10     # порог backpressure: не читаем источник, пока у
                            # получателя в буфере больше этого (256 КБ)


def _keepalive(sock: socket.socket) -> None:
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass


class ProxyRelay:
    def __init__(self, upstream: ProxyConfig, connect_timeout: int = 20) -> None:
        self.up = upstream
        self.connect_timeout = connect_timeout
        self.host = "127.0.0.1"
        self.port: Optional[int] = None
        self._server: Optional[socket.socket] = None
        self._running = False

        self._auth = b""
        if upstream.username:
            tok = base64.b64encode(
                f"{upstream.username}:{upstream.password or ''}".encode("utf-8"))
            self._auth = b"Proxy-Authorization: Basic " + tok + b"\r\n"

        # счётчики для диагностики (видны в profiles/<name>/last_run.log)
        self._lock = threading.Lock()
        self._active = 0          # сейчас открытых туннелей
        self._served = 0          # всего обслужено
        self._up_fail = 0         # неудачных подключений к upstream-прокси
        self._bytes = 0           # всего переслано байт (обе стороны)

    def _log(self, msg: str) -> None:
        try:
            sys.stderr.write(f"[relay {time.strftime('%H:%M:%S')}] {msg}\n")
            sys.stderr.flush()
        except Exception:  # noqa: BLE001
            pass

    # --------------------------------------------------------------- public
    def start(self) -> tuple[str, int]:
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, 0))
        self._server.listen(256)
        self.port = self._server.getsockname()[1]
        self._running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        threading.Thread(target=self._monitor, daemon=True).start()
        self._log(f"старт: 127.0.0.1:{self.port} -> {self.up.host}:{self.up.port}")
        return self.host, self.port

    def _monitor(self) -> None:
        """
        Каждые 10с пишем пульс релея. Главное — «новых_туннелей за 10с»:
        пока ты сёрфишь, оно > 0; как только обрыв — упадёт в 0, и в этой же
        строке видно почему (растут ли сбои_к_прокси, жив ли accept-loop).
        """
        prev, prev_b = 0, 0
        while self._running:
            time.sleep(10)
            with self._lock:
                served, active, upf, total_b = (self._served, self._active,
                                                self._up_fail, self._bytes)
            delta = served - prev
            kb = (total_b - prev_b) // 1024
            prev, prev_b = served, total_b
            self._log(f"пульс: трафик_за_10с={kb}КБ | новых_туннелей={delta} "
                      f"| активных={active} | всего={served} | сбоев_к_прокси={upf} "
                      f"| потоков={threading.active_count()} "
                      f"| accept={'жив' if self._running else 'мёртв'}")

    def stop(self) -> None:
        self._running = False
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass
            self._server = None

    # -------------------------------------------------------------- internal
    def _accept_loop(self) -> None:
        while self._running:
            try:
                client, _ = self._server.accept()
            except OSError:
                break  # сервер закрыт (обычно stop())
            except Exception as e:  # noqa: BLE001
                self._log(f"accept-сбой (продолжаю): {e!r}")
                continue
            try:
                threading.Thread(target=self._handle, args=(client,),
                                 daemon=True).start()
            except Exception as e:  # noqa: BLE001
                # не удалось создать поток (исчерпаны ресурсы?) — это и был бы
                # «всё встало». Логируем явно.
                self._log(f"НЕ удалось создать поток для соединения: {e!r}")
                try:
                    client.close()
                except OSError:
                    pass
        if self._running:
            self._log("ВНИМАНИЕ: accept-loop ЗАВЕРШИЛСЯ сам — новые соединения "
                      "больше не принимаются (это и есть обрыв).")

    def _handle(self, client: socket.socket) -> None:
        upstream: Optional[socket.socket] = None
        counted = False
        try:
            # 1) читаем заголовок запроса (с таймаутом — пустые preconnect отсечём)
            client.settimeout(_HEAD_TIMEOUT)
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = client.recv(4096)
                if not chunk:
                    return
                head += chunk
                if len(head) > _MAX_HEAD:
                    return
            client.settimeout(None)

            # 2) коннект к upstream-прокси (3 попытки — резидентные прокси блипуют
            #    при ротации/нагрузке; повтор сглаживает короткие провалы)
            attempts = 3
            for attempt in range(attempts):
                try:
                    upstream = socket.create_connection(
                        (self.up.host, self.up.port), timeout=self.connect_timeout)
                    break
                except OSError as e:
                    if attempt == attempts - 1:
                        with self._lock:
                            self._up_fail += 1
                        self._log(f"НЕ удалось подключиться к прокси "
                                  f"{self.up.host}:{self.up.port} за {attempts} попытки: {e}")
                        return
                    time.sleep(0.3 * (attempt + 1))
            upstream.settimeout(None)
            _keepalive(client)
            _keepalive(upstream)
            # RST при закрытии upstream -> сокет к прокси НЕ копится в TIME_WAIT.
            try:
                upstream.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, _LINGER_RST)
            except OSError:
                pass

            i = head.find(b"\r\n")
            upstream.sendall(head[:i + 2] + self._auth + head[i + 2:])

            with self._lock:
                self._active += 1
                self._served += 1
                counted = True

            # 3) туннель: select ТОЛЬКО на этих 2 сокетах -> никакого лимита fd
            self._pipe(client, upstream)
        except OSError:
            pass
        except Exception as e:  # noqa: BLE001
            self._log(f"ошибка соединения: {e!r}")
        finally:
            if counted:
                with self._lock:
                    self._active -= 1
            for s in (client, upstream):
                if s:
                    try:
                        s.close()
                    except OSError:
                        pass

    def _pipe(self, a: socket.socket, b: socket.socket) -> None:
        """
        Полнодуплексный туннель, НЕблокирующий, с буферами и backpressure.

        КРИТИЧНО: нельзя слать блокирующим sendall — если получатель не успевает
        забирать (TCP flow control), sendall заблокирует поток, тот перестанет
        читать встречное направление, и оба направления зависнут (дедлок). Именно
        это вешало туннели. Здесь sendall заменён на неблокирующий send с дослыланием
        остатка по готовности; если буфер получателя переполнен — временно не читаем
        источник (backpressure). select только на 2 сокетах -> лимита fd нет.
        """
        a.setblocking(False)
        b.setblocking(False)
        out = {a: b"", b: b""}        # байты, ждущие отправки В этот сокет
        tearing = False               # одна из сторон закрылась -> сворачиваем туннель

        while True:
            # ПОСЛЕ закрытия одной стороны больше не читаем — только дослаём остатки
            # и сразу закрываем ОБА сокета. Так соединение к прокси и сокет в пуле
            # Chromium освобождаются МГНОВЕННО, а не висят полузакрытыми (иначе пул
            # сокетов к прокси забивается -> новые вкладки/запросы встают).
            if tearing and not out[a] and not out[b]:
                return

            rlist, wlist = [], []
            for s in (a, b):
                peer = b if s is a else a
                if not tearing and len(out[peer]) < _HIGH_WATER:
                    rlist.append(s)
                if out[s]:
                    wlist.append(s)

            if not rlist and not wlist:
                return

            try:
                r, w, _ = select.select(rlist, wlist, [], _IDLE_TIMEOUT)
            except (OSError, ValueError):
                return
            if not r and not w:
                return  # простой дольше idle-таймаута

            for s in r:
                peer = b if s is a else a
                try:
                    data = s.recv(65536)
                except BlockingIOError:
                    continue
                except OSError:
                    return
                if not data:           # EOF — закрываем весь туннель (дослав остатки)
                    tearing = True
                else:
                    out[peer] += data
                    self._bytes += len(data)   # учёт трафика (для пульса)

            for s in w:
                if not out[s]:
                    continue
                try:
                    n = s.send(out[s])
                except BlockingIOError:
                    continue
                except OSError:
                    return
                out[s] = out[s][n:]
