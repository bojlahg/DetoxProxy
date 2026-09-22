#!/usr/bin/env python3
"""Чёрный ящик-проверка LLM-прокси для сравнения стеков. Только stdlib, Python 3.10+.

Запуск:  python check.py --cmd "<команда запуска прокси>" [--base-port 18080] [--skip-load]

Проверка сама поднимает два фейковых upstream (A и B), запускает прокси с переменными
окружения LISTEN_ADDR, UPSTREAMS, TTFT_TIMEOUT_MS и гоняет тесты. Код возврата 0 — всё зелёное.
"""
import argparse
import asyncio
import json
import os
import shlex
import subprocess
import sys
import time

NS = 1_000_000_000
now_ns = time.perf_counter_ns


class Buf:
    """Буферизованное чтение поверх asyncio.StreamReader."""

    def __init__(self, reader):
        self.r = reader
        self.b = bytearray()

    async def fill(self):
        chunk = await self.r.read(65536)
        if not chunk:
            raise EOFError
        self.b += chunk

    async def until(self, sep):
        while True:
            i = self.b.find(sep)
            if i >= 0:
                out = bytes(self.b[:i])
                del self.b[: i + len(sep)]
                return out
            await self.fill()

    async def exactly(self, n):
        while len(self.b) < n:
            await self.fill()
        out = bytes(self.b[:n])
        del self.b[:n]
        return out

    def take_all(self):
        out = bytes(self.b)
        self.b.clear()
        return out


def parse_headers(head):
    lines = head.decode("latin-1").split("\r\n")
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return lines[0], headers


async def read_chunked(buf):
    out = bytearray()
    while True:
        line = await buf.until(b"\r\n")
        size = int(line.split(b";")[0].strip() or b"0", 16)
        if size == 0:
            await buf.until(b"\r\n")
            return bytes(out)
        out += await buf.exactly(size)
        await buf.exactly(2)


# --------------------------------------------------------------------------- mock upstream


class Mock:
    """Фейковый OpenAI-совместимый upstream. mode: ok | 503 | stall_first | abort_mid."""

    def __init__(self, name, port):
        self.name = name
        self.port = port
        self.mode = "ok"
        self.requests = []
        self.server = None

    async def start(self):
        self.server = await asyncio.start_server(self._conn, "127.0.0.1", self.port)

    def posts(self):
        return [r for r in self.requests if r["path"] == "/v1/chat/completions"]

    async def _conn(self, reader, writer):
        buf = Buf(reader)
        try:
            while True:
                try:
                    head = await buf.until(b"\r\n\r\n")
                except EOFError:
                    break
                line, headers = parse_headers(head)
                parts = line.split(" ")
                method, path = parts[0], parts[1] if len(parts) > 1 else "/"
                if headers.get("transfer-encoding", "").lower() == "chunked":
                    body = await read_chunked(buf)
                else:
                    body = await buf.exactly(int(headers.get("content-length", "0") or 0))
                rec = {"rid": len(self.requests), "t": now_ns(), "method": method, "path": path,
                       "headers": headers, "body": body, "disconnected_at": None, "done": False}
                self.requests.append(rec)
                keep = await self._serve(rec, buf, writer)
                rec["done"] = True
                if not keep:
                    break
        except (OSError, EOFError, asyncio.IncompleteReadError, ValueError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _send(self, writer, status, obj):
        data = json.dumps(obj).encode()
        writer.write(b"HTTP/1.1 " + status.encode() + b"\r\ncontent-type: application/json\r\ncontent-length: "
                     + str(len(data)).encode() + b"\r\n\r\n" + data)
        await writer.drain()

    async def _serve(self, rec, buf, writer):
        if rec["path"] != "/v1/chat/completions":
            await self._send(writer, "200 OK", {"status": "ok", "upstream": self.name})
            return True
        if self.mode == "503":
            await self._send(writer, "503 Service Unavailable", {"error": {"message": "mock overloaded", "type": "overloaded"}})
            return True
        try:
            req = json.loads(rec["body"] or b"{}")
        except ValueError:
            await self._send(writer, "400 Bad Request", {"error": {"message": "bad json"}})
            return True
        xm = req.get("x_mock") or {}
        ttft = xm.get("ttft_ms", 50) / 1000
        interval = xm.get("interval_ms", 20) / 1000
        n_events = xm.get("events", 10)
        rid = rec["rid"]

        if not req.get("stream"):
            await asyncio.sleep(ttft)
            await self._send(writer, "200 OK", {
                "id": f"chatcmpl-{rid}", "object": "chat.completion", "x_upstream": self.name,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": f"hello from {self.name}"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}})
            return True

        async def watch():
            try:
                await buf.fill()
            except (EOFError, OSError):
                rec["disconnected_at"] = now_ns()

        watcher = asyncio.ensure_future(watch())

        async def pause(delay):
            """False, если за время паузы прокси закрыл соединение."""
            if watcher.done():
                if rec["disconnected_at"]:
                    return False
                await asyncio.sleep(delay)
                return True
            await asyncio.wait({watcher}, timeout=delay)
            return not rec["disconnected_at"]

        async def chunk(data):
            writer.write(b"%x\r\n" % len(data) + data + b"\r\n")
            await writer.drain()

        try:
            writer.write(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncache-control: no-cache\r\n"
                         b"transfer-encoding: chunked\r\n\r\n")
            await writer.drain()
            if self.mode == "stall_first":
                ttft = 3.0
            if not await pause(ttft):
                return False
            for i in range(n_events):
                if self.mode == "abort_mid" and i == 3:
                    writer.transport.abort()
                    return False
                ev = {"id": f"chatcmpl-{rid}", "object": "chat.completion.chunk", "x_upstream": self.name,
                      "x_seq": i, "choices": [{"index": 0, "delta": {"content": f"tok{i} "}}], "x_sent_ns": now_ns()}
                await chunk(b"data: " + json.dumps(ev).encode() + b"\n\n")
                if i < n_events - 1 and not await pause(interval):
                    return False
            await chunk(b"data: [DONE]\n\n")
            writer.write(b"0\r\n\r\n")
            await writer.drain()
            return not watcher.done()
        except OSError:
            if not rec["disconnected_at"]:
                rec["disconnected_at"] = now_ns()
            return False
        finally:
            watcher.cancel()
            try:
                await watcher
            except BaseException:  # noqa: BLE001 — ждём завершения чтения, чтобы не столкнуться со следующим запросом
                pass


# --------------------------------------------------------------------------- client


class Result:
    def __init__(self):
        self.status = 0
        self.headers = {}
        self.body = bytearray()
        self.events = []  # (t_arrival_ns, payload_str)
        self.t0 = now_ns()
        self.ended = "?"
        self.error = None

    def json(self):
        return json.loads(bytes(self.body))

    def data_events(self):
        return [(t, json.loads(p)) for t, p in self.events if p != "[DONE]"]


async def _do_request(res, port, method, path, body, headers, stop_after):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        hdrs = {"host": f"127.0.0.1:{port}", "accept": "*/*"}
        data = b""
        if body is not None:
            data = json.dumps(body).encode()
            hdrs["content-type"] = "application/json"
            hdrs["content-length"] = str(len(data))
        hdrs.update(headers or {})
        raw = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
        res.t0 = now_ns()
        writer.write(raw.encode() + data)
        await writer.drain()
        buf = Buf(reader)
        line, res.headers = parse_headers(await buf.until(b"\r\n\r\n"))
        res.status = int(line.split(" ")[1])
        sse = bytearray()

        def feed(piece):
            res.body += piece
            sse.extend(piece.replace(b"\r\n", b"\n"))
            t = now_ns()
            while True:
                i = sse.find(b"\n\n")
                if i < 0:
                    break
                block = bytes(sse[:i]).decode("utf-8", "replace")
                del sse[: i + 2]
                for ln in block.split("\n"):
                    if ln.startswith("data:"):
                        res.events.append((t, ln[5:].strip()))
            return stop_after is not None and len(res.events) >= stop_after

        try:
            if res.headers.get("transfer-encoding", "").lower() == "chunked":
                while True:
                    ln = await buf.until(b"\r\n")
                    size = int(ln.split(b";")[0].strip() or b"0", 16)
                    if size == 0:
                        res.ended = "complete"
                        break
                    piece = await buf.exactly(size)
                    await buf.exactly(2)
                    if feed(piece):
                        res.ended = "client_abort"
                        break
            elif "content-length" in res.headers:
                left = int(res.headers["content-length"])
                while left > 0:
                    if not buf.b:
                        await buf.fill()
                    piece = buf.take_all()[:left]
                    left -= len(piece)
                    if feed(piece):
                        res.ended = "client_abort"
                        break
                else:
                    res.ended = "complete"
            else:
                while True:
                    if buf.b and feed(buf.take_all()):
                        res.ended = "client_abort"
                        break
                    await buf.fill()
        except EOFError:
            res.ended = "eof" if res.ended == "?" else res.ended
        except (OSError, asyncio.IncompleteReadError):
            res.ended = "reset"
    finally:
        try:
            writer.transport.abort()
        except Exception:
            pass


async def request(port, method, path, body=None, headers=None, stop_after=None, timeout=10.0):
    res = Result()
    try:
        await asyncio.wait_for(_do_request(res, port, method, path, body, headers, stop_after), timeout)
    except asyncio.TimeoutError:
        res.ended = "timeout"
    except OSError as e:
        res.ended = "connect_error"
        res.error = str(e)
    return res


def chat(stream, **x_mock):
    return {"model": "test-model", "stream": stream, "messages": [{"role": "user", "content": "Привет, мир"}],
            "temperature": 0.2, "x_mock": x_mock}


def pct(values, p):
    if not values:
        return 0.0
    s = sorted(values)
    return s[min(len(s) - 1, int(round(p / 100 * (len(s) - 1))))]


# --------------------------------------------------------------------------- tests


class Suite:
    def __init__(self, proxy_port, a, b):
        self.p = proxy_port
        self.a = a
        self.b = b
        self.results = []

    def reset(self):
        self.a.mode = "ok"
        self.b.mode = "ok"

    async def run(self, name, coro, timeout=30):
        self.reset()
        t = time.time()
        try:
            detail = await asyncio.wait_for(coro(), timeout)
            ok = True
        except AssertionError as e:
            ok, detail = False, str(e) or "assertion failed"
        except asyncio.TimeoutError:
            ok, detail = False, f"тест завис (> {timeout} s)"
        except Exception as e:  # noqa: BLE001
            ok, detail = False, f"{type(e).__name__}: {e}"
        self.results.append({"name": name, "ok": ok, "detail": detail, "sec": round(time.time() - t, 2)})
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}", flush=True)
        self.reset()
        await asyncio.sleep(0.05)

    async def t_nonstream(self):
        body = chat(False, ttft_ms=20)
        n = len(self.a.posts())
        r = await request(self.p, "POST", "/v1/chat/completions", body, {"authorization": "Bearer test-key-123"})
        assert r.status == 200, f"статус {r.status}, ended={r.ended}"
        assert r.json().get("x_upstream") == "A", "ответ должен прийти от первого upstream (A) без изменений"
        posts = self.a.posts()
        assert len(posts) == n + 1, "upstream A должен получить ровно один запрос"
        assert json.loads(posts[-1]["body"]) == body, "тело запроса до upstream дошло изменённым"
        assert posts[-1]["headers"].get("authorization") == "Bearer test-key-123", "заголовок Authorization не проброшен"
        return "тело и Authorization проброшены без изменений"

    async def t_stream(self):
        r = await request(self.p, "POST", "/v1/chat/completions", chat(True, ttft_ms=150, interval_ms=80, events=8))
        assert r.status == 200, f"статус {r.status}, ended={r.ended}"
        assert r.headers.get("content-type", "").startswith("text/event-stream"), f"content-type={r.headers.get('content-type')}"
        evs = r.data_events()
        assert len(evs) == 8, f"получено {len(evs)} событий из 8 (ended={r.ended})"
        assert r.events[-1][1] == "[DONE]", "нет завершающего data: [DONE]"
        lags = [(t - e["x_sent_ns"]) / 1e6 for t, e in evs]
        assert max(lags) < 50, f"события буферизуются: максимальная задержка {max(lags):.1f} ms (порог 50 ms)"
        return f"8 событий, задержка пересылки max {max(lags):.2f} ms"

    async def t_cancel(self):
        n = len(self.a.posts())
        r = await request(self.p, "POST", "/v1/chat/completions", chat(True, ttft_ms=30, interval_ms=30, events=200), stop_after=3)
        assert r.ended == "client_abort", f"клиент не дочитал до 3 событий: ended={r.ended}, status={r.status}"
        t_abort = now_ns()
        rec = self.a.posts()[n]
        for _ in range(150):
            if rec["disconnected_at"]:
                break
            await asyncio.sleep(0.01)
        assert rec["disconnected_at"], "клиент отключился, но прокси не закрыл соединение с upstream за 1.5 s (генерация продолжается)"
        return f"upstream отменён через {(rec['disconnected_at'] - t_abort) / 1e6:.0f} ms после отключения клиента"

    async def t_failover(self):
        self.a.mode = "503"
        nb = len(self.b.posts())
        r = await request(self.p, "POST", "/v1/chat/completions", chat(True, ttft_ms=30, interval_ms=10, events=5))
        assert r.status == 200, f"stream: статус {r.status} (ожидался 200 от upstream B)"
        evs = r.data_events()
        assert len(evs) == 5 and all(e["x_upstream"] == "B" for _, e in evs), "stream: события должны прийти от B"
        r2 = await request(self.p, "POST", "/v1/chat/completions", chat(False, ttft_ms=10))
        assert r2.status == 200 and r2.json().get("x_upstream") == "B", f"non-stream: статус {r2.status}, ожидался ответ от B"
        assert len(self.b.posts()) == nb + 2, "B должен получить ровно два запроса"
        return "A отдаёт 503 → оба запроса обслужены B, клиент ошибок не видит"

    async def t_all_down(self):
        self.a.mode = self.b.mode = "503"
        r = await request(self.p, "POST", "/v1/chat/completions", chat(True), timeout=8)
        assert r.status in (502, 503), f"статус {r.status} (ожидался 502 или 503), ended={r.ended}"
        try:
            err = r.json()
        except ValueError:
            raise AssertionError("тело ошибки не JSON")
        assert "error" in err, 'в теле нет ключа "error"'
        return f"статус {r.status}, JSON-ошибка в формате OpenAI"

    async def t_ttft_timeout(self):
        self.a.mode = "stall_first"
        na = len(self.a.posts())
        r = await request(self.p, "POST", "/v1/chat/completions", chat(True, ttft_ms=30, interval_ms=10, events=5), timeout=6)
        assert r.status == 200, f"статус {r.status}, ended={r.ended}"
        evs = r.data_events()
        assert len(evs) == 5 and all(e["x_upstream"] == "B" for _, e in evs), \
            f"ожидались 5 событий от B, получено {len(evs)} от {sorted({e['x_upstream'] for _, e in evs})}"
        first_ms = (evs[0][0] - r.t0) / 1e6
        assert first_ms < 1500, f"первое событие пришло через {first_ms:.0f} ms (TTFT_TIMEOUT_MS=500, порог 1500 ms)"
        rec = self.a.posts()[na]
        for _ in range(100):
            if rec["disconnected_at"]:
                break
            await asyncio.sleep(0.01)
        assert rec["disconnected_at"], "зависшая попытка к A не отменена (соединение не закрыто)"
        return f"A прислал заголовки и завис → переключение на B, первое событие через {first_ms:.0f} ms, попытка к A отменена"

    async def t_midstream(self):
        self.a.mode = "abort_mid"
        nb = len(self.b.posts())
        t = time.time()
        r = await request(self.p, "POST", "/v1/chat/completions", chat(True, ttft_ms=30, interval_ms=30, events=10), timeout=5)
        took = time.time() - t
        assert r.ended != "timeout", "стрим не завершён: после обрыва upstream клиент висит"
        evs = [e for _, e in r.data_events() if "x_upstream" in e]
        assert len(evs) == 3 and all(e["x_upstream"] == "A" for e in evs), f"ожидались ровно 3 события от A, получено {len(evs)}"
        assert len(self.b.posts()) == nb, "после первого байта retry запрещён, но B получил запрос"
        return f"3 события доставлены, стрим закрыт за {took:.2f} s, retry не было"

    async def t_metrics(self):
        r = await request(self.p, "GET", "/metrics")
        assert r.status == 200, f"статус {r.status}"
        total = 0.0
        for ln in bytes(r.body).decode("utf-8", "replace").splitlines():
            if ln.startswith("proxy_requests_total"):
                try:
                    total += float(ln.rsplit(" ", 1)[1])
                except (ValueError, IndexError):
                    pass
        assert total >= 5, f"сумма proxy_requests_total = {total} (ожидалось ≥ 5)"
        return f"proxy_requests_total = {total:.0f}"

    async def _load(self, port, n, events):
        body = chat(True, ttft_ms=50, interval_ms=40, events=events)
        rs = await asyncio.gather(*[request(port, "POST", "/v1/chat/completions", body, timeout=60) for _ in range(n)])
        bad = [r for r in rs if r.status != 200 or len(r.data_events()) != events]
        lags = [(t - e["x_sent_ns"]) / 1e6 for r in rs for t, e in r.data_events()]
        return bad, lags

    async def t_load(self):
        n, events = 200, 25
        _, base = await self._load(self.a.port, n, events)
        bad, lags = await self._load(self.p, n, events)
        assert not bad, f"{len(bad)} из {n} стримов неполные или с ошибкой (пример: status={bad[0].status}, ended={bad[0].ended}, events={len(bad[0].events)})"
        self.load = {"streams": n, "events_per_stream": events,
                     "direct_ms": {"p50": round(pct(base, 50), 3), "p99": round(pct(base, 99), 3)},
                     "proxy_ms": {"p50": round(pct(lags, 50), 3), "p99": round(pct(lags, 99), 3), "max": round(max(lags), 3)}}
        return (f"{n} стримов × {events} событий; задержка события напрямую p50/p99 = {self.load['direct_ms']['p50']}/{self.load['direct_ms']['p99']} ms, "
                f"через прокси = {self.load['proxy_ms']['p50']}/{self.load['proxy_ms']['p99']} ms")


def rss_mb(pid):
    try:
        if os.name == "nt":
            out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"], capture_output=True, text=True, timeout=10).stdout
            kb = "".join(ch for ch in out.strip().split('","')[-1] if ch.isdigit())
            return round(int(kb) / 1024, 1)
        with open(f"/proc/{pid}/status") as f:
            for ln in f:
                if ln.startswith("VmRSS"):
                    return round(int(ln.split()[1]) / 1024, 1)
    except Exception:  # noqa: BLE001
        return None


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cmd", required=True, help="команда запуска прокси")
    ap.add_argument("--base-port", type=int, default=18080)
    ap.add_argument("--skip-load", action="store_true")
    args = ap.parse_args()

    port = args.base_port
    a, b = Mock("A", port + 1), Mock("B", port + 2)
    await a.start()
    await b.start()

    env = dict(os.environ, LISTEN_ADDR=f"127.0.0.1:{port}", TTFT_TIMEOUT_MS="500",
               UPSTREAMS=f"http://127.0.0.1:{port + 1},http://127.0.0.1:{port + 2}")
    log = open("proxy.log", "wb")
    proc = subprocess.Popen(shlex.split(args.cmd, posix=(os.name != "nt")), env=env, stdout=log, stderr=subprocess.STDOUT)
    suite = Suite(port, a, b)
    suite.load = None
    try:
        up = False
        for _ in range(150):
            if proc.poll() is not None:
                break
            r = await request(port, "GET", "/healthz", timeout=1)
            if r.status == 200:
                up = True
                break
            await asyncio.sleep(0.1)
        if not up:
            print(f"[FAIL] start: прокси не ответил 200 на GET /healthz за 15 s (exit={proc.poll()}); см. proxy.log", flush=True)
            suite.results.append({"name": "start", "ok": False, "detail": "прокси не стартовал"})
        else:
            await suite.run("nonstream_passthrough", suite.t_nonstream)
            await suite.run("stream_incremental", suite.t_stream)
            await suite.run("client_cancel", suite.t_cancel)
            await suite.run("failover_before_first_byte", suite.t_failover)
            await suite.run("all_upstreams_down", suite.t_all_down)
            await suite.run("ttft_timeout_failover", suite.t_ttft_timeout)
            await suite.run("midstream_abort_no_retry", suite.t_midstream)
            await suite.run("metrics", suite.t_metrics)
            if not args.skip_load:
                await suite.run("load_200_streams", suite.t_load, timeout=150)
            alive = proc.poll() is None
            suite.results.append({"name": "no_crash", "ok": alive, "detail": "процесс жив" if alive else f"процесс упал, exit={proc.poll()}"})
            print(f"[{'PASS' if alive else 'FAIL'}] no_crash: {suite.results[-1]['detail']}", flush=True)
        mem = rss_mb(proc.pid) if proc.poll() is None else None
    finally:
        if proc.poll() is None:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True)
            else:
                proc.terminate()
        log.close()

    passed = sum(1 for r in suite.results if r["ok"])
    summary = {"passed": passed, "total": len(suite.results), "rss_mb_after_tests": mem, "load": suite.load, "tests": suite.results}
    with open("check-result.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"\nИТОГ: {passed}/{len(suite.results)}; память прокси после тестов: {mem} MB", flush=True)
    return 0 if passed == len(suite.results) else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(asyncio.run(main()))
