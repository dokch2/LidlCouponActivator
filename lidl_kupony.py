#!/usr/bin/env python3
"""
Aktywator kuponow Lidl Plus.

Klient API sekcji "Kupony" serwisu www.lidl.pl/mla/:

    GET    /prm/antiforgerytoken                              -> cookie XSRF-TOKEN
    GET    /prm/api/v1/{KRAJ}/promotionslist?language={LANG}  -> lista kuponow
    POST   /prm/api/v1/{KRAJ}/promotions/{id}/activation?language={LANG}
    DELETE /prm/api/v1/{KRAJ}/promotions/{id}/activation?language={LANG}

Uwierzytelnianie opiera sie na cookies sesji www.lidl.pl, przede wszystkim authToken.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

BASE = "https://www.lidl.pl"
PRM = f"{BASE}/prm"
API = f"{PRM}/api/v1"

# Backend odrzuca zapytania bez naglowka User-Agent typowego dla przegladarki.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
)

ROOT = Path(__file__).resolve().parent
DEFAULT_COOKIE_FILE = ROOT / "cookies.txt"

# Limit calego logowania: od uruchomienia przegladarki do uzyskania cookie authToken.
LOGIN_TIMEOUT_S = 30


# --------------------------------------------------------------------------- #
# Logowanie diagnostyczne
# --------------------------------------------------------------------------- #

class Log:
    """Logger z timestampem; verbose wlacza pelne dumpy HTTP."""

    def __init__(self, verbose: bool = True, show_secrets: bool = False):
        self.verbose = verbose
        self.show_secrets = show_secrets

    def _ts(self) -> str:
        return datetime.now().strftime("%H:%M:%S")

    def info(self, msg: str) -> None:
        print(f"[{self._ts()}] {msg}", flush=True)

    def step(self, msg: str) -> None:
        print(f"\n[{self._ts()}] === {msg} ===", flush=True)

    def debug(self, msg: str) -> None:
        if self.verbose:
            print(f"[{self._ts()}]   {msg}", flush=True)

    def mask(self, value: str, keep: int = 8) -> str:
        if self.show_secrets:
            return value
        if value is None:
            return ""
        if len(value) <= keep:
            return "***"
        return f"{value[:keep]}...({len(value)} zn.)"

    def request(self, method: str, url: str, headers: dict, body) -> None:
        """Wypisuje wychodzace zapytanie; wartosci wrazliwe sa maskowane."""
        if not self.verbose:
            return
        print(f"[{self._ts()}]   --> {method} {url}", flush=True)
        for k, v in headers.items():
            if k.lower() == "cookie":
                names = [c.split("=", 1)[0] for c in v.split("; ") if c]
                print(f"[{self._ts()}]       {k}: <{len(names)} cookies: {', '.join(names)}>", flush=True)
            elif k.lower() in ("x-csrf-token", "authorization"):
                print(f"[{self._ts()}]       {k}: {self.mask(v)}", flush=True)
            else:
                print(f"[{self._ts()}]       {k}: {v}", flush=True)
        if body is None:
            print(f"[{self._ts()}]       body: <brak>", flush=True)
        else:
            print(f"[{self._ts()}]       body: {body}", flush=True)

    def response(self, resp: httpx.Response, max_body: int = 400) -> None:
        if not self.verbose:
            return
        print(f"[{self._ts()}]   <-- {resp.status_code} {resp.reason_phrase} "
              f"({resp.headers.get('content-type', '?')}, {len(resp.content)} B)", flush=True)
        set_cookie = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        for sc in set_cookie:
            name = sc.split("=", 1)[0]
            print(f"[{self._ts()}]       set-cookie: {name}=<ukryte>", flush=True)
        text = resp.text
        if text:
            snippet = text[:max_body].replace("\n", " ")
            more = "" if len(text) <= max_body else f" ...(+{len(text) - max_body} zn.)"
            print(f"[{self._ts()}]       body: {snippet}{more}", flush=True)
        else:
            print(f"[{self._ts()}]       body: <puste>", flush=True)


# --------------------------------------------------------------------------- #
# Cookies
# --------------------------------------------------------------------------- #

def parse_cookie_header(raw: str) -> dict:
    """Parsuje surowy naglowek 'Cookie: a=1; b=2' skopiowany z DevTools."""
    out = {}
    for part in raw.strip().split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def load_cookies(path: Path, log: Log, quiet: bool = False) -> dict:
    """
    Wczytuje cookies z pliku. Obsluguje trzy formaty:
      1. surowy naglowek Cookie (jedna linia 'a=1; b=2')
      2. JSON: {"authToken": "...", ...}
      3. JSON: storage_state z Playwright / export z rozszerzenia (lista obiektow)
    """
    if not path.exists():
        raise SystemExit(
            f"Brak pliku z cookies: {path}\n"
            f"Zrob: python lidl_kupony.py login   (Playwright)\n"
            f"albo wklej do {path.name} naglowek Cookie z DevTools (F12 -> Network -> "
            f"dowolne zapytanie do /prm/ -> Request Headers -> Cookie)."
        )

    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        raise SystemExit(f"Plik {path} jest pusty.")

    cookies: dict = {}
    if raw.startswith("{") or raw.startswith("["):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise SystemExit(f"Plik {path.name} nie jest poprawnym JSON-em: {e}")
        if isinstance(data, dict) and "cookies" in data:  # storage_state
            data = data["cookies"]
        if isinstance(data, list):
            for c in data:
                if c.get("name"):
                    cookies[c["name"]] = c.get("value", "")
        elif isinstance(data, dict):
            cookies = {k: str(v) for k, v in data.items()}
    else:
        cookies = parse_cookie_header(raw)

    if not quiet:
        if "authToken" not in cookies:
            log.info("UWAGA: w cookies nie ma 'authToken' - zapytania najpewniej dostana 401.")
        log.debug(f"wczytano {len(cookies)} cookies z {path.name}: {', '.join(cookies)}")
    return cookies


def token_expiry(cookies: dict) -> float | None:
    """Zwraca znacznik czasu wygasniecia JWT z cookie authToken albo None."""
    tok = cookies.get("authToken")
    if not tok or tok.count(".") != 2:
        return None
    try:
        payload = tok.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None
    exp = data.get("exp")
    return float(exp) if exp else None


def token_info(cookies: dict, log: Log) -> None:
    """Wypisuje pozostaly czas waznosci sesji."""
    exp = token_expiry(cookies)
    if exp is None:
        return
    left = int(exp - time.time())
    when = datetime.fromtimestamp(exp, tz=timezone.utc).astimezone().strftime("%H:%M:%S")
    if left <= 0:
        log.info(f"SESJA WYGASLA (authToken wygasl o {when}).")
    else:
        log.debug(f"authToken wazny do {when} (zostalo {left // 60} min {left % 60} s)")


def session_valid(path: Path, log: Log, margin_s: int = 120) -> bool:
    """
    Sprawdza, czy zapisana sesja nadaje sie do uzycia.

    Margines chroni przed sesja wygasajaca w trakcie dluzszego przebiegu.
    """
    if not path.exists():
        log.debug(f"brak pliku {path.name}")
        return False
    try:
        cookies = load_cookies(path, log, quiet=True)
    except SystemExit:
        return False

    if "authToken" not in cookies:
        log.debug("w pliku nie ma cookie authToken")
        return False

    exp = token_expiry(cookies)
    if exp is None:
        log.debug("nie udalo sie odczytac waznosci tokenu - probuje uzyc sesji")
        return True

    left = int(exp - time.time())
    if left <= margin_s:
        log.debug(f"sesja wygasla lub wygasa za {left} s")
        return False

    log.debug(f"sesja wazna jeszcze {left // 60} min {left % 60} s")
    return True


def ensure_session(args, log: Log) -> None:
    """Gwarantuje wazna sesje przed wywolaniem API; w razie potrzeby uruchamia logowanie."""
    path = Path(args.cookies)
    if session_valid(path, log):
        return

    if getattr(args, "no_login", False):
        raise SystemExit(
            f"Brak waznej sesji w {path}. Uruchom: python lidl_kupony.py login\n"
            f"(pomijasz automatyczne logowanie przez --no-login)"
        )

    log.step("Brak waznej sesji - uruchamiam logowanie")
    if cmd_login(args, log) != 0:
        raise SystemExit("Logowanie nie powiodlo sie - przerywam.")

    if not session_valid(path, log):
        raise SystemExit("Po zalogowaniu nadal brak waznej sesji - przerywam.")


# --------------------------------------------------------------------------- #
# Klient API
# --------------------------------------------------------------------------- #

class LidlPlus:
    def __init__(self, cookies: dict, country: str, language: str, log: Log):
        self.country = country.upper()
        self.language = language
        self.log = log
        self.activated_count = 0  # ostatnie activatedCount z API
        self.client = httpx.Client(
            cookies=cookies,
            timeout=30.0,
            follow_redirects=False,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
                "Accept-Language": f"{language},{language.split('-')[0]};q=0.9",
                "Origin": BASE,
                "Referer": f"{PRM}/promotions-list",
            },
        )

    def close(self) -> None:
        self.client.close()

    # -- niskopoziomowe -----------------------------------------------------

    def _send(self, method: str, url: str, extra_headers: dict | None = None,
              content=None, attempts: int = 3) -> httpx.Response:
        headers = dict(self.client.headers)
        if extra_headers:
            headers.update(extra_headers)
        cookie_hdr = "; ".join(f"{k}={v}" for k, v in self.client.cookies.items())
        self.log.request(method, url, {**headers, "Cookie": cookie_hdr}, content)

        # Serwer bywa zrywa polaczenie keep-alive przy serii zapytan; ponawiamy
        # z rosnaca przerwa, zamiast przerywac caly przebieg.
        last_error: Exception | None = None
        for attempt in range(1, attempts + 1):
            try:
                resp = self.client.request(method, url, headers=extra_headers, content=content)
                self.log.response(resp)
                return resp
            except (httpx.RemoteProtocolError, httpx.TransportError) as e:
                last_error = e
                if attempt == attempts:
                    break
                pause = 2 * attempt
                self.log.info(f"    problem z polaczeniem ({type(e).__name__}) "
                              f"- ponawiam za {pause} s [proba {attempt + 1}/{attempts}]")
                time.sleep(pause)

        raise ConnectionError(f"{method} {url} nie powiodlo sie: {last_error}") from last_error

    def _drop_cookie(self, name: str) -> int:
        """Usuwa z jara wszystkie kopie cookie o danej nazwie."""
        jar = self.client.cookies.jar
        targets = [(c.domain, c.path, c.name) for c in jar if c.name == name]
        for domain, path, cname in targets:
            jar.clear(domain, path, cname)
        return len(targets)

    def _get_cookie(self, name: str) -> str | None:
        """Zwraca ostatnia wartosc cookie, omijajac CookieConflict przy duplikatach."""
        values = [c.value for c in self.client.cookies.jar if c.name == name]
        return values[-1] if values else None

    def refresh_csrf(self) -> str:
        """Pobiera token CSRF; odpowiedz jest pusta, token trafia do cookie XSRF-TOKEN."""
        self.log.step("Pobieram token CSRF (antiforgerytoken)")
        # Usuniecie poprzedniego tokenu zapobiega wyslaniu dwoch cookies XSRF-TOKEN naraz.
        dropped = self._drop_cookie("XSRF-TOKEN") + self._drop_cookie("AntiforgeryCookie")
        if dropped:
            self.log.debug(f"usunieto {dropped} stare cookie CSRF przed odswiezeniem")

        self._send("GET", f"{PRM}/antiforgerytoken")
        token = self._get_cookie("XSRF-TOKEN")
        if not token:
            raise RuntimeError("Nie dostalem cookie XSRF-TOKEN - bez niego POST bedzie odrzucony.")
        self.log.debug(f"XSRF-TOKEN = {self.log.mask(token)}")
        return token

    # -- wysokopoziomowe ----------------------------------------------------

    def list_coupons(self) -> list[dict]:
        """Zwraca liste kuponow bez duplikatow; ten sam kupon moze wystapic w kilku sekcjach."""
        self.log.step("Pobieram liste kuponow")
        url = f"{API}/{self.country}/promotionslist?language={self.language}"
        resp = self._send("GET", url)
        if resp.status_code == 401:
            raise SystemExit("401 - sesja wygasla albo cookies sa nieprawidlowe. Odswiez cookies.")
        resp.raise_for_status()
        data = resp.json()

        coupons: dict[str, dict] = {}
        for section in data.get("sections", []):
            for promo in section.get("promotions", []):
                pid = promo.get("id")
                if pid and pid not in coupons:
                    promo["_section"] = section.get("id")
                    coupons[pid] = promo

        self.activated_count = data.get("activatedCount") or 0
        self.log.info(
            f"Znaleziono {len(coupons)} kuponow "
            f"(aktywnych wg API: {self.activated_count}), sekcji: {len(data.get('sections', []))}"
        )
        return list(coupons.values())

    def activate(self, coupon_id: str, csrf: str) -> tuple[bool, str, int, str]:
        url = f"{API}/{self.country}/promotions/{coupon_id}/activation?language={self.language}"
        resp = self._send(
            "POST", url,
            extra_headers={"Content-Type": "application/json", "X-CSRF-TOKEN": csrf},
            content=None,  # API nie oczekuje tresci zadania
        )
        ok = 200 <= resp.status_code < 300
        detail = ""
        if not ok:
            detail = resp.text.strip().strip('[]"').replace('\\"', '"')[:120]
        return ok, f"HTTP {resp.status_code}", resp.status_code, detail

    def deactivate(self, coupon_id: str, csrf: str) -> tuple[bool, str]:
        url = f"{API}/{self.country}/promotions/{coupon_id}/activation?language={self.language}"
        resp = self._send(
            "DELETE", url,
            extra_headers={"Content-Type": "application/json", "X-CSRF-TOKEN": csrf},
        )
        ok = 200 <= resp.status_code < 300
        return ok, f"HTTP {resp.status_code}"


# --------------------------------------------------------------------------- #
# Prezentacja
# --------------------------------------------------------------------------- #

def _parse_dt(raw: str | None) -> datetime | None:
    """Parsuje date ISO 8601 z API; zwraca None dla braku lub niepoprawnej wartosci."""
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def window_status(c: dict) -> str:
    """
    Ocenia okno waznosci kuponu: "ok", "expired" albo "not_started".

    API odrzuca kodem HTTP 412 zarowno kupony po endValidityDate, jak i te,
    ktorych startValidityDate jeszcze nie nadeszla.
    """
    now = datetime.now(timezone.utc)
    end = _parse_dt(c.get("endValidityDate"))
    if end and end < now:
        return "expired"
    start = _parse_dt(c.get("startValidityDate"))
    if start and start > now:
        return "not_started"
    return "ok"


def label(c: dict) -> str:
    offer = (c.get("offer") or "").strip()
    desc = (c.get("description") or c.get("title") or "").strip()
    return f"{offer} | {desc}"[:70]


STATUS_MARK = {"expired": "WYGASL ", "not_started": "PRZYSZL"}


def print_coupons(coupons: list[dict]) -> None:
    print()
    for i, c in enumerate(coupons, 1):
        if c.get("isActivated"):
            mark = "AKTYWNY"
        else:
            mark = STATUS_MARK.get(window_status(c), "       ")
        ch = ",".join(c.get("channels") or [])
        print(f" {i:>3}. [{mark}] {label(c):<70} {ch:<12} {c['id']}")
    print()


# --------------------------------------------------------------------------- #
# Komendy
# --------------------------------------------------------------------------- #

def cmd_list(args, log: Log) -> int:
    ensure_session(args, log)
    cookies = load_cookies(Path(args.cookies), log)
    token_info(cookies, log)
    api = LidlPlus(cookies, args.country, args.language, log)
    try:
        coupons = api.list_coupons()
        print_coupons(coupons)
        todo = [c for c in coupons
                if not c.get("isActivated") and window_status(c) == "ok"]
        blocked = sum(1 for c in coupons
                      if not c.get("isActivated") and window_status(c) != "ok")
        log.info(f"Do aktywacji: {len(todo)} z {len(coupons)}"
                 f"{f' (pomijalnych poza oknem waznosci: {blocked})' if blocked else ''}")
    finally:
        api.close()
    return 0


def cmd_activate(args, log: Log) -> int:
    ensure_session(args, log)
    cookies = load_cookies(Path(args.cookies), log)
    token_info(cookies, log)
    api = LidlPlus(cookies, args.country, args.language, log)
    try:
        coupons = api.list_coupons()
        before_count = api.activated_count
        todo = [c for c in coupons if not c.get("isActivated")]

        expired = [c for c in todo if window_status(c) == "expired"]
        not_started = [c for c in todo if window_status(c) == "not_started"]
        todo = [c for c in todo if window_status(c) == "ok"]

        if expired:
            log.info(f"Pomijam {len(expired)} wygasly(ch) kupon(ow) - API odrzuca je z HTTP 412:")
            for c in expired:
                log.info(f"  - {label(c)} (waznosc do {c.get('endValidityDate')})")

        if not_started:
            log.info(f"Pomijam {len(not_started)} kupon(ow) przed startem waznosci "
                     f"- API odrzuca je z HTTP 412:")
            for c in not_started:
                log.info(f"  - {label(c)} (start {c.get('startValidityDate')})")

        if not todo:
            if expired or not_started:
                log.info("Brak kuponow do aktywacji: pozostale sa aktywne albo poza oknem waznosci.")
            else:
                log.info("Wszystkie kupony sa juz aktywne - nie ma co robic.")
            return 0

        if args.all:
            selected = todo
        else:
            selected = todo[: args.limit]

        log.info(f"Nieaktywnych: {len(todo)}. Biore: {len(selected)}"
                 f"{' (WSZYSTKIE)' if args.all else f' (--limit {args.limit})'}")
        print()
        for i, c in enumerate(selected, 1):
            print(f"   {i}. {label(c)}  [{c['id']}]")

        if args.dry_run:
            log.step("DRY-RUN - pokazuje zapytania, ale nic nie wysylam")
            for c in selected:
                url = f"{API}/{args.country.upper()}/promotions/{c['id']}/activation?language={args.language}"
                log.info(f"POST {url}")
                log.debug("naglowki: Content-Type: application/json, X-CSRF-TOKEN: <token>, Cookie: <sesja>")
                log.debug("body: <brak>")
            return 0

        csrf = api.refresh_csrf()

        ok_count = 0
        fail = []
        conflicts = []
        log.step(f"Aktywuje {len(selected)} kupon(ow)")
        for i, c in enumerate(selected, 1):
            log.info(f"[{i}/{len(selected)}] {label(c)}")
            try:
                ok, msg, code, detail = api.activate(c["id"], csrf)
            except ConnectionError as e:
                # Pojedynczy kupon nie moze przerwac calej serii.
                log.info(f"    BLAD polaczenia: {e}")
                fail.append((c, "brak polaczenia"))
                time.sleep(args.delay)
                continue

            # 400/403 zwykle oznacza zuzyty token CSRF i ma sens po odswiezeniu.
            # 409 i 412 to odmowy merytoryczne, ponawianie nie pomoze.
            if not ok and code in (400, 403):
                log.info(f"    {msg} - odswiezam CSRF i ponawiam")
                csrf = api.refresh_csrf()
                ok, msg, code, detail = api.activate(c["id"], csrf)

            if ok:
                ok_count += 1
                log.info(f"    OK ({msg})")
            elif code == 409:
                # Kupony na cale zakupy wykluczaja sie wzajemnie; API wskazuje
                # w odpowiedzi kupon, ktory juz zajmuje to miejsce.
                conflicts.append((c, detail))
                log.info(f"    POMINIETY - konflikt z innym kuponem"
                         f"{f' ({detail})' if detail else ''}")
            else:
                fail.append((c, f"{msg}{f' - {detail}' if detail else ''}"))
                log.info(f"    BLAD ({msg}){f': {detail}' if detail else ''}")
            if i < len(selected):
                time.sleep(args.delay)

        log.step("Weryfikacja - pobieram liste jeszcze raz")
        # Aktywacja jest asynchroniczna (HTTP 202), wiec stan wymaga chwili na ustalenie.
        time.sleep(1.5)
        # Po aktywacji kupon otrzymuje nowe id, dlatego porownujemy activatedCount
        # oraz tresc kuponu zamiast identyfikatorow.
        after_list = api.list_coupons()
        gained = api.activated_count - before_count

        if gained < len(selected):
            log.info("Nie wszystko jeszcze doszlo - czekam i sprawdzam raz jeszcze")
            time.sleep(3)
            after_list = api.list_coupons()
            gained = api.activated_count - before_count

        active_labels = {label(c) for c in after_list if c.get("isActivated")}
        confirmed = [c for c in selected if label(c) in active_labels]

        log.step("PODSUMOWANIE")
        log.info(f"Wyslano zapytan: {len(selected)} | HTTP OK: {ok_count}"
                 f"{f' | konflikty: {len(conflicts)}' if conflicts else ''}")
        log.info(f"activatedCount: {before_count} -> {api.activated_count} (przybylo {gained})")
        log.info(f"Potwierdzone po tresci kuponu: {len(confirmed)}/{len(selected)}")
        for c in selected:
            state = "AKTYWNY" if label(c) in active_labels else "brak potwierdzenia"
            log.info(f"  {label(c)} -> {state}")

        if conflicts:
            log.info("Pominiete z powodu konfliktu z juz aktywnym kuponem "
                     "(nie da sie miec obu naraz):")
            for c, detail in conflicts:
                log.info(f"  - {label(c)}{f' - koliduje z: {detail}' if detail else ''}")

        for c, msg in fail:
            log.info(f"  nieudane: {label(c)} -> {msg}")

        if gained == 0 and not conflicts:
            log.info("UWAGA: zadne activatedCount nie drgnelo - traktuje to jako blad.")
            return 1
        return 0 if not fail else 1
    finally:
        api.close()


def cmd_deactivate(args, log: Log) -> int:
    """Cofa aktywacje pojedynczego kuponu."""
    ensure_session(args, log)
    cookies = load_cookies(Path(args.cookies), log)
    api = LidlPlus(cookies, args.country, args.language, log)
    try:
        csrf = api.refresh_csrf()
        log.step(f"Dezaktywuje kupon {args.id}")
        ok, msg = api.deactivate(args.id, csrf)
        log.info("OK" if ok else f"BLAD ({msg})")
        return 0 if ok else 1
    finally:
        api.close()


EMAIL_SELECTORS = (
    "input#email",
    "input[name='Input.Email']",
    "input[name=Input_Email]",
    "input[type=email]",
    "input[autocomplete='username']",
)

PASSWORD_SELECTORS = (
    "input#password",
    "input[name='Input.Password']",
    "input[name=Input_Password]",
    "input[type=password]",
    "input[autocomplete='current-password']",
)

# Etykiety przyciskow zatwierdzajacych; formularz bywa jedno- lub dwustopniowy.
SUBMIT_TEXTS = ("Zaloguj", "Dalej", "Kontynuuj", "Zaloguj się", "Log in", "Continue", "Next")


def _dump_form(page, log: Log) -> None:
    """Wypisuje pola i przyciski formularza na potrzeby diagnostyki selektorow."""
    try:
        info = page.evaluate(
            """() => ({
                inputs: [...document.querySelectorAll('input')]
                    .filter(i => i.type !== 'hidden')
                    .map(i => ({type: i.type, name: i.name, id: i.id,
                                ph: i.placeholder, vis: !!i.offsetParent})),
                buttons: [...document.querySelectorAll('button, input[type=submit]')]
                    .map(b => ({text: (b.innerText || b.value || '').trim().slice(0, 30),
                                type: b.type, id: b.id, vis: !!b.offsetParent}))
            })"""
        )
    except Exception as e:
        log.debug(f"nie udalo sie odczytac formularza: {e}")
        return
    log.debug(f"pola: {json.dumps(info['inputs'], ensure_ascii=False)}")
    log.debug(f"przyciski: {json.dumps(info['buttons'], ensure_ascii=False)}")


def _first_visible(page, selectors, timeout_ms: int = 8000):
    """Zwraca pierwszy widoczny element z listy selektorow albo None."""
    deadline = time.time() + timeout_ms / 1000
    while time.time() < deadline:
        for sel in selectors:
            try:
                loc = page.locator(sel).first
                if loc.count() > 0 and loc.is_visible():
                    return loc, sel
            except Exception:
                continue
        page.wait_for_timeout(300)
    return None, None


def _click_submit(page, log: Log) -> bool:
    """
    Klika przycisk zatwierdzajacy formularz.

    Wymagane klikniecie: przycisk obsluguje zdarzenie JS i nie reaguje na klawisz Enter.
    """
    try:
        btn = page.locator("button[type=submit]").first
        if btn.count() > 0 and btn.is_visible():
            btn.click()
            log.debug("kliknieto button[type=submit]")
            return True
    except Exception:
        pass

    for text in SUBMIT_TEXTS:
        try:
            btn = page.get_by_role("button", name=text, exact=False).first
            if btn.count() > 0 and btn.is_visible():
                btn.click()
                log.debug(f"kliknieto przycisk '{text}'")
                return True
        except Exception:
            continue

    log.info("Nie znalazlem przycisku zatwierdzenia - kliknij go sam w oknie.")
    return False


def _lidl_cookies(ctx) -> dict:
    """
    Zbiera cookies ze wszystkich domen lidl.pl.

    Filtrowanie po adresie www.lidl.pl pomijaloby cookies host-only ustawione na
    domenie lidl.pl, na ktorej konczy sie logowanie. Przy powtorzonych nazwach
    pierwszenstwo ma www.lidl.pl, bo pod ten host kierowane sa zapytania API.
    """
    out: dict = {}
    try:
        all_cookies = ctx.cookies()
    except Exception:
        return out
    lidl = [c for c in all_cookies if "lidl.pl" in (c.get("domain") or "")]
    for c in sorted(lidl, key=lambda c: "www" in (c.get("domain") or "")):
        out[c["name"]] = c["value"]
    return out


def mask_emails(text: str) -> str:
    """Zasłania adresy e-mail; logi bywaja przekazywane dalej przy zglaszaniu bledow."""
    return re.sub(r"[\w.+-]+@[\w-]+\.[\w.-]+", "<e-mail ukryty>", text or "")


def _diagnose_login_failure(page, out_dir: Path, log: Log, headed: bool) -> None:
    """
    Wypisuje stan strony po nieudanym logowaniu i zapisuje zrzut ekranu.

    Bez okna przegladarki jest to jedyny sposob, zeby ustalic przyczyne:
    captcha, blad danych logowania albo zadanie kodu 2FA.
    """
    try:
        log.info(f"Adres strony: {mask_emails(page.url)}")
        log.info(f"Tytul strony: {page.title()}")
    except Exception as e:
        log.debug(f"nie udalo sie odczytac stanu strony: {e}")
        return

    # Widoczne komunikaty bledu i typowe markery ochrony antybotowej.
    try:
        info = page.evaluate(
            """() => {
                const txt = document.body ? document.body.innerText : '';
                const errors = [...document.querySelectorAll(
                    '[class*=error], [class*=Error], [role=alert], [class*=invalid]')]
                    .map(e => e.innerText.trim()).filter(Boolean).slice(0, 5);
                const captcha = /recaptcha|captcha|hcaptcha/i.test(document.body.innerHTML);
                return {errors, captcha, snippet: txt.replace(/\\s+/g, ' ').slice(0, 300)};
            }"""
        )
    except Exception as e:
        log.debug(f"nie udalo sie odczytac tresci strony: {e}")
        return

    for msg in info.get("errors", []):
        log.info(f"Komunikat na stronie: {mask_emails(msg)}")
    if info.get("captcha"):
        log.info("Na stronie wykryto captche.")
    if info.get("snippet"):
        log.debug(f"tresc strony: {mask_emails(info['snippet'])}")

    try:
        shot = out_dir / "login_error.png"
        page.screenshot(path=str(shot), full_page=True)
        log.info(f"Zrzut ekranu: {shot}")
    except Exception as e:
        log.debug(f"nie udalo sie zapisac zrzutu ekranu: {e}")

    if not headed:
        log.info("Sprobuj z oknem: python lidl_kupony.py login --headed")


def cmd_login(args, log: Log) -> int:
    """
    Loguje przez przegladarke (Playwright) i zapisuje cookies sesji.

    Logowanie po czystym HTTP nie jest mozliwe: accounts.lidl.com stosuje
    ochrone Akamai oraz reCAPTCHA. Domyslnie przebiega bez okna, w limicie
    LOGIN_TIMEOUT_S; wymaga kompletu danych w .env. Flaga --headed otwiera
    okno i pozwala dokonczyc logowanie recznie.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise SystemExit(
            "Brak Playwright. Zainstaluj:\n"
            "    pip install playwright\n"
            "    python -m playwright install chromium\n"
            "Albo pomin logowanie i wklej cookies recznie do cookies.txt (patrz README)."
        )

    email = os.environ.get("LIDL_EMAIL", "")
    password = os.environ.get("LIDL_PASSWORD", "")
    out = Path(args.cookies)
    headed = getattr(args, "headed", False)

    if not headed and not (email and password):
        raise SystemExit(
            "Logowanie bez okna wymaga LIDL_EMAIL i LIDL_PASSWORD w pliku .env.\n"
            "Uzupelnij .env albo uruchom z --headed, zeby zalogowac sie recznie."
        )

    deadline = time.time() + LOGIN_TIMEOUT_S

    def budget_ms(cap: int) -> int:
        """Pozostaly czas do limitu w ms, ograniczony do cap."""
        left = int((deadline - time.time()) * 1000)
        return max(500, min(cap, left))

    tryb = "z oknem" if headed else "bez okna"
    log.step(f"Uruchamiam przegladarke ({tryb}), limit {LOGIN_TIMEOUT_S} s")

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=not headed,
            args=["--disable-blink-features=AutomationControlled"],
        )
        ctx = browser.new_context(user_agent=USER_AGENT, locale="pl-PL")
        page = ctx.new_page()
        page.goto(f"{BASE}/mla/", wait_until="domcontentloaded", timeout=budget_ms(20000))

        if "accounts.lidl.com" in page.url:
            _dump_form(page, log)

            if email:
                loc, sel = _first_visible(page, EMAIL_SELECTORS, timeout_ms=budget_ms(8000))
                if loc:
                    loc.fill(email)
                    log.info(f"Wpisano e-mail (pole: {sel})")
                else:
                    log.info("Nie znalazlem pola e-mail.")

            # Pole hasla bywa dostepne dopiero w drugim kroku formularza.
            pwd_loc, pwd_sel = _first_visible(page, PASSWORD_SELECTORS, timeout_ms=budget_ms(2000))
            if not pwd_loc and email:
                log.info("Brak pola hasla - formularz dwustopniowy, klikam dalej")
                _click_submit(page, log)
                pwd_loc, pwd_sel = _first_visible(page, PASSWORD_SELECTORS,
                                                  timeout_ms=budget_ms(8000))
                _dump_form(page, log)

            if password and pwd_loc:
                pwd_loc.fill(password)
                log.info(f"Wpisano haslo (pole: {pwd_sel})")
                _click_submit(page, log)
            elif password:
                log.info("Nie znalazlem pola hasla.")

            if headed:
                log.info("Jesli pojawi sie captcha albo kod 2FA - zrob to sam w oknie.")
        else:
            log.info("Sesja juz aktywna - nie trzeba sie logowac.")

        # Odpytywanie stanu zamiast wait_for_url: aplikacja nie zawsze wykonuje
        # pelna nawigacje, a zamkniete okno wymaga czytelnego komunikatu.
        log.info(f"Czekam na zalogowanie... limit {LOGIN_TIMEOUT_S} s, Ctrl+C przerywa")
        cookies: dict = {}
        last_nudge = 0.0

        while time.time() < deadline:
            if page.is_closed():
                log.info("Przegladarka zostala zamknieta przed zalogowaniem - nic nie zapisano.")
                return 1

            cookies = _lidl_cookies(ctx)
            try:
                alive = bool(ctx.pages)
            except Exception:
                alive = False
            if not alive:
                log.info("Przegladarka zostala zamknieta - nic nie zapisano.")
                return 1

            if "authToken" in cookies:
                log.info("Jest authToken - zalogowany.")
                break

            # Po zalogowaniu sesja /prm/ nie jest jeszcze zainicjowana; wymuszamy
            # nawigacje na liste kuponow, aby nie wymagac dzialania uzytkownika.
            try:
                url = page.url
            except Exception:
                url = ""
            if "accounts.lidl.com" not in url and time.time() - last_nudge > 3:
                last_nudge = time.time()
                log.debug("jestem poza accounts.lidl.com - wchodze na /prm/promotions-list")
                try:
                    page.goto(f"{PRM}/promotions-list", wait_until="domcontentloaded",
                              timeout=budget_ms(10000))
                except Exception as e:
                    log.debug(f"nawigacja nieudana ({e}) - probuje dalej")

            time.sleep(0.5)
        else:
            log.info(f"Limit {LOGIN_TIMEOUT_S} s minal bez zalogowania - przerywam.")
            _diagnose_login_failure(page, out.parent, log, headed)
            return 1

        # Wejscie na liste kuponow inicjuje sesje /prm/ i ustawia cookie XSRF-TOKEN.
        try:
            page.goto(f"{PRM}/promotions-list", wait_until="domcontentloaded", timeout=15000)
            page.wait_for_timeout(1500)
            cookies = _lidl_cookies(ctx)
        except Exception as e:
            log.debug(f"nie udalo sie odswiezyc /prm/ ({e}) - zapisuje to, co mam")

        out.write_text(json.dumps(cookies, indent=2), encoding="utf-8")
        log.info(f"Zapisano {len(cookies)} cookies do {out}: {', '.join(cookies)}")
        token_info(cookies, log)

        try:
            browser.close()
        except Exception:
            pass
    return 0


# --------------------------------------------------------------------------- #

def load_env() -> None:
    """Wczytuje plik .env polozony obok skryptu."""
    path = ROOT / ".env"
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


def add_global_flags(parser: argparse.ArgumentParser, with_defaults: bool) -> None:
    """
    Dodaje flagi wspolne dla wszystkich komend.

    Rejestrowane sa dwukrotnie: raz na parserze glownym (z wartosciami domyslnymi)
    i raz na kazdej komendzie, dzieki czemu dzialaja po obu stronach nazwy komendy.
    W wariancie dla komend wartosci domyslne sa pomijane (SUPPRESS), bo inaczej
    nadpisywalyby flage podana przed nazwa komendy.
    """
    def default(value):
        return value if with_defaults else argparse.SUPPRESS

    parser.add_argument("--cookies", default=default(str(DEFAULT_COOKIE_FILE)),
                        help="plik z cookies")
    parser.add_argument("--country", default=default(os.environ.get("LIDL_COUNTRY", "PL")))
    parser.add_argument("--language", default=default(os.environ.get("LIDL_LANGUAGE", "pl-PL")))
    parser.add_argument("-q", "--quiet", action="store_true", default=default(False),
                        help="mniej debugu")
    parser.add_argument("--show-secrets", action="store_true", default=default(False),
                        help="nie maskuj tokenow w logach")
    parser.add_argument("--no-login", action="store_true", default=default(False),
                        help="nie loguj sie automatycznie przy braku waznej sesji")
    parser.add_argument("--headed", action="store_true", default=default(False),
                        help="pokaz okno przegladarki przy logowaniu (do captchy albo 2FA)")


def main() -> int:
    # Nazwy kuponow zawieraja znaki spoza cp1250 (np. U+2300); domyslne kodowanie
    # konsoli Windows przerywaloby wypisywanie listy bledem UnicodeEncodeError.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    load_env()
    ap = argparse.ArgumentParser(
        description="Aktywator kuponow Lidl Plus przez API www.lidl.pl/prm/",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Przyklady:\n"
               "  python lidl_kupony.py list\n"
               "  python lidl_kupony.py activate --dry-run\n"
               "  python lidl_kupony.py activate --limit 1\n"
               "  python lidl_kupony.py activate --all\n",
    )
    add_global_flags(ap, with_defaults=True)

    sub = ap.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("login", help="zaloguj przez przegladarke i zapisz cookies")
    pls = sub.add_parser("list", help="wypisz kupony")

    pa = sub.add_parser("activate", help="aktywuj kupony")
    pa.add_argument("--limit", type=int, default=1, help="ile kuponow (domyslnie 1 - bezpiecznie)")
    pa.add_argument("--all", action="store_true", help="wszystkie nieaktywne")
    pa.add_argument("--dry-run", action="store_true", help="pokaz zapytania, nic nie wysylaj")
    pa.add_argument("--delay", type=float, default=1.2, help="przerwa miedzy zapytaniami [s]")

    pd = sub.add_parser("deactivate", help="cofnij aktywacje kuponu")
    pd.add_argument("--id", required=True)

    # Te same flagi akceptowane rowniez po nazwie komendy.
    for sp in (pl, pls, pa, pd):
        add_global_flags(sp, with_defaults=False)

    args = ap.parse_args()
    log = Log(verbose=not args.quiet, show_secrets=args.show_secrets)

    log.info(f"Start: {args.cmd} | kraj={args.country} | jezyk={args.language}")

    handlers = {
        "login": cmd_login,
        "list": cmd_list,
        "activate": cmd_activate,
        "deactivate": cmd_deactivate,
    }
    try:
        return handlers[args.cmd](args, log)
    except KeyboardInterrupt:
        log.info("Przerwane.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
