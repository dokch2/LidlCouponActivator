# Lidl Plus – aktywator kuponów

Aktywuje kupony Lidl Plus **przez API**, bez klikania po stronie. Odtwarza dokładnie
te zapytania, które robi frontend `www.lidl.pl/mla/` → sekcja Kupony (`/prm/`).

## Jak to działa

Zdekompilowany bundle frontendu (`app-*.js`) pokazuje taki kontrakt:

| Krok | Zapytanie |
|---|---|
| CSRF | `GET /prm/antiforgerytoken` → odpowiedź pusta, token przychodzi w cookie `XSRF-TOKEN` |
| Lista | `GET /prm/api/v1/PL/promotionslist?language=pl-PL` |
| Aktywacja | `POST /prm/api/v1/PL/promotions/{id}/activation?language=pl-PL` |
| Cofnięcie | `DELETE /prm/api/v1/PL/promotions/{id}/activation?language=pl-PL` |

Nagłówki przy POST/DELETE: `Content-Type: application/json`, `X-CSRF-TOKEN: <cookie XSRF-TOKEN>`,
**bez body** (frontend też go nie wysyła). Autoryzacja idzie po cookie `authToken` (JWT z `accounts.lidl.com`).

## Instalacja

```bash
pip install -r requirements.txt
```

Playwright jest opcjonalny – potrzebny tylko dla komendy `login`.

## Cookies – dwa sposoby

### A) Ręcznie

1. Zaloguj się w przeglądarce na https://www.lidl.pl/mla/
2. F12 → Network → wejdź na https://www.lidl.pl/prm/promotions-list
3. Kliknij zapytanie `promotionslist` → Request Headers → skopiuj **całą** wartość `Cookie:`
4. Wklej do pliku `cookies.txt` obok skryptu (jedna linia)

### B) Automatyczne - Playwright

```bash
pip install playwright
python -m playwright install chromium
python lidl_kupony.py login
```

Działa **bez okna** (headless), z limitem **30 sekund**. Wymaga `LIDL_EMAIL` i `LIDL_PASSWORD`
w pliku `.env` (skopiuj z `.env.example` – skrypt wczytuje go sam); bez nich przerywa od razu
z komunikatem. Po zalogowaniu zapisuje `cookies.txt`.

Jeśli Lidl pokaże captchę albo poprosi o kod 2FA, logowanie bez okna padnie po 30 s –
wtedy uruchom `python lidl_kupony.py login --headed`, żeby dokończyć ręcznie w oknie.

Czysty HTTP na `accounts.lidl.com` nie przejdzie – tam jest ochrona Akamai + reCAPTCHA,
dlatego logowanie wymaga prawdziwej przeglądarki.

**Sesja żyje ~1 godzinę** (`exp` w JWT). Po tym czasie dostaniesz 401 i trzeba odświeżyć cookies.
Skrypt na starcie sam wypisuje, ile zostało ważności.

## Użycie

Każda komenda sprawdza na starcie, czy zapisana sesja jest jeszcze ważna (z 2-minutowym
zapasem). Jeśli nie – sama uruchamia logowanie, a po nim wykonuje to, o co prosiłeś.
Czyli `activate --all` na czystym katalogu po prostu zadziała.

Flaga `--no-login` wyłącza to zachowanie – skrypt wtedy przerwie z komunikatem
zamiast otwierać przeglądarkę (przydatne w zadaniach automatycznych).

```bash
python lidl_kupony.py list
```

```bash
python lidl_kupony.py activate --dry-run --all
```

```bash
python lidl_kupony.py activate --limit 1
```

```bash
python lidl_kupony.py activate --all
```

```bash
python lidl_kupony.py deactivate --id <nowe-id-kuponu>
```

Domyślnie `activate` bierze **1 kupon** – żeby nie odpalić wszystkiego przypadkiem.
`--all` aktywuje wszystkie nieaktywne, `--delay` reguluje odstęp między zapytaniami (domyślnie 1.2 s).

Przydatne flagi: `-q` (mniej debugu), `--show-secrets` (nie maskuj tokenów),
`--no-login`, `--headed`, `--cookies <ścieżka>`, `--country`, `--language`.
Działają zarówno przed nazwą komendy, jak i po niej – `login --headed`
i `--headed login` znaczą to samo.

Część kuponów API odrzuci i to jest normalne:

| Kod | Znaczenie |
|---|---|
| `412` | poza oknem ważności – wygasły albo jeszcze nie wystartował; skrypt odsiewa je sam |
| `409` | konflikt – rabaty na całe zakupy wykluczają się wzajemnie, może być aktywny tylko jeden |

Konflikt nie jest traktowany jak awaria (kod wyjścia zostaje 0), a w podsumowaniu
widać, z którym kuponem koliduje.

## Uwaga o pliku cookies.txt

`cookies.txt` zawiera token sesji Twojego konta – traktuj go jak hasło.
Jest w `.gitignore`; nie wrzucaj go nigdzie.
