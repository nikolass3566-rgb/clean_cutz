import firebase_admin
from firebase_admin import credentials, messaging, firestore, auth as fb_auth
from firebase_admin.messaging import UnregisteredError, SenderIdMismatchError, ThirdPartyAuthError, QuotaExceededError
from google.cloud.firestore_v1.base_query import FieldFilter
import datetime
import time
import threading
import os
import uvicorn
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json
from typing import List, Optional

# --- INICIJALIZACIJA ---
app = FastAPI()

# CORS: aplikacija (browser) poziva admin endpointe. Autorizacija ide preko Firebase ID tokena,
# pa je "*" bezbedno; po želji ograniči: ALLOWED_ORIGINS="https://tvoj-sajt.com,https://www.tvoj-sajt.com"
_origins = [o.strip() for o in os.environ.get('ALLOWED_ORIGINS', '*').split(',') if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

firebase_config = os.environ.get('FIREBASE_CONFIG')

if firebase_config:
    cred_dict = json.loads(firebase_config)
    cred = credentials.Certificate(cred_dict)
else:
    cred = credentials.Certificate("serviceAccountKey.json")

firebase_admin.initialize_app(cred)
db = firestore.client()

# ──────────────────────────────────────────────
# VREMENSKA ZONA — prava zona (automatski prelazi letnje/zimsko računanje vremena).
# Ako na serveru nema tzdata baze, dodaj "tzdata" u requirements.txt.
# ──────────────────────────────────────────────
try:
    from zoneinfo import ZoneInfo
    TZ_LOCAL = ZoneInfo("Europe/Belgrade")
except Exception as tz_err:
    print(f"UPOZORENJE: zona Europe/Belgrade nije dostupna ({tz_err}) — koristim fiksno UTC+2. Dodaj 'tzdata' u requirements.txt.")
    TZ_LOCAL = datetime.timezone(datetime.timedelta(hours=2))

UTC = datetime.timezone.utc

# Tipovi grešaka koji znače "token je mrtav, obriši ga".
DEAD_TOKEN_ERRORS = (UnregisteredError, SenderIdMismatchError, ThirdPartyAuthError)

# Podsetnici: prozor u minutima (min..max pre termina), flag u dokumentu termina,
# tip obaveštenja (ikona u aplikaciji) i prag za preskakanje podsetnika
# ako je termin zakazan već UNUTAR tog praga (npr. zakazano 40 min unapred → nema "za 2 sata").
REMINDERS = [
    {'min': 115, 'max': 121, 'flag': 'sent_2h',    'type': 'reminder_2h',    'threshold': 120},
    {'min': 55,  'max': 61,  'flag': 'sent_1h',    'type': 'reminder_1h',    'threshold': 60},
    {'min': 25,  'max': 31,  'flag': 'sent_30min', 'type': 'reminder_30min', 'threshold': 30},
]

PUSH_TTL_SECONDS = 30 * 60          # zakasneli push (telefon ugašen) se odbacuje posle 30 min
NOTIF_KEEP_DAYS = 30                # istorija obaveštenja starija od ovoga se briše
NEW_APPT_MAX_AGE_SECONDS = 15 * 60  # novu rezervaciju javljamo frizeru samo ako je mlađa od 15 min


@app.api_route("/", methods=["GET", "HEAD"])
def health_check():
    return {"status": "online", "timezone": "Europe/Belgrade"}



# ──────────────────────────────────────────────
# ADMIN ENDPOINTI — brisanje naloga (Authentication + Firestore), blokiranje i reset podataka.
# Svaki poziv mora imati "Authorization: Bearer <Firebase ID token>" admina;
# uloga se proverava u users/{uid}.role == 'admin' (klijent ne može da je falsifikuje).
# ──────────────────────────────────────────────
def require_admin(authorization):
    if not authorization or not authorization.lower().startswith('bearer '):
        raise HTTPException(status_code=401, detail="Nedostaje prijava.")
    try:
        decoded = fb_auth.verify_id_token(authorization[7:].strip())
    except Exception:
        raise HTTPException(status_code=401, detail="Nevažeća prijava. Prijavi se ponovo.")
    uid = decoded.get('uid')
    snap = db.collection('users').document(uid).get()
    if not snap.exists or (snap.to_dict() or {}).get('role') != 'admin':
        raise HTTPException(status_code=403, detail="Samo admin može ovo da uradi.")
    return uid


def load_target_client(caller_uid, target_uid):
    """Vraća (ref, data) ciljnog KLIJENTA; odbija sebe, admine i frizere."""
    if not target_uid or not isinstance(target_uid, str):
        raise HTTPException(status_code=400, detail="Nedostaje korisnik.")
    if target_uid == caller_uid:
        raise HTTPException(status_code=400, detail="Ne možeš da upravljaš sopstvenim nalogom.")
    ref = db.collection('users').document(target_uid)
    snap = ref.get()
    data = snap.to_dict() or {} if snap.exists else {}
    role = data.get('role', 'client')
    if role == 'admin':
        raise HTTPException(status_code=400, detail="Admin nalog se ne može menjati odavde.")
    if role == 'employee':
        raise HTTPException(status_code=400, detail="Prvo ukloni ulogu frizera, pa onda upravljaj nalogom.")
    return ref, data


def delete_refs(refs):
    refs = list(refs)
    for i in range(0, len(refs), 400):
        batch = db.batch()
        for r in refs[i:i + 400]:
            batch.delete(r)
        batch.commit()
    return len(refs)


def wipe_collection(name):
    total = 0
    while True:
        docs = list(db.collection(name).limit(400).stream())
        if not docs:
            break
        total += delete_refs(d.reference for d in docs)
    return total


class UidBody(BaseModel):
    uid: str


class BlockBody(BaseModel):
    uid: str
    blocked: bool


class ResetBody(BaseModel):
    confirm: str


@app.post("/admin/delete-user")
def admin_delete_user(body: UidBody, authorization: str = Header(None)):
    caller = require_admin(authorization)
    ref, _data = load_target_client(caller, body.uid)

    # 1) Authentication (prvo, da se korisnik više ne može prijaviti)
    try:
        fb_auth.delete_user(body.uid)
    except fb_auth.UserNotFoundError:
        pass
    except Exception as e:
        print(f"Brisanje iz Authentication nije uspelo: {e}")
        raise HTTPException(status_code=500, detail="Brisanje iz Authentication nije uspelo.")

    # 2) Njegovi termini + zaključani termini (da slotovi ne ostanu zauzeti)
    appt_docs = list(db.collection('appointments').where(filter=FieldFilter('clientId', '==', body.uid)).stream())
    to_delete = []
    for d in appt_docs:
        to_delete.append(d.reference)
        to_delete.append(db.collection('busySlots').document(d.id))
        for l in db.collection('slotLocks').where(filter=FieldFilter('apptId', '==', d.id)).stream():
            to_delete.append(l.reference)

    # 3) Njegova obaveštenja, profil (users) i javni zapis
    for n in db.collection('notifications').where(filter=FieldFilter('userId', '==', body.uid)).stream():
        to_delete.append(n.reference)
    to_delete.append(ref)
    to_delete.append(db.collection('publicStaff').document(body.uid))

    count = delete_refs(to_delete)
    print(f"Admin {caller} obrisao korisnika {body.uid} ({len(appt_docs)} termina, ukupno {count} dokumenata).")
    return {"ok": True, "appointments": len(appt_docs)}


@app.post("/admin/block-user")
def admin_block_user(body: BlockBody, authorization: str = Header(None)):
    caller = require_admin(authorization)
    ref, _data = load_target_client(caller, body.uid)

    # Onemogući / vrati nalog u Authentication — blokiran korisnik se ne može ni prijaviti
    try:
        fb_auth.update_user(body.uid, disabled=body.blocked)
        if body.blocked:
            fb_auth.revoke_refresh_tokens(body.uid)  # odjavi ga i sa već otvorenih sesija
    except fb_auth.UserNotFoundError:
        pass
    except Exception as e:
        print(f"Blokiranje u Authentication nije uspelo: {e}")
        raise HTTPException(status_code=500, detail="Promena u Authentication nije uspela.")

    ref.set({
        'blocked': body.blocked,
        'blockedAt': firestore.SERVER_TIMESTAMP if body.blocked else None,
    }, merge=True)
    print(f"Admin {caller}: korisnik {body.uid} blocked={body.blocked}")
    return {"ok": True, "blocked": body.blocked}


@app.post("/admin/reset-data")
def admin_reset_data(body: ResetBody, authorization: str = Header(None)):
    caller = require_admin(authorization)
    if (body.confirm or '').strip().upper() != 'OBRISI':
        raise HTTPException(status_code=400, detail="Potvrda nije ispravna.")
    deleted = {}
    for name in ('appointments', 'notifications', 'busySlots', 'slotLocks'):
        deleted[name] = wipe_collection(name)
    print(f"Admin {caller} resetovao podatke: {deleted}")
    return {"ok": True, "deleted": deleted}


# ══════════════════════════════════════════════════════════════════════════
# REZERVACIJE — SERVER JE JEDINA ISTINA
# Klijent (browser) šalje samo: frizera, ID-jeve usluga, početak i napomenu.
# Sve ostalo server računa i proverava sam: cena, trajanje, radno vreme, slobodni
# dan, blokiran nalog, limit od 48h, preklapanje i razmak između termina.
# Upis se radi u jednoj Firestore transakciji, a klijentima je u Firestore
# pravilima ZABRANJENO da sami prave termine, busySlots i slotLocks.
# ══════════════════════════════════════════════════════════════════════════
BOOKING_BUFFER_MINUTES = 5
CELL_MS = 5 * 60 * 1000                     # mora biti isto kao CELL_MS u aplikaciji
MAX_APPTS_48H = 3
MAX_SERVICES_PER_BOOKING = 8
MAX_DAYS_AHEAD = int(os.environ.get('BOOKING_MAX_DAYS_AHEAD', '180'))
ACTIVE_STATUSES = ('pending', 'confirmed')

# Raspored frizera: svaki frizer sam unosi radno vreme po datumu (kolekcija employeeSchedules,
# dokument "<empId>_<YYYY-MM-DD>"). Radno vreme salona (workingHours) i slobodni dani (blackoutDates)
# ostaju spoljni okvir — lični raspored se SECE sa njim.
# EMPLOYEE_SCHEDULE_REQUIRED=true  -> dan bez unetog rasporeda = frizer se ne može zakazati.
# EMPLOYEE_SCHEDULE_REQUIRED=false -> dan bez unetog rasporeda = važi radno vreme salona (blaži prelaz).
SCHEDULE_MAX_DAYS_AHEAD = int(os.environ.get('SCHEDULE_MAX_DAYS_AHEAD', '14'))
EMPLOYEE_SCHEDULE_REQUIRED = os.environ.get('EMPLOYEE_SCHEDULE_REQUIRED', 'true').lower() != 'false'


class BookingError(Exception):
    def __init__(self, status, detail):
        self.status = status
        self.detail = detail


def lock_ids(emp_id, start_ms, end_ms):
    ids = []
    t = (start_ms // CELL_MS) * CELL_MS
    while t < end_ms:
        ids.append(f"{emp_id}_{t // CELL_MS}")
        t += CELL_MS
    return ids


def current_user(authorization):
    """Proverava Firebase ID token i vraća (uid, podaci iz users)."""
    if not authorization or not authorization.lower().startswith('bearer '):
        raise HTTPException(status_code=401, detail="Nedostaje prijava.")
    try:
        decoded = fb_auth.verify_id_token(authorization[7:].strip(), check_revoked=True)
    except Exception:
        raise HTTPException(status_code=401, detail="Nevažeća prijava. Prijavi se ponovo.")
    uid = decoded.get('uid')
    snap = db.collection('users').document(uid).get()
    if not snap.exists:
        raise HTTPException(status_code=403, detail="Nalog nije pronađen.")
    return uid, (snap.to_dict() or {})


def _get_all(refs, transaction):
    """db.get_all NE garantuje redosled rezultata — vraćamo ih tačno onim redom kojim su traženi."""
    found = {snap.reference.path: snap for snap in db.get_all(refs, transaction=transaction)}
    return [found.get(r.path) or r.get(transaction=transaction) for r in refs]


def _parse_hhmm(v, default):
    try:
        h, m = (v or default).split(':')
        return int(h), int(m)
    except Exception:
        h, m = default.split(':')
        return int(h), int(m)


def run_booking(transaction, caller_uid, caller, body, write):
    """Cela provera (i upis ako je write=True). Sva čitanja idu PRE upisa."""
    now = datetime.datetime.now(UTC)
    caller_role = caller.get('role', 'client')
    is_staff = caller_role in ('admin', 'employee')

    # ── ulaz ──
    ids = body.serviceIds or []
    if not ids or len(ids) > MAX_SERVICES_PER_BOOKING or len(set(ids)) != len(ids):
        raise BookingError(400, "Izaberi usluge.")
    if body.startMs % 60000 != 0:
        raise BookingError(400, "Neispravno vreme termina.")
    start = datetime.datetime.fromtimestamp(body.startMs / 1000, UTC)
    if start < now - datetime.timedelta(seconds=30):
        raise BookingError(400, "Termin je u prošlosti.")
    if start > now + datetime.timedelta(days=MAX_DAYS_AHEAD):
        raise BookingError(400, "Termin je predaleko unapred.")
    emp_id = (body.employeeId or '').strip()
    if not emp_id or emp_id == '__any__':
        raise BookingError(400, "Izaberi frizera.")

    # ── ko je klijent ──
    client_id = body.clientId or caller_uid
    if client_id != caller_uid:
        if not is_staff:
            raise BookingError(403, "Nemaš pravo da zakazuješ za drugog korisnika.")
        if caller_role == 'employee' and emp_id != caller_uid:
            raise BookingError(403, "Frizer može da zakazuje samo za sebe.")

    # ── čitanja ──
    refs = [db.collection('users').document(emp_id),
            db.collection('publicStaff').document(emp_id)]
    if client_id != caller_uid:
        refs.append(db.collection('users').document(client_id))
    svc_refs = [db.collection('services').document(i) for i in ids]
    snaps = _get_all(refs + svc_refs, transaction)
    emp_user, emp_pub = snaps[0], snaps[1]
    client_snap = snaps[2] if client_id != caller_uid else None
    svc_snaps = snaps[len(refs):]

    emp_data = (emp_user.to_dict() or {}) if emp_user.exists else {}
    if not emp_user.exists or emp_data.get('role') not in ('employee', 'admin') or not emp_pub.exists:
        raise BookingError(400, "Izabrani frizer nije dostupan.")

    client_data = caller if client_snap is None else ((client_snap.to_dict() or {}) if client_snap.exists else None)
    if client_data is None:
        raise BookingError(400, "Klijent nije pronađen.")
    if client_data.get('blocked'):
        raise BookingError(403, "Nalog je blokiran. Zakazivanje nije moguće." if client_snap is None else "Klijent je blokiran.")
    if client_snap is None and caller_role == 'client' and not (client_data.get('phone') or '').strip():
        raise BookingError(400, "Unesi broj telefona pre zakazivanja.")

    services = []
    for sn in svc_snaps:
        d = (sn.to_dict() or {}) if sn.exists else {}
        if not sn.exists or not d.get('isActive'):
            raise BookingError(400, "Jedna od usluga više nije dostupna.")
        services.append({'id': sn.id, 'name': d.get('name', ''), 'price': int(d.get('price') or 0),
                         'dur': int(d.get('durationMinutes') or 0)})
    duration = sum(x['dur'] for x in services)
    price = sum(x['price'] for x in services)
    if duration <= 0:
        raise BookingError(400, "Neispravno trajanje usluge.")
    end = start + datetime.timedelta(minutes=duration)
    start_ms, end_ms = body.startMs, int(end.timestamp() * 1000)

    # ── radno vreme i slobodni dani ──
    local = start.astimezone(TZ_LOCAL)
    dow = str((local.weekday() + 1) % 7)            # JS getDay(): nedelja = 0
    date_str = local.date().strftime('%Y-%m-%d')
    wh_snap = db.collection('workingHours').document(dow).get(transaction=transaction)
    sched_snap = db.collection('employeeSchedules').document(f"{emp_id}_{date_str}").get(transaction=transaction)
    wh = (wh_snap.to_dict() or {}) if wh_snap.exists else {}
    if wh.get('isOpen') is False:
        raise BookingError(400, "Salon je zatvoren tog dana.")
    oh, om = _parse_hhmm(wh.get('open'), '10:00')
    ch, cm = _parse_hhmm(wh.get('close'), '20:00')
    day = local.date()
    open_dt = datetime.datetime.combine(day, datetime.time(oh, om), tzinfo=TZ_LOCAL)
    close_dt = datetime.datetime.combine(day, datetime.time(ch, cm), tzinfo=TZ_LOCAL)
    sc = (sched_snap.to_dict() or {}) if sched_snap.exists else None
    if sc is None and EMPLOYEE_SCHEDULE_REQUIRED:
        raise BookingError(400, "Frizer za taj dan nije uneo radno vreme.")
    if sc is not None:
        if sc.get('off'):
            raise BookingError(400, "Frizer ne radi tog dana.")
        sh, sm = _parse_hhmm(sc.get('start'), '10:00')
        eh, em = _parse_hhmm(sc.get('end'), '20:00')
        open_dt = max(open_dt, datetime.datetime.combine(day, datetime.time(sh, sm), tzinfo=TZ_LOCAL))
        close_dt = min(close_dt, datetime.datetime.combine(day, datetime.time(eh, em), tzinfo=TZ_LOCAL))
    if start < open_dt or end > close_dt:
        raise BookingError(400, "Termin je van radnog vremena.")
    blackout = list(db.collection('blackoutDates').where(filter=FieldFilter('date', '==', date_str)).limit(1).stream(transaction=transaction))
    if blackout:
        raise BookingError(400, "Salon je tog dana zatvoren.")

    # ── limit aktivnih termina u 48h (samo za klijente) ──
    if caller_role == 'client' and client_snap is None:
        horizon = now + datetime.timedelta(hours=48)
        mine = list(db.collection('appointments').where(filter=FieldFilter('clientId', '==', client_id)).stream(transaction=transaction))
        active = 0
        for d in mine:
            a = d.to_dict() or {}
            st = a.get('startTime')
            if a.get('status') in ACTIVE_STATUSES and st is not None and now <= st <= horizon:
                active += 1
        if active >= MAX_APPTS_48H:
            raise BookingError(429, f"Maksimum {MAX_APPTS_48H} aktivnih rezervacija u 48h.")

    # ── preklapanje + razmak (ćelije i busySlots), zauzetost samo aktivnih termina ──
    buf_ms = BOOKING_BUFFER_MINUTES * 60000
    own_cells = lock_ids(emp_id, start_ms, end_ms)
    check_cells = lock_ids(emp_id, start_ms - buf_ms, end_ms + buf_ms)
    lock_snaps = _get_all([db.collection('slotLocks').document(c) for c in check_cells], transaction)
    suspects = {}                                   # apptId -> True
    for ls in lock_snaps:
        if ls.exists:
            suspects[(ls.to_dict() or {}).get('apptId') or '__none__'] = True

    win_lo = start - datetime.timedelta(hours=14)
    busy_docs = list(db.collection('busySlots')
                     .where(filter=FieldFilter('start', '>=', win_lo))
                     .where(filter=FieldFilter('start', '<=', end + datetime.timedelta(minutes=BOOKING_BUFFER_MINUTES)))
                     .stream(transaction=transaction))
    buf_td = datetime.timedelta(minutes=BOOKING_BUFFER_MINUTES)
    for bd in busy_docs:
        b = bd.to_dict() or {}
        if b.get('empId') != emp_id or not b.get('start') or not b.get('end'):
            continue
        if start < b['end'] + buf_td and end > b['start'] - buf_td:
            suspects[b.get('apptId') or bd.id] = True

    for appt_id in list(suspects.keys()):
        if appt_id == '__none__':
            raise BookingError(409, "SLOT_TAKEN")   # zaključana ćelija bez termina — tretiramo kao zauzeto
    if suspects:
        appt_snaps = _get_all([db.collection('appointments').document(i) for i in suspects], transaction)
        for sn in appt_snaps:
            # zaostali zapis otkazanog/obrisanog termina se ignoriše (i prepisuje); aktivan termin = zauzeto
            if not sn.exists:
                continue
            a = sn.to_dict() or {}
            if a.get('status') not in ACTIVE_STATUSES:
                continue
            a_s, a_e = a.get('startTime'), a.get('endTime')
            # Ćelije su zaokružene na 5 min pa mogu da "zahvate" sused koji se stvarno ne preklapa — proveravamo tačno.
            if a_s is not None and a_e is not None and not (start < a_e + buf_td and end > a_s - buf_td):
                continue
            print(f"SLOT_TAKEN: frizer {emp_id}, traženo {start.isoformat()}–{end.isoformat()}, sukob sa terminom {sn.id} ({a_s}–{a_e}, status {a.get('status')})")
            raise BookingError(409, "SLOT_TAKEN")

    result = {"ok": True, "free": True, "durationMinutes": duration, "price": price,
              "startMs": start_ms, "endMs": end_ms}
    if not write:
        return result

    # ── upis (u istoj transakciji) ──
    note = ''.join(ch for ch in str(body.note or '') if ch >= ' ' or ch == '\n').strip()[:200]
    appt_ref = db.collection('appointments').document()
    emp_pub_data = emp_pub.to_dict() or {}
    transaction.set(appt_ref, {
        'id': appt_ref.id,
        'clientId': client_id,
        'clientName': (client_data.get('name') or '').strip(),
        'clientPhone': (client_data.get('phone') or '').strip(),
        'clientAvatarUrl': client_data.get('avatarUrl'),
        'employeeId': emp_id,
        'employeeName': emp_pub_data.get('name') or emp_data.get('name') or '',
        'employeeAvatarUrl': emp_pub_data.get('avatarUrl') or emp_data.get('avatarUrl'),
        'serviceId': services[0]['id'],
        'serviceName': ' + '.join(x['name'] for x in services),
        'serviceDuration': duration,
        'price': price,
        'startTime': start,
        'endTime': end,
        'status': 'confirmed',
        'notes': note,
        'createdAt': firestore.SERVER_TIMESTAMP,
        'sent_2h': False, 'sent_1h': False, 'sent_30min': False,
        'createdBy': caller_uid,
    })
    transaction.set(db.collection('busySlots').document(appt_ref.id), {
        'empId': emp_id, 'clientId': client_id, 'apptId': appt_ref.id, 'start': start, 'end': end})
    for cid in own_cells:
        transaction.set(db.collection('slotLocks').document(cid), {
            'empId': emp_id, 'clientId': client_id, 'apptId': appt_ref.id, 'start': start})
    result['id'] = appt_ref.id
    return result


@firestore.transactional
def _book_txn(transaction, caller_uid, caller, body):
    return run_booking(transaction, caller_uid, caller, body, write=True)


class BookBody(BaseModel):
    employeeId: str
    serviceIds: List[str]
    startMs: int
    note: Optional[str] = ''
    clientId: Optional[str] = None


@app.post("/book")
def api_book(body: BookBody, authorization: str = Header(None)):
    uid, caller = current_user(authorization)
    try:
        res = _book_txn(db.transaction(), uid, caller, body)
    except BookingError as e:
        raise HTTPException(status_code=e.status, detail=e.detail)
    print(f"Rezervacija {res.get('id')} ({uid} -> {body.employeeId}, {len(body.serviceIds)} usl.)")
    return res


@app.post("/book/check")
def api_book_check(body: BookBody, authorization: str = Header(None)):
    """Ista provera kao /book, ali bez upisa — za UI (npr. da li dodatna usluga još staje)."""
    uid, caller = current_user(authorization)
    try:
        return run_booking(None, uid, caller, body, write=False)
    except BookingError as e:
        raise HTTPException(status_code=e.status, detail=e.detail)


# ──────────────────────────────────────────────
# RASPORED FRIZERA — frizer sam unosi radno vreme za narednih SCHEDULE_MAX_DAYS_AHEAD dana.
# Ide preko servera (a ne direktno u Firestore) da bismo proverili:
#  - format i opseg datuma, start < end, korak od 5 min
#  - da se uklapa u radno vreme salona
#  - da frizer ne "skrati" dan preko već zakazanih termina
# ──────────────────────────────────────────────
class DayEntry(BaseModel):
    date: str                       # YYYY-MM-DD
    off: bool = False               # true = ne radim taj dan
    start: Optional[str] = None     # "HH:MM"
    end: Optional[str] = None


class ScheduleBody(BaseModel):
    days: List[DayEntry]
    employeeId: Optional[str] = None    # samo admin može da menja tuđi raspored


def _hhmm_strict(v):
    try:
        h, m = str(v).split(':')
        h, m = int(h), int(m)
        if 0 <= h <= 23 and 0 <= m <= 59 and m % 5 == 0:
            return h, m
    except Exception:
        pass
    return None


@app.post("/schedule/set")
def api_schedule_set(body: ScheduleBody, authorization: str = Header(None)):
    uid, caller = current_user(authorization)
    role = caller.get('role', 'client')
    if role not in ('employee', 'admin'):
        raise HTTPException(status_code=403, detail="Samo frizer može da podešava radno vreme.")
    emp_id = body.employeeId or uid
    if emp_id != uid and role != 'admin':
        raise HTTPException(status_code=403, detail="Možeš da menjaš samo svoj raspored.")
    if not body.days or len(body.days) > 31:
        raise HTTPException(status_code=400, detail="Nema dana za čuvanje.")

    today = datetime.datetime.now(TZ_LOCAL).date()
    last_day = today + datetime.timedelta(days=SCHEDULE_MAX_DAYS_AHEAD - 1)
    writes = []
    for e in body.days:
        try:
            day = datetime.date.fromisoformat(e.date)
        except Exception:
            raise HTTPException(status_code=400, detail=f"Neispravan datum: {e.date}")
        label = day.strftime('%d.%m.')
        if day < today or day > last_day:
            raise HTTPException(status_code=400, detail=f"{label} je van dozvoljenog perioda (narednih {SCHEDULE_MAX_DAYS_AHEAD} dana).")
        doc = {'empId': emp_id, 'date': e.date, 'off': bool(e.off), 'updatedAt': firestore.SERVER_TIMESTAMP}
        if e.off:
            doc.update({'start': None, 'end': None})
            new_lo = new_hi = None
        else:
            s_, e_ = _hhmm_strict(e.start), _hhmm_strict(e.end)
            if not s_ or not e_:
                raise HTTPException(status_code=400, detail=f"{label}: vreme mora biti u formatu HH:MM (korak 5 min).")
            if s_ >= e_:
                raise HTTPException(status_code=400, detail=f"{label}: kraj mora biti posle početka.")
            dow = str((day.weekday() + 1) % 7)
            wh = (db.collection('workingHours').document(dow).get().to_dict() or {})
            if wh.get('isOpen') is False:
                raise HTTPException(status_code=400, detail=f"{label}: salon je zatvoren tog dana.")
            so, eo = _parse_hhmm(wh.get('open'), '10:00'), _parse_hhmm(wh.get('close'), '20:00')
            if s_ < so or e_ > eo:
                raise HTTPException(status_code=400, detail=f"{label}: salon radi {so[0]:02d}:{so[1]:02d}–{eo[0]:02d}:{eo[1]:02d}, unesi vreme u tom okviru.")
            doc.update({'start': f"{s_[0]:02d}:{s_[1]:02d}", 'end': f"{e_[0]:02d}:{e_[1]:02d}"})
            new_lo = datetime.datetime.combine(day, datetime.time(*s_), tzinfo=TZ_LOCAL)
            new_hi = datetime.datetime.combine(day, datetime.time(*e_), tzinfo=TZ_LOCAL)

        # postojeći aktivni termini tog dana moraju ostati unutar novog radnog vremena
        d0 = datetime.datetime.combine(day, datetime.time(0, 0), tzinfo=TZ_LOCAL)
        d1 = d0 + datetime.timedelta(days=1)
        clash = []
        for b in db.collection('busySlots') \
                .where(filter=FieldFilter('start', '>=', d0)) \
                .where(filter=FieldFilter('start', '<', d1)).stream():
            bd = b.to_dict() or {}
            if bd.get('empId') != emp_id or not bd.get('start') or not bd.get('end'):
                continue
            if new_lo is None or bd['start'] < new_lo or bd['end'] > new_hi:
                clash.append(to_local(bd['start']).strftime('%H:%M'))
        if clash:
            raise HTTPException(status_code=409,
                detail=f"{label}: imaš zakazane termine ({', '.join(sorted(clash))}) koji ne staju u novo radno vreme. Prvo ih otkaži ili proširi radno vreme.")
        writes.append((db.collection('employeeSchedules').document(f"{emp_id}_{e.date}"), doc))

    batch = db.batch()
    for ref, doc in writes:
        batch.set(ref, doc)
    batch.commit()
    print(f"Raspored: {emp_id} ažurirao {len(writes)} dana (poziva {uid})")
    return {"ok": True, "saved": len(writes)}


@app.get("/push/ack")
def push_ack(stage: str = "", v: str = "", clients: str = "", visible: str = "", shown: str = "", err: str = "", ua: str = ""):
    """DIJAGNOSTIKA: service worker javlja šta je uradio sa push-om. Samo piše u log (skrati i očisti tekst)."""
    c = lambda x: str(x)[:120].replace('\n', ' ').replace('\r', ' ')
    print(f"PUSH ACK stage={c(stage)} v={c(v)} clients={c(clients)} visible={c(visible)} shown={c(shown)} err={c(err)} ua={c(ua)}")
    return {"ok": True}


class PushTestBody(BaseModel):
    delay: int = 10


@app.post("/push/test")
def api_push_test(body: PushTestBody, authorization: str = Header(None)):
    """Šalje probno obaveštenje na sve sačuvane uređaje ulogovanog korisnika (posle 'delay' sekundi,
    da stigneš da zaključaš telefon ili izađeš iz aplikacije). Rezultat slanja piše u Render log."""
    uid, user = current_user(authorization)
    tokens = collect_tokens(user)
    if not tokens:
        raise HTTPException(status_code=400, detail="Nema sačuvanog uređaja za obaveštenja. Dozvoli obaveštenja i otvori aplikaciju.")
    delay = max(0, min(30, int(body.delay)))

    def _run():
        time.sleep(delay)
        ref = db.collection('users').document(uid)
        for tok, field in tokens.items():
            print(f"PUSH TEST → {uid} / {field}")
            send_fcm_notification(tok, "Probno obaveštenje", "Ako ovo vidiš u traci, obaveštenja rade.", f"test-{int(time.time())}", ref, field)

    threading.Thread(target=_run, daemon=True).start()
    return {"ok": True, "devices": len(tokens), "delay": delay}


class CancelBody(BaseModel):
    apptId: str


@app.post("/cancel")
def api_cancel(body: CancelBody, authorization: str = Header(None)):
    uid, caller = current_user(authorization)
    ref = db.collection('appointments').document(body.apptId)
    snap = ref.get()
    if not snap.exists:
        raise HTTPException(status_code=404, detail="Termin ne postoji.")
    a = snap.to_dict() or {}
    role = caller.get('role', 'client')
    if not (role == 'admin' or a.get('clientId') == uid or a.get('employeeId') == uid):
        raise HTTPException(status_code=403, detail="Nemaš pravo da otkažeš ovaj termin.")
    if a.get('status') not in ACTIVE_STATUSES:
        raise HTTPException(status_code=400, detail="Termin se više ne može otkazati.")
    st = a.get('startTime')
    if role == 'client' and st is not None and st < datetime.datetime.now(UTC):
        raise HTTPException(status_code=400, detail="Termin je već počeo.")

    refs = {}
    st_ms = int(st.timestamp() * 1000) if st else None
    en = a.get('endTime')
    en_ms = int(en.timestamp() * 1000) if en else None
    if a.get('employeeId') and st_ms is not None and en_ms is not None:
        for c in lock_ids(a['employeeId'], st_ms, en_ms):
            refs[c] = db.collection('slotLocks').document(c)
    for l in db.collection('slotLocks').where(filter=FieldFilter('apptId', '==', body.apptId)).stream():
        refs[l.id] = l.reference

    batch = db.batch()
    batch.update(ref, {'status': 'cancelled', 'updatedAt': firestore.SERVER_TIMESTAMP, 'cancelledBy': uid})
    batch.delete(db.collection('busySlots').document(body.apptId))
    for r in refs.values():
        batch.delete(r)
    batch.commit()
    print(f"Termin {body.apptId} otkazao {uid}")
    return {"ok": True}


def autocomplete_past():
    """Termini kojima je prošao kraj postaju 'completed' (ranije je to radio browser)."""
    try:
        now = datetime.datetime.now(UTC)
        q = db.collection('appointments') \
            .where(filter=FieldFilter('endTime', '>=', now - datetime.timedelta(days=7))) \
            .where(filter=FieldFilter('endTime', '<', now))
        n = 0
        for d in q.stream():
            if (d.to_dict() or {}).get('status') in ACTIVE_STATUSES:
                d.reference.update({'status': 'completed', 'updatedAt': firestore.SERVER_TIMESTAMP})
                n += 1
        if n:
            print(f"Automatski završeno {n} termina.")
    except Exception as e:
        print(f"Greška pri automatskom završavanju: {e}")


def first_name(full_name, default='Klijent'):
    parts = (full_name or '').strip().split()
    return parts[0] if parts else default


def to_local(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC).astimezone(TZ_LOCAL)
    return dt.astimezone(TZ_LOCAL)


# ──────────────────────────────────────────────
# SLANJE — data-only payload (jedan prikaz, kontroliše ga service worker),
# TTL da zakasneli push ne stigne posle termina, i pravo rukovanje mrtvim tokenima.
# Vraća True ako je "obrađeno" (poslato ili token mrtav), False ako treba ponoviti.
# ──────────────────────────────────────────────
def send_fcm_notification(token, title, body, tag, user_ref=None, token_field=None, url='/'):
    if not token:
        return True

    message = messaging.Message(
        data={
            'title': title,
            'body': body,
            'tag': tag,
            'url': url,
        },
        android=messaging.AndroidConfig(
            priority='high',
            ttl=datetime.timedelta(seconds=PUSH_TTL_SECONDS),
        ),
        webpush=messaging.WebpushConfig(
            headers={'Urgency': 'high', 'TTL': str(PUSH_TTL_SECONDS)},
        ),
        token=token,
    )
    try:
        messaging.send(message)
        print(f"Notifikacija poslata: {title} [{tag}]")
        return True
    except DEAD_TOKEN_ERRORS as e:
        print(f"Mrtav token ({type(e).__name__}) — brišem iz Firestore-a.")
        if user_ref is not None and token_field is not None:
            try:
                user_ref.update({token_field: firestore.DELETE_FIELD})
            except Exception as ce:
                print(f"Nisam uspeo da obrišem token: {ce}")
        return True
    except QuotaExceededError as e:
        print(f"Kvota prekoračena, pokušaću ponovo kasnije: {e}")
        return False
    except Exception as e:
        print(f"Greška pri slanju: {e}")
        return False


# ──────────────────────────────────────────────
# ATOMSKI "CLAIM" — samo jedna instanca/transakcija može da postavi flag.
# release_flag() vraća flag na False kad slanje ne uspe, da se pokuša ponovo.
# ──────────────────────────────────────────────
@firestore.transactional
def _claim_transaction(transaction, appt_ref, flag_field):
    snap = appt_ref.get(transaction=transaction)
    if not snap.exists:
        return False
    data = snap.to_dict() or {}
    if data.get(flag_field):
        return False
    transaction.update(appt_ref, {flag_field: True})
    return True


def claim_reminder(appt_ref, flag_field):
    transaction = db.transaction()
    return _claim_transaction(transaction, appt_ref, flag_field)


def release_flag(appt_ref, flag_field):
    try:
        appt_ref.update({flag_field: False})
        print(f"Slanje nije uspelo — flag '{flag_field}' vraćen, pokušaću ponovo.")
    except Exception as e:
        print(f"Nisam uspeo da vratim flag '{flag_field}': {e}")


# ──────────────────────────────────────────────
# ISTORIJA OBAVEŠTENJA (zvono u aplikaciji). ID dokumenta je određen unapred
# (npr. "<termin>_reminder_1h"), pa je upis idempotentan — ponovljen pokušaj
# slanja nikad ne pravi duplikat u zvoncu.
# ──────────────────────────────────────────────
def create_notification(user_id, title, body, appointment_id=None, ntype='info', doc_id=None):
    data = {
        'userId': user_id,
        'title': title,
        'body': body,
        'appointmentId': appointment_id,
        'type': ntype,
        'read': False,
        'createdAt': firestore.SERVER_TIMESTAMP,
    }
    try:
        if doc_id:
            db.collection('notifications').document(doc_id).set(data)
        else:
            db.collection('notifications').add(data)
    except Exception as e:
        print(f"Nisam uspeo da upišem notifikaciju u istoriju: {e}")


def collect_tokens(user_data):
    """Svi tokeni korisnika (po uređaju: fcmTokens.<id>, plus stara polja) → {token: putanja polja}. Bez duplikata."""
    out = {}
    for dev, t in (user_data.get('fcmTokens') or {}).items():
        if t:
            out.setdefault(t, f'fcmTokens.{dev}')
    for field in ('fcmToken', 'fcmTokenWeb'):
        t = user_data.get(field)
        if t:
            out.setdefault(t, field)
    return out


def send_to_all(user_data, user_ref, title, body, tag):
    ok = False
    toks = collect_tokens(user_data)
    print(f"PUSH [{tag}] → {len(toks)} uređaja: {', '.join(toks.values()) or '—'}")
    for token, field in toks.items():
        ok = send_fcm_notification(token, title, body, tag, user_ref, field) or ok
    return ok


def has_push_token(user_data):
    return bool(collect_tokens(user_data))


# ──────────────────────────────────────────────
# PODSETNICI KLIJENTIMA (2h / 1h / 30min)
# Čita SAMO termine koji počinju u narednih ~125 min (ne sve "confirmed").
# Upit koristi samo jedno polje (startTime) → ne treba composite index;
# status se proverava u kodu.
# ──────────────────────────────────────────────
def process_reminders():
    now = datetime.datetime.now(UTC)
    window_start = now - datetime.timedelta(minutes=5)
    window_end = now + datetime.timedelta(minutes=125)

    docs = db.collection('appointments') \
        .where(filter=FieldFilter('startTime', '>=', window_start)) \
        .where(filter=FieldFilter('startTime', '<=', window_end)) \
        .stream()

    users_cache = {}

    def get_user(uid):
        if uid not in users_cache:
            ref = db.collection('users').document(uid)
            snap = ref.get()
            users_cache[uid] = (ref, snap.to_dict() or {}) if snap.exists else (None, None)
        return users_cache[uid]

    for doc in docs:
        appt = doc.to_dict() or {}
        if appt.get('status') != 'confirmed':
            continue

        start = appt.get('startTime')
        client_id = appt.get('clientId')
        if not start or not client_id:
            continue
        if start.tzinfo is None:
            start = start.replace(tzinfo=UTC)

        diff_minutes = (start - now).total_seconds() / 60

        reminder = next((r for r in REMINDERS
                         if r['min'] <= diff_minutes <= r['max'] and not appt.get(r['flag'])), None)
        if not reminder:
            continue

        appt_id = doc.id
        appt_ref = doc.reference
        flag = reminder['flag']

        # Termin zakazan tek unutar praga (npr. 40 min unapred) → podsetnik "za 2h" nema smisla.
        created = appt.get('createdAt')
        if created is not None:
            if created.tzinfo is None:
                created = created.replace(tzinfo=UTC)
            if created > start - datetime.timedelta(minutes=reminder['threshold']):
                claim_reminder(appt_ref, flag)  # samo označi, bez slanja
                continue

        user_ref, user_data = get_user(client_id)
        if user_data is None:
            continue

        if not claim_reminder(appt_ref, flag):
            continue

        name = first_name(user_data.get('name'))
        hhmm = to_local(start).strftime('%H:%M')
        emp = appt.get('employeeName')
        kod = f" kod {emp}" if emp else ""

        if flag == 'sent_2h':
            title, body = "Vidimo se uskoro!", f"Zdravo {name}, termin ti je za 2 sata ({hhmm})."
        elif flag == 'sent_1h':
            title, body = "Još sat vremena!", f"{name}, tvoj termin{kod} je za 1 sat ({hhmm})."
        else:
            title, body = "Skoro je vreme!", f"{name}, vidimo se u salonu za 30 minuta ({hhmm})!"

        # Istorija (zvono) — uvek, idempotentno
        create_notification(client_id, title, body, appt_id, reminder['type'],
                            doc_id=f"{appt_id}_{reminder['type']}")

        if has_push_token(user_data):
            ok = send_to_all(user_data, user_ref, title, body, tag=f"appt-{appt_id}-{flag}")
            if not ok:
                release_flag(appt_ref, flag)   # pokušaj ponovo u sledećem krugu
        else:
            print(f"Korisnik {name} nema FCM token — upisano samo u istoriju.")


# ──────────────────────────────────────────────
# ČIŠĆENJE stare istorije obaveštenja (jednom na sat)
# ──────────────────────────────────────────────
def cleanup_old_notifications():
    try:
        cutoff = datetime.datetime.now(UTC) - datetime.timedelta(days=NOTIF_KEEP_DAYS)
        old = db.collection('notifications') \
            .where(filter=FieldFilter('createdAt', '<', cutoff)) \
            .limit(400).stream()
        batch = db.batch()
        n = 0
        for d in old:
            batch.delete(d.reference)
            n += 1
        if n:
            batch.commit()
            print(f"Obrisano {n} starih obaveštenja.")
    except Exception as e:
        print(f"Greška pri čišćenju obaveštenja: {e}")


def cleanup_old_schedules():
    try:
        cutoff = (datetime.datetime.now(TZ_LOCAL).date() - datetime.timedelta(days=7)).strftime('%Y-%m-%d')
        old = list(db.collection('employeeSchedules').where(filter=FieldFilter('date', '<', cutoff)).limit(400).stream())
        if old:
            delete_refs(d.reference for d in old)
            print(f"Obrisano {len(old)} starih zapisa rasporeda.")
    except Exception as e:
        print(f"Greška pri čišćenju rasporeda: {e}")


def check_appointments_loop():
    print("Servis za podsetnike pokrenut (Europe/Belgrade)...")
    last_cleanup = 0.0
    last_complete = 0.0

    while True:
        started = time.time()
        try:
            process_reminders()
            if started - last_complete > 300:
                autocomplete_past()
                last_complete = started
            if started - last_cleanup > 3600:
                cleanup_old_notifications()
                cleanup_old_schedules()
                last_cleanup = started
        except Exception as e:
            print(f"Greška u glavnom loopu: {e}")
        time.sleep(max(5, 60 - (time.time() - started)))


# ──────────────────────────────────────────────
# REAL-TIME: nova rezervacija → frizeru, otkazivanje → frizeru i klijentu.
# Pratimo samo buduće termine. Prvi snapshot se NE preskače (da restart servisa
# ne proguta rezervaciju), već se stare rezervacije filtriraju po createdAt;
# claim flag garantuje da se šalje najviše jednom.
# ──────────────────────────────────────────────
def notify_user(user_id, title, body, appt_id, ntype, doc_id, tag):
    user_ref = db.collection('users').document(user_id)
    snap = user_ref.get()
    if not snap.exists:
        return
    user_data = snap.to_dict() or {}
    create_notification(user_id, title, body, appt_id, ntype, doc_id=doc_id)
    if has_push_token(user_data):
        send_to_all(user_data, user_ref, title, body, tag=tag)
    else:
        print(f"{user_data.get('name')} nema FCM token — samo istorija upisana.")


def handle_new_appointment(doc):
    appt = doc.to_dict() or {}
    if appt.get('employeeNotified'):
        return
    if appt.get('status') not in ('confirmed', 'pending'):
        return

    created = appt.get('createdAt')
    if created is not None:
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        if (datetime.datetime.now(UTC) - created).total_seconds() > NEW_APPT_MAX_AGE_SECONDS:
            return  # stara rezervacija (npr. iz početnog snapshot-a)

    employee_id = appt.get('employeeId')
    if not employee_id or employee_id == '__any__':
        return
    if not claim_reminder(doc.reference, 'employeeNotified'):
        return

    start = to_local(appt.get('startTime'))
    when = start.strftime('%d.%m. u %H:%M') if start else 'nepoznato vreme'
    title = "Nova rezervacija!"
    body = f"{appt.get('clientName', 'Klijent')} je zakazao/la '{appt.get('serviceName', 'Usluga')}' — {when}."
    note = (appt.get('notes') or '').strip()
    if note:
        body += f" Napomena: {note[:120]}"

    notify_user(employee_id, title, body, doc.id, 'new_appointment',
                doc_id=f"{doc.id}_new_appointment", tag=f"new-appt-{doc.id}")
    print(f"Frizer {employee_id} obavešten o novom terminu {doc.id}")


def handle_cancelled_appointment(doc):
    appt = doc.to_dict() or {}
    if appt.get('status') != 'cancelled' or appt.get('cancelNotified'):
        return
    if not claim_reminder(doc.reference, 'cancelNotified'):
        return

    start = to_local(appt.get('startTime'))
    when = start.strftime('%d.%m. u %H:%M') if start else 'nepoznato vreme'
    service = appt.get('serviceName', 'Usluga')

    by = appt.get('cancelledBy')
    employee_id = appt.get('employeeId')
    client_id = appt.get('clientId')

    # Obaveštavamo "drugu stranu": ako je otkazao klijent → frizeru; ako je otkazao frizer → klijentu;
    # admin (ili nepoznato) → obojici.
    if employee_id and employee_id != '__any__' and by != employee_id:
        notify_user(employee_id, "Termin otkazan",
                    f"Termin klijenta {appt.get('clientName', 'Klijent')} ('{service}') — {when} je otkazan.",
                    doc.id, 'cancelled', doc_id=f"{doc.id}_cancelled_emp", tag=f"cancel-emp-{doc.id}")

    if client_id and by != client_id:
        notify_user(client_id, "Termin otkazan",
                    f"Tvoj termin za '{service}' — {when} je otkazan.",
                    doc.id, 'cancelled', doc_id=f"{doc.id}_cancelled_client", tag=f"cancel-client-{doc.id}")


def start_watcher():
    def on_snapshot(col_snapshot, changes, read_time):
        try:
            for change in changes:
                try:
                    kind = change.type.name
                    if kind == 'ADDED':
                        handle_new_appointment(change.document)
                    elif kind == 'MODIFIED':
                        handle_cancelled_appointment(change.document)
                except Exception as inner_e:
                    print(f"Greška pri obradi promene ({getattr(change.document, 'id', '?')}): {inner_e}")
        except Exception as outer_e:
            print(f"Greška u on_snapshot callback-u: {outer_e}")

    q = db.collection('appointments') \
        .where(filter=FieldFilter('startTime', '>=', datetime.datetime.now(UTC)))
    return q.on_snapshot(on_snapshot)


def watch_appointments():
    print("Osluškujem nove i otkazane rezervacije...")
    while True:
        watch = None
        try:
            watch = start_watcher()
        except Exception as e:
            print(f"Greška pri pokretanju listenera: {e}")
        # Obnavljamo listener na 6h — ako je veza tiho umrla, ovo ga vraća u život.
        # Bezbedno je jer claim flagovi sprečavaju duplo slanje.
        time.sleep(6 * 3600 if watch else 30)
        try:
            if watch:
                watch.unsubscribe()
        except Exception:
            pass


# Pokretanje pozadinskih thread-ova
threading.Thread(target=check_appointments_loop, daemon=True).start()
threading.Thread(target=watch_appointments, daemon=True).start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)