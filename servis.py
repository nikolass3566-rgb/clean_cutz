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


@app.get("/")
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


def send_to_all(user_data, user_ref, title, body, tag):
    token = user_data.get('fcmToken')
    token_web = user_data.get('fcmTokenWeb')
    ok = False
    if token:
        ok = send_fcm_notification(token, title, body, tag, user_ref, 'fcmToken') or ok
    if token_web and token_web != token:
        ok = send_fcm_notification(token_web, title, body, tag, user_ref, 'fcmTokenWeb') or ok
    return ok


def has_push_token(user_data):
    return bool(user_data.get('fcmToken') or user_data.get('fcmTokenWeb'))


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


def check_appointments_loop():
    print("Servis za podsetnike pokrenut (Europe/Belgrade)...")
    last_cleanup = 0.0

    while True:
        started = time.time()
        try:
            process_reminders()
            if started - last_cleanup > 3600:
                cleanup_old_notifications()
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

    employee_id = appt.get('employeeId')
    if employee_id and employee_id != '__any__':
        notify_user(employee_id, "Termin otkazan",
                    f"Termin klijenta {appt.get('clientName', 'Klijent')} ('{service}') — {when} je otkazan.",
                    doc.id, 'cancelled', doc_id=f"{doc.id}_cancelled_emp", tag=f"cancel-emp-{doc.id}")

    client_id = appt.get('clientId')
    if client_id:
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