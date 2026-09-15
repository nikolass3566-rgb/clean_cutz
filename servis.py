import firebase_admin
from firebase_admin import credentials, messaging, firestore
from firebase_admin.messaging import UnregisteredError, SenderIdMismatchError, ThirdPartyAuthError, QuotaExceededError
from google.cloud.firestore_v1.base_query import FieldFilter
from google.cloud import firestore as gcf
import datetime
import time
import threading
import os
import uvicorn
from fastapi import FastAPI
import json

# --- INICIJALIZACIJA ---
app = FastAPI()

firebase_config = os.environ.get('FIREBASE_CONFIG')

if firebase_config:
    cred_dict = json.loads(firebase_config)
    cred = credentials.Certificate(cred_dict)
else:
    cred = credentials.Certificate("serviceAccountKey.json")

firebase_admin.initialize_app(cred)
db = firestore.client()

OFFSET = datetime.timedelta(hours=2)
TZ_LOCAL = datetime.timezone(OFFSET)

# Tipovi grešaka koji znače "token je mrtav, obriši ga" — hvatamo prave Firebase exception klase,
# ne string-matching, jer se poruke greške razlikuju između verzija SDK-a.
DEAD_TOKEN_ERRORS = (UnregisteredError, SenderIdMismatchError, ThirdPartyAuthError)

@app.get("/")
def health_check():
    return {"status": "online", "timezone": "UTC+2"}


# ──────────────────────────────────────────────
# SLANJE — sa webpush tag-om (kolapsira duplikate sa istog origina, čak i ako
# stignu iz više otvorenih tabova/PWA prozora u isto vreme) i pravim rukovanjem
# mrtvim tokenima.
# ──────────────────────────────────────────────
def send_fcm_notification(token, title, body, tag, user_ref=None, token_field=None, url='/'):
    if not token:
        return True

    # VAŽNO: šaljemo ISKLJUČIVO "data" payload, bez "notification" ključa.
    # Ako poruka sadrži "notification" polje, browser je AUTOMATSKI prikaže
    # čim stigne push event — pre nego što naš service-worker kod uopšte
    # stigne do reči. Kombinovano sa self-registrovanim 'push' listenerom
    # i/ili onBackgroundMessage-om u service workeru, to je davalo 2-3
    # notifikacije za JEDNU poruku. Sa data-only porukom, PRIKAZ u potpunosti
    # kontroliše naš JS kod u firebase-messaging-sw.js (samo onBackgroundMessage) —
    # tačno jedan put prikaza.
    message = messaging.Message(
        data={
            'title': title,
            'body': body,
            'tag': tag,
            'url': url,
        },
        android=messaging.AndroidConfig(priority='high'),
        webpush=messaging.WebpushConfig(headers={'Urgency': 'high'}),
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
        return True  # tretiramo kao "obrađeno" da ne blokira reminder flag zauvek
    except QuotaExceededError as e:
        print(f"Kvota prekoračena, pokušaću ponovo kasnije: {e}")
        return False
    except Exception as e:
        print(f"Greška pri slanju: {e}")
        return False


# ──────────────────────────────────────────────
# ATOMSKI "CLAIM" — sprečava duple pošiljke čak i ako dve instance servisa
# (npr. preklapanje tokom redeploy-a) rade istovremeno. Samo jedna transakcija
# uspe da postavi flag na True; druga vidi da je flag već True i odustaje.
# ──────────────────────────────────────────────
@firestore.transactional
def _claim_transaction(transaction, appt_ref, flag_field):
    snap = appt_ref.get(transaction=transaction)
    if not snap.exists:
        return False
    if snap.get(flag_field):
        return False  # neko drugi je već zauzeo ovaj reminder
    transaction.update(appt_ref, {flag_field: True})
    return True

def claim_reminder(appt_ref, flag_field):
    transaction = db.transaction()
    return _claim_transaction(transaction, appt_ref, flag_field)


# ──────────────────────────────────────────────
# ISTORIJA OBAVEŠTENJA (zvono u aplikaciji) — upisujemo je UVEK, nezavisno od
# toga da li push uspe da stigne na uređaj. Tako zaposleni (i klijent) uvek
# imaju trag ko je i kada zakazao, čak i ako je notifikacija sa uređaja nestala,
# telefon bio ugašen, ili korisnik uopšte nije uključio push.
# ──────────────────────────────────────────────
def create_notification(user_id, title, body, appointment_id=None, ntype='info'):
    try:
        db.collection('notifications').add({
            'userId': user_id,
            'title': title,
            'body': body,
            'appointmentId': appointment_id,
            'type': ntype,
            'read': False,
            'createdAt': firestore.SERVER_TIMESTAMP,
        })
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


# --- GLAVNI LOOP: podsetnici pre termina ---
def check_appointments_loop():
    print("Servis za podsetnike pokrenut u UTC+2 zoni...")

    while True:
        try:
            now = datetime.datetime.now(TZ_LOCAL)
            print(f"Provera termina (Lokalno): {now.strftime('%H:%M:%S')}")

            appointments = db.collection('appointments')\
                .where(filter=FieldFilter('status', '==', 'confirmed'))\
                .stream()

            for doc in appointments:
                appt = doc.to_dict()
                appt_id = doc.id
                start_time = appt.get('startTime')
                if not start_time:
                    continue

                if start_time.tzinfo is None:
                    start_time = start_time.replace(tzinfo=TZ_LOCAL)
                else:
                    start_time = start_time.astimezone(TZ_LOCAL)

                diff_minutes = (start_time - now).total_seconds() / 60
                if diff_minutes < -5:
                    continue

                client_id = appt.get('clientId')
                if not client_id:
                    continue

                user_ref = db.collection('users').document(client_id)
                user_doc = user_ref.get()
                if not user_doc.exists:
                    continue
                user_data = user_doc.to_dict()
                user_name = user_data.get('name', 'Klijent')
                has_token = bool(user_data.get('fcmToken') or user_data.get('fcmTokenWeb'))
                if not has_token:
                    print(f"Korisnik {user_name} nema FCM token — upisujem samo u istoriju, bez push-a.")

                appt_ref = db.collection('appointments').document(appt_id)

                # 2 SATA
                if 119 <= diff_minutes <= 121 and not appt.get('sent_2h'):
                    if claim_reminder(appt_ref, 'sent_2h'):
                        title, body = "Vidimo se uskoro!", f"Zdravo {user_name}, termin ti je za 2 sata."
                        create_notification(client_id, title, body, appt_id, 'reminder_2h')
                        if has_token:
                            send_to_all(user_data, user_ref, title, body, tag=f"appt-{appt_id}-2h")

                # 1 SAT
                elif 59 <= diff_minutes <= 61 and not appt.get('sent_1h'):
                    if claim_reminder(appt_ref, 'sent_1h'):
                        title, body = "Još sat vremena!", f"{user_name}, tvoj termin kod {appt.get('employeeName')} je za 1h."
                        create_notification(client_id, title, body, appt_id, 'reminder_1h')
                        if has_token:
                            send_to_all(user_data, user_ref, title, body, tag=f"appt-{appt_id}-1h")

                # 30 MINUTA
                elif 29 <= diff_minutes <= 31 and not appt.get('sent_30min'):
                    if claim_reminder(appt_ref, 'sent_30min'):
                        title, body = "Skoro je vreme!", f"{user_name}, vidimo se u salonu za 30 minuta!"
                        create_notification(client_id, title, body, appt_id, 'reminder_30min')
                        if has_token:
                            send_to_all(user_data, user_ref, title, body, tag=f"appt-{appt_id}-30min")

            time.sleep(60)

        except Exception as e:
            print(f"Greška u glavnom loopu: {e}")
            time.sleep(30)


# ──────────────────────────────────────────────
# NOVO: trenutno obaveštenje ZAPOSLENOM kada klijent (ili admin u njegovo ime)
# zakaže novi termin — real-time Firestore listener, ne čeka 60s petlju.
# Preskačemo prvi "snapshot" (sadrži SVE postojeće dokumente kao ADDED) da ne
# bismo bombardovali zaposlene starim terminima pri svakom restartu servisa.
# ──────────────────────────────────────────────
_first_snapshot_done = {'flag': False}

def watch_new_appointments():
    print("Osluškujem nove rezervacije za obaveštenja zaposlenima...")

    def on_snapshot(col_snapshot, changes, read_time):
        if not _first_snapshot_done['flag']:
            # Ovo je inicijalni snapshot pri pokretanju — sadrži sve postojeće
            # dokumente kao "ADDED". Preskačemo ga da ne šaljemo staru istoriju.
            _first_snapshot_done['flag'] = True
            return

        for change in changes:
            if change.type.name != 'ADDED':
                continue

            appt = change.document.to_dict()
            appt_ref = change.document.reference

            # Idempotentnost: ako je iz bilo kog razloga listener okinuo dvaput
            # (rekonekcija itd.), claim garantuje da šaljemo samo jednom.
            if appt.get('employeeNotified'):
                continue
            if not claim_reminder(appt_ref, 'employeeNotified'):
                continue

            employee_id = appt.get('employeeId')
            if not employee_id or employee_id == '__any__':
                continue

            emp_doc = db.collection('users').document(employee_id).get()
            if not emp_doc.exists:
                continue
            emp_data = emp_doc.to_dict()
            emp_ref = db.collection('users').document(employee_id)

            start_time = appt.get('startTime')
            if start_time:
                if start_time.tzinfo is None:
                    start_time = start_time.replace(tzinfo=TZ_LOCAL)
                else:
                    start_time = start_time.astimezone(TZ_LOCAL)
                when = start_time.strftime('%d.%m. u %H:%M')
            else:
                when = 'nepoznato vreme'

            client_name = appt.get('clientName', 'Klijent')
            service_name = appt.get('serviceName', 'Usluga')
            title = "Nova rezervacija!"
            body = f"{client_name} je zakazao/la '{service_name}' — {when}."

            # Istorija se upisuje UVEK, push samo ako zaposleni ima token —
            # tako zaposleni uvek vidi ko je i kada zakazao čak i ako push kasni/ne stigne.
            create_notification(employee_id, title, body, change.document.id, 'new_appointment')
            if emp_data.get('fcmToken') or emp_data.get('fcmTokenWeb'):
                send_to_all(emp_data, emp_ref, title, body, tag=f"new-appt-{change.document.id}")
            else:
                print(f"Zaposleni {emp_data.get('name')} nema FCM token — samo istorija upisana.")

            print(f"Zaposleni {emp_data.get('name')} obavešten o novom terminu {change.document.id}")

    db.collection('appointments').on_snapshot(on_snapshot)


# Pokretanje pozadinskih thread-ova
threading.Thread(target=check_appointments_loop, daemon=True).start()
threading.Thread(target=watch_new_appointments, daemon=True).start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)