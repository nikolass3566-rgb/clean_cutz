import firebase_admin
from firebase_admin import credentials, messaging, firestore
from google.cloud.firestore_v1.base_query import FieldFilter
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

@app.get("/")
def health_check():
    return {"status": "online", "timezone": "UTC+2"}

# --- FUNKCIJA ZA SLANJE ---
def send_fcm_notification(token, title, body):
    # Ako token ne postoji, označi kao poslato da se ne pokušava ponovo
    if not token:
        print("Token je None, preskačem slanje.")
        return True

    message = messaging.Message(
        notification=messaging.Notification(title=title, body=body),
        android=messaging.AndroidConfig(
            priority='high',
            notification=messaging.AndroidNotification(
                channel_id='appointments_channel',
                priority='max',
                default_sound=True,
                default_vibrate_timings=True
            )
        ),
        token=token
    )
    try:
        messaging.send(message)
        print(f"Notifikacija uspešno poslata: {title}")
        return True
    except Exception as e:
        print(f"Greška pri slanju: {e}")
        # Nevažeći ili istekli token — označi kao poslato da se ne ponavlja beskonačno
        if "Requested entity was not found" in str(e) or "invalid-registration-token" in str(e):
            print("Nevažeći FCM token — označavam kao poslato da preskočim ovaj termin.")
            return True
        return False

# --- GLAVNI LOOP ---
def check_appointments_loop():
    print(f"Servis pokrenut u UTC+2 zoni...")

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

                # Konverzija vremena u lokalnu zonu
                if start_time.tzinfo is None:
                    start_time = start_time.replace(tzinfo=TZ_LOCAL)
                else:
                    start_time = start_time.astimezone(TZ_LOCAL)

                diff_minutes = (start_time - now).total_seconds() / 60

                # Preskoči termine koji su davno prošli
                if diff_minutes < -5:
                    continue

                # Uzmi podatke korisnika
                client_id = appt.get('clientId')
                if not client_id:
                    continue

                user_doc = db.collection('users').document(client_id).get()
                if not user_doc.exists:
                    continue

                user_data = user_doc.to_dict()
                token     = user_data.get('fcmToken')
                token_web = user_data.get('fcmTokenWeb')
                user_name = user_data.get('name', 'Klijent')

                # Ako korisnik nema nijedan token, preskoči
                if not token and not token_web:
                    print(f"Korisnik {user_name} nema FCM token (izlogovan), preskačem.")
                    continue

                # --- LOGIKA SLANJA ---
                def send_to_all(title, body, flag_field):
                    """Šalje na sve dostupne tokene, vraća True ako bar jedan uspe."""
                    results = []
                    if token:
                        results.append(send_fcm_notification(token, title, body))
                    if token_web:
                        results.append(send_fcm_notification(token_web, title, body))
                    return any(results)

                # 2 SATA (119 - 121 min pre)
                if 119 <= diff_minutes <= 121 and not appt.get('sent_2h'):
                    if send_to_all(
                        "Vidimo se uskoro!",
                        f"Zdravo {user_name}, termin ti je za 2 sata.",
                        'sent_2h'
                    ):
                        db.collection('appointments').document(appt_id).update({'sent_2h': True})
                        print(f"sent_2h -> True za termin {appt_id}")

                # 1 SAT (59 - 61 min pre)
                elif 59 <= diff_minutes <= 61 and not appt.get('sent_1h'):
                    if send_to_all(
                        "Jos sat vremena!",
                        f"{user_name}, tvoj termin kod {appt.get('employeeName')} je za 1h.",
                        'sent_1h'
                    ):
                        db.collection('appointments').document(appt_id).update({'sent_1h': True})
                        print(f"sent_1h -> True za termin {appt_id}")

                # 30 MINUTA (29 - 31 min pre)
                elif 29 <= diff_minutes <= 31 and not appt.get('sent_30min'):
                    if send_to_all(
                        "Skoro je vreme!",
                        f"{user_name}, vidimo se u salonu za 30 minuta!",
                        'sent_30min'
                    ):
                        db.collection('appointments').document(appt_id).update({'sent_30min': True})
                        print(f"sent_30min -> True za termin {appt_id}")

            time.sleep(60)

        except Exception as e:
            print(f"Greška u glavnom loopu: {e}")
            time.sleep(30)

# Pokretanje pozadinskog thread-a
threading.Thread(target=check_appointments_loop, daemon=True).start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)