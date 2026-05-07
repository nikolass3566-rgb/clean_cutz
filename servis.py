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

# Pokušaj da učitaš konfiguraciju iz varijable (za Render)
firebase_config = os.environ.get('FIREBASE_CONFIG')

if firebase_config:
    # Render okruženje
    cred_dict = json.loads(firebase_config)
    cred = credentials.Certificate(cred_dict)
else:
    # Lokalno okruženje (tvoj PC)
    cred = credentials.Certificate("serviceAccountKey.json")

firebase_admin.initialize_app(cred)
db = firestore.client()

# Tvoja lokalna vremenska zona (UTC+2)
OFFSET = datetime.timedelta(hours=2)
TZ_LOCAL = datetime.timezone(OFFSET)

@app.get("/")
def health_check():
    return {"status": "online", "timezone": "UTC+2"}

# --- FUNKCIJA ZA SLANJE (IZMENJENA ZA HIGH PRIORITY) ---
def send_fcm_notification(token, title, body):
    if not token:
        return False
    
    # Kreiramo poruku sa visokim prioritetom i ispravnim kanalom
    message = messaging.Message(
        notification=messaging.Notification(title=title, body=body),
        android=messaging.AndroidConfig(
            priority='high',
            notification=messaging.AndroidNotification(
                channel_id='appointments_channel', # Mora se podudarati sa useAuth.js
                priority='max',
                default_sound=True,
                default_vibrate_timings=True
            )
        ),
        token=token
    )
    try:
        messaging.send(message)
        return True
    except Exception as e:
        print(f"Greška pri slanju: {e}")
        return False

# --- GLAVNI LOOP ---
def check_appointments_loop():
    print(f"Servis pokrenut u UTC+2 zoni...")
    
    while True:
        try:
            # Uzimamo trenutno vreme u tvojoj zoni (UTC+2)
            now = datetime.datetime.now(TZ_LOCAL)
            print(f"Provera termina (Lokalno): {now.strftime('%H:%M:%S')}")

            # Čitamo potvrđene termine
            appointments = db.collection('appointments')\
                .where(filter=FieldFilter('status', '==', 'confirmed'))\
                .stream()

            for doc in appointments:
                appt = doc.to_dict()
                appt_id = doc.id
                start_time = appt.get('startTime')

                if not start_time:
                    continue

                # Konverzija vremena iz baze u tvoju vremensku zonu
                if start_time.tzinfo is None:
                    start_time = start_time.replace(tzinfo=TZ_LOCAL)
                else:
                    start_time = start_time.astimezone(TZ_LOCAL)

                # Razlika u minutima
                diff_minutes = (start_time - now).total_seconds() / 60

                # Preskoči termine koji su prošli
                if diff_minutes < -5:
                    continue

                # Uzmi token korisnika
                user_doc = db.collection('users').document(appt.get('clientId')).get()
                if not user_doc.exists:
                    continue
                
                user_data = user_doc.to_dict()
                token = user_data.get('fcmToken')
                user_name = user_data.get('name', 'Klijent')

                # --- LOGIKA SLANJA (Prozor od 2 minuta radi sigurnosti) ---
                
                # 2 SATA (119 - 121 min pre)
                if 119 <= diff_minutes <= 121 and not appt.get('sent_2h'):
                    if send_fcm_notification(token, "Vidimo se uskoro!", f"Zdravo {user_name}, termin ti je za 2 sata."):
                        db.collection('appointments').document(appt_id).update({'sent_2h': True})

                # 1 SAT (59 - 61 min pre)
                elif 59 <= diff_minutes <= 61 and not appt.get('sent_1h'):
                    if send_fcm_notification(token, "Još sat vremena!", f"{user_name}, tvoj termin kod {appt.get('employeeName')} je za 1h."):
                        db.collection('appointments').document(appt_id).update({'sent_1h': True})

                # 30 MINUTA (29 - 31 min pre)
                elif 29 <= diff_minutes <= 31 and not appt.get('sent_30min'):
                    if send_fcm_notification(token, "Skoro je vreme!", f"{user_name}, vidimo se u salonu za 30 minuta!"):
                        db.collection('appointments').document(appt_id).update({'sent_30min': True})

            # Proveravaj svakog minuta (preciznije za prozor od 2 min)
            time.sleep(60) 

        except Exception as e:
            print(f"Greška: {e}")
            time.sleep(30)

# Pokretanje pozadinskog thread-a
threading.Thread(target=check_appointments_loop, daemon=True).start()

if __name__ == "__main__":
    # Render koristi PORT varijablu
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)