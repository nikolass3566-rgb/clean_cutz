import firebase_admin
from firebase_admin import credentials, messaging, firestore
from datetime import datetime, timedelta
import time

# 1. Inicijalizacija (koristi svoj Service Account JSON)
cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

def send_push(token, title, body):
    message = messaging.Message(
        notification=messaging.Notification(title=title, body=body),
        token=token,
    )
    try:
        response = messaging.send(message)
        print('Successfully sent message:', response)
    except Exception as e:
        print('Error sending message:', e)

def check_appointments():
    now = datetime.now()
    # Intervali za podsetnike (u minutima)
    reminders = [120, 60, 30]
    
    for minutes in reminders:
        # Tražimo termin koji je tačno za X minuta (+/- 2 minuta tolerancije)
        start_search = now + timedelta(minutes=minutes - 2)
        end_search = now + timedelta(minutes=minutes + 2)
        
        docs = db.collection('appointments')\
                 .where('status', '==', 'confirmed')\
                 .where('startTime', '>=', start_search)\
                 .where('startTime', '<=', end_search)\
                 .stream()

        for doc in docs:
            appt = doc.to_dict()
            # Uzimamo user token iz profila korisnika
            user_ref = db.collection('users').document(appt['clientId']).get()
            if user_ref.exists:
                user_data = user_ref.to_dict()
                token = user_data.get('fcmToken')
                if token:
                    send_push(
                        token, 
                        "Podsetnik za šišanje ✂️", 
                        f"Tvoj termin kod frizera {appt['employeeName']} je za {minutes} min!"
                    )

# Beskonačna petlja koja simulira Cron Job (svakih 5 minuta)
if __name__ == "__main__":
    while True:
        print(f"Checking for appointments at {datetime.now()}...")
        check_appointments()
        time.sleep(300) # Spavaj 5 minuta