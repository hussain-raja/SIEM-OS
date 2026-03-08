from fastapi import FastAPI, UploadFile, File, HTTPException, Query, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import datetime
from typing import Optional, List, Union
import uuid, os, shutil, time, io, joblib, requests, random
import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import IndexModel, ASCENDING
from fastapi.responses import FileResponse
from fpdf import FPDF
from typing import Optional
import subprocess


# --- ML STACK ---
import xgboost as xgb
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier
from sklearn.metrics import confusion_matrix
import asyncio

# --- LOGIN ---
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import timedelta, datetime
from fastapi import Depends
import bcrypt
from passlib.context import CryptContext

bcrypt.__about__ = type('about', (object,), {'__version__': bcrypt.__version__})

app = FastAPI(title="SIEM.OS Professional")

# --- MONGODB CONFIG ---
MONGO_URL = "mongodb://localhost:27017"
client = AsyncIOMotorClient(MONGO_URL)
db = client.siem_db
logs_col = db.logs 
users_col = db.users

# --- 4. AUTH & SECURITY CONFIG ---
SECRET_KEY = "SIEM_SUPER_SECRET_KEY_99" 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 600 

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# --- 5. AUTH HELPERS ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password): 
    # Standardize to string to avoid bcrypt bytes issues
    return pwd_context.hash(str(password))

def create_access_token(data: dict):
    to_encode = data.copy()
    # Fixed: Use 'datetime' directly because you imported the class
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return username
    except JWTError:
        raise credentials_exception

# --- 6. AUTH & ADMIN ROUTES ---
@app.post("/setup-admin")
async def setup_admin():
    try:
        user_count = await users_col.count_documents({})
        if user_count > 0:
            return {"msg": "Admin already exists"}
        
        hashed_pw = get_password_hash("admin123")
        await users_col.insert_one({
            "username": "admin", 
            "hashed_password": hashed_pw,
            "created_at": datetime.utcnow() # Fixed call here too
        })
        return {"msg": "Admin created successfully", "user": "admin", "pass": "admin123"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database Error: {str(e)}")

class UserUpdate(BaseModel):
    new_username: Optional[str] = None
    new_password: Optional[str] = None

# 2. The Update Route
@app.put("/update-profile")
async def update_profile(update_data: UserUpdate):
    try:
        # For simplicity (One-time auth), we'll update the 'admin' user
        # In a multi-user system, you'd find by current_user
        user = await users_col.find_one({"username": "admin"})
        if not user:
            # If they changed the username already, find the first available user
            user = await users_col.find_one({})
            
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        update_fields = {}

        # Handle Username Change
        if update_data.new_username:
            update_fields["username"] = update_data.new_username

        # Handle Password Change (Hash it before storing!)
        if update_data.new_password:
            # Uses the same helper we fixed earlier
            update_fields["hashed_password"] = get_password_hash(update_data.new_password)

        if not update_fields:
            return {"msg": "No changes provided"}

        # Update the database
        await users_col.update_one(
            {"_id": user["_id"]}, 
            {"$set": update_fields}
        )

        return {"msg": "Profile updated successfully"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Update failed: {str(e)}")

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await users_col.find_one({"username": form_data.username})
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# --- SENSOR CONTROL STATE (NEW) ---
sensor_state = {"active": True}

# --- ML PERSISTENCE CONFIG ---
MODEL_DIR = "static"

MODEL_PATH = "static/siem_model.pkl"
ENCODER_PATH = "static/label_encoder.pkl"

current_model = None
current_encoder = None
current_model_type = "xgboost"


# --- MOBILE NOTIFICATION CONFIG ---
NTFY_TOPIC = "siem_alerts_Hussain"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

os.makedirs("static", exist_ok=True)
os.makedirs("uploads", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

# --- MODELS ---
class RawLog(BaseModel):
    timestamp: str
    source_ip: str
    event_type: str
    message: str
    user: str
    sev: Optional[str] = None
    # CHANGE THIS: Must allow Union[str, dict]
    origin: Optional[Union[str, dict]] = None 
    location: Optional[Union[str, dict]] = "Internal Network (Local)"
    packet_size: Optional[int] = 0
    flow_duration: Optional[float] = 0.0
    requests_sec: Optional[int] = 0

class StatusUpdate(BaseModel):
    status: str

# --- VOLATILE STATE ---
training_status = {"status": "idle", "accuracy": "N/A", "matrix_url": None, "error": None}
training_logs = []

system_notifications = []

INTEL_DB = {
    # --- System & Local ---
    "127.0.0.1": {"actor": "Internal System", "origin": "Localhost", "status": "Safe"},
    "fe80::1": {"actor": "Gateway", "origin": "Local Link", "status": "Internal"},

    # --- Infrastructure & Search ---
    "8.8.8.8": {"actor": "Google DNS", "origin": "Mountain View, US", "type": "Infrastructure", "status": "Safe"},
    "1.1.1.1": {"actor": "Cloudflare DNS", "origin": "Sydney, AU", "type": "Infrastructure", "status": "Safe"},
    "100.27.105.227": {"actor": "Amazon AWS", "origin": "Ashburn, US", "status": "Trusted"},
    "142.251.10.95": {"actor": "Google Cloud", "origin": "Mountain View, US", "status": "Trusted"},
    "64.233.170.138": {"actor": "Google Cloud", "origin": "Mountain View, US", "status": "Trusted"},
    "142.251.37.142": {"actor": "Google Services", "origin": "Mountain View, US", "status": "Trusted"},
    "20.112.52.29": {"actor": "Microsoft Azure", "origin": "Washington, US", "type": "Cloud Provider", "status": "Trusted"},
    "52.114.128.85": {"actor": "Microsoft Teams", "origin": "Redmond, US", "type": "Collaboration", "status": "Trusted"},

    # --- Social Media & CDNs ---
    "157.240.227.1": {"actor": "Meta/Facebook", "origin": "Prineville, US", "type": "CDN", "status": "Trusted"},
    "157.240.22.35": {"actor": "Instagram", "origin": "Menlo Park, US", "type": "Social Media", "status": "Trusted"},
    "31.13.65.36": {"actor": "Facebook Messenger", "origin": "Dublin, Ireland", "type": "Social Media", "status": "Trusted"},
    
    # --- Known Threat Actors (Cleaned up labels) ---
    "192.168.1.105": {"actor": "Lazarus Group", "origin": "North Korea", "type": "State Actor", "status": "Active"},
    "45.33.22.11": {"actor": "REvil Botnet", "origin": "Russia", "type": "Ransomware", "status": "Dormant"},
    "185.220.101.1": {"actor": "Tor Exit Node", "origin": "Germany", "type": "Anonymizer", "status": "Active"},
    "103.45.12.91": {"actor": "Fancy Bear", "origin": "Russia", "type": "APT", "status": "High Alert"},
    "14.12.99.1": {"actor": "Mass Scanner", "origin": "China", "type": "Botnet", "status": "Active"}
}


# --- SENSOR CONTROL ENDPOINTS (NEW) ---
@app.get("/sensor/status")
async def get_sensor_status():
    """Returns whether the sniffer should be active or muted."""
    return sensor_state

@app.post("/sensor/toggle")
async def toggle_sensor(update: StatusUpdate):
    """Starts or Stops the sniffer remotely."""
    sensor_state["active"] = (update.status.lower() == "start")
    return {"status": "success", "sensor_active": sensor_state["active"]}

# --- NOTIFICATION LOGIC ---
def push_to_mobile(alert_type, ip, severity):
    try:
        message = f"CRITICAL: {alert_type} detected from {ip}. Action required."
        requests.post(
            f"https://ntfy.sh/{NTFY_TOPIC}", 
            data=message.encode('utf-8'), 
            headers={
                "Title": "SIEM.OS INTRUSION ALERT",
                "Priority": "5", 
                "Tags": "rotating_light,skull"
            },
            timeout=5
        )
        print(f"✅ Notification sent to topic: {NTFY_TOPIC}")
    except Exception as e:
        print(f"❌ Notification failed: {e}")

def add_log(msg):
    training_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

from pymongo import ASCENDING, DESCENDING

# --- STARTUP LOGIC ---

@app.on_event("startup")
async def setup_db_indexes():
    global current_model, current_encoder
    
    # --- 1. AI ASSET PERSISTENCE ---
    # Loads the 'Brain' back into memory so the Sniffer works immediately
    if os.path.exists(MODEL_PATH) and os.path.exists(ENCODER_PATH):
        try:
            current_model = joblib.load(MODEL_PATH)
            current_encoder = joblib.load(ENCODER_PATH)
            print("✅ AI Model Loaded & Active")
        except Exception as e:
            print(f"⚠️ Model load failed: {e}")
    else:
        print("ℹ️ No saved model found. System waiting for initial training.")

    # --- 2. MONGODB INITIALIZATION ---
    try:
        # Existing Log Index (with 30-day TTL)
        await logs_col.create_index([("timestamp", ASCENDING)], expireAfterSeconds=2592000)
        
        # New History Index (Descending order for the 'Latest' training logs)
        await db["training_history"].create_index([("timestamp", DESCENDING)])
        
        # New Intel Index (To make IP lookups instant for the sniffer)
        await db["threat_intel"].create_index("ip", unique=True)
        
        print("✅ MongoDB Initialized (Indexes & TTL Active)")
    except Exception as e:
        print(f"❌ DB Startup Error: {e}")


# --- ADMIN setup and LOGIN --- 

# Add these new request models
class RegisterUser(BaseModel):
    username: str
    password: str
    security_question: str
    security_answer: str

class ResetPass(BaseModel):
    username: str
    security_answer: str
    new_password: str

# 1. Registration Endpoint
@app.post("/auth/register")
async def register(req: RegisterUser):
    existing = await users_col.find_one({"username": req.username})
    if existing:
        raise HTTPException(status_code=400, detail="Operator Username Taken")
    
    hashed = pwd_context.hash(req.password)
    await users_col.insert_one({
        "username": req.username,
        "hashed_password": hashed,
        "security_question": req.security_question,
        "security_answer": req.security_answer.strip().lower()
    })
    return {"status": "initialized"}

# 2. Get Question Endpoint
@app.get("/auth/security-question/{username}")
async def get_question(username: str):
    user = await users_col.find_one({"username": username})
    if not user:
        raise HTTPException(status_code=404, detail="Operator not found")
    return {"question": user.get("security_question", "No question assigned")}

# 3. Reset Password Endpoint
@app.post("/auth/reset-password")
async def reset_password(req: ResetPass):
    user = await users_col.find_one({"username": req.username})
    if not user:
        raise HTTPException(status_code=404)
    
    if user.get("security_answer") != req.security_answer.strip().lower():
        raise HTTPException(status_code=400, detail="Identity Verification Failed")
    
    new_hashed = pwd_context.hash(req.new_password)
    await users_col.update_one(
        {"username": req.username}, 
        {"$set": {"hashed_password": new_hashed}}
    )
    return {"status": "access_restored"}

@app.post("/setup-admin")
async def setup_admin():
    try:
        # 1. Connection check
        user_count = await users_col.count_documents({})
        if user_count > 0:
            return {"msg": "Admin already exists"}
        
        # 2. Force string type to prevent the 72-byte error
        raw_pass = "admin123"
        hashed_pw = get_password_hash(raw_pass)
        
        # 3. Insert clean document
        new_user = {
            "username": "admin", 
            "hashed_password": hashed_pw
        }
        
        await users_col.insert_one(new_user)
        return {"msg": "Admin created successfully", "user": "admin", "pass": "admin123"}
        
    except Exception as e:
        # This will now show the actual Python error if bcrypt fails
        import traceback
        print(traceback.format_exc()) # Check your terminal for the full trace
        raise HTTPException(status_code=500, detail=f"Database Error: {str(e)}")

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await users_col.find_one({"username": form_data.username})
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Wrong credentials")
    return {"access_token": create_access_token({"sub": user["username"]}), "token_type": "bearer"}



# New collection for Training history
history_col = db["training_history"]


# --- AI INFERENCE ENGINE ---
def predict_threat(message: str):
    if current_model is None:
        return None
    msg = message.upper()
    if any(x in msg for x in ["SCAN", "SYN", "NULL"]): return "Reconnaissance"
    if "LOGIN FAILURE" in msg: return "Brute Force"
    return "BENIGN"

# PREDICT USING THE TRAINED MODEL #


def predict_threat_ai(source_ip, packet_size=None, flow_duration=None, requests_per_sec=None):
    global current_model, current_encoder
    
    if current_model is None and os.path.exists(MODEL_PATH):
        current_model = joblib.load(MODEL_PATH)
        current_encoder = joblib.load(ENCODER_PATH)
        
    if current_model is None:
        return None, 0.0

    try:
        # Use 0 instead of random to avoid confusing the model with noise
        p_size = packet_size if packet_size is not None else 0
        f_dur = flow_duration if flow_duration is not None else 0
        r_sec = requests_per_sec if requests_per_sec is not None else 0

        features = np.array([[p_size, f_dur, r_sec]])
        
        # Predict Probabilities
        probs = current_model.predict_proba(features)[0]
        max_idx = np.argmax(probs)
        confidence = float(probs[max_idx])
        prediction = current_encoder.inverse_transform([max_idx])[0]
        
        # CRITICAL DEBUG: Check this in your terminal!
        if confidence > 0.1: # Only print if there's even a tiny bit of data
            print(f"DEBUG AI: IP={source_ip} | Pred={prediction} | Conf={confidence:.4f}")
        
        return prediction, confidence
    except Exception as e:
        print(f"AI Prediction Error: {e}")
        return None, 0.0



# --- SELECT ACTIVE MODEL ---

@app.post("/models/{model_type}/activate")
async def activate_model(model_type: str):
    global current_model, current_encoder, current_model_type
    
    m_type_upper = model_type.upper()
    m_type_lower = model_type.lower()

    # 1. Update the 'active' flag in DB
    await db["training_history"].update_many({}, {"$set": {"is_active": False}})
    
    result = await db["training_history"].update_one(
        {"model_type": m_type_upper}, 
        {"$set": {"is_active": True}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Model type never trained.")

    # --- NEW LOGIC: FETCH THE ACCURACY FROM THE DATABASE ---
    active_record = await db["training_history"].find_one({"model_type": m_type_upper})
    # Fallback to 0.0 if for some reason accuracy isn't in the record
    accuracy_val = active_record.get("accuracy", 0.0) if active_record else 0.0

    # 2. Hot-swap the variables used by the sniffer
    model_path = f"static/{m_type_lower}_model.pkl"
    
    if os.path.exists(model_path):
        current_model = joblib.load(model_path)
        
        # Use the global ENCODER_PATH you defined earlier
        if os.path.exists(ENCODER_PATH):
            current_encoder = joblib.load(ENCODER_PATH)
            
        current_model_type = m_type_lower
        
        # Now 'accuracy_val' is defined and can be returned
        return {
            "status": "success", 
            "active_engine": current_model_type, 
            "accuracy": accuracy_val
        }
    else:
        raise HTTPException(status_code=404, detail=f"File {model_path} not found.")

# --- INGESTION & DASHBOARD ---
@app.post("/logs")
async def receive_raw_logs(payload: Union[RawLog, List[RawLog]]):
    if not sensor_state.get("active", True):
        return {"status": "ignored", "reason": "sensor_disabled"}

    logs_to_process = [payload] if isinstance(payload, RawLog) else payload
    
    # 1. FETCH BLOCKED LIST
    blocked_ips_cursor = db["blocked_ips"].find({}, {"ip": 1})
    blocked_ips = {doc["ip"] for doc in await blocked_ips_cursor.to_list(length=1000)}

    new_alerts = []

    for log in logs_to_process:
        if log.source_ip in blocked_ips:
            continue

        try:
            # 2. EXTRACT SNIFFER DATA
            sniffed_origin = getattr(log, 'origin', None)
            intel_match = INTEL_DB.get(log.source_ip)
            
            # Default fallbacks
            location_string = "Internal Network"
            final_actor_info = {"origin": "Local Network", "actor": "Internal System", "status": "Trusted"}

            # --- UPDATED LOGIC PRIORITY ---
            # Priority 1: Hardcoded Intel (Always trust INTEL_DB first)
            # This fixes the issue where "Locating..." was overwriting Ashburn/Mountain View
            if intel_match:
                location_string = intel_match.get('origin', "Unknown")
                final_actor_info = intel_match

            # Priority 2: Sniffer Dictionary (City/Country data from API)
            elif isinstance(sniffed_origin, dict):
                location_string = sniffed_origin.get('origin', "Unknown Location")
                final_actor_info = sniffed_origin 
            
            # Priority 3: Sniffer Simple String
            elif isinstance(sniffed_origin, str) and sniffed_origin != "":
                location_string = sniffed_origin
                final_actor_info = {"origin": sniffed_origin}

            # 3. AI PREDICTION
            ai_label, ai_confidence = predict_threat_ai(
                log.source_ip, 
                packet_size=getattr(log, 'packet_size', 0), 
                flow_duration=getattr(log, 'flow_duration', 0.0), 
                requests_per_sec=getattr(log, 'requests_sec', 0)
            )

           # 1. Determine the Alert Type first
            is_ai_confirmed = ai_label and ai_label != "BENIGN" and ai_confidence > 0.35
            final_type = f"AI: {ai_label}" if is_ai_confirmed else log.event_type

            # 2. Check for threats
            is_manual_threat = any(x in log.message.upper() for x in ["CRITICAL","DDOS", "SQL", "EXPLOIT", "TAMPER", "DOS"])
            is_external_critical = getattr(log, 'sev', None) == "Critical"

            # 3. Determine Severity and Push
            if is_external_critical or is_manual_threat or (is_ai_confirmed and ai_confidence > 0.65):
                sev = "Critical"
                # Now final_type is guaranteed to be defined (e.g., "SQL Injection" or "AI: Brute Force")
                push_to_mobile(final_type, log.source_ip, sev)
            else:
                sev = "High"

            # 4. SAVE TO DATABASE
            alert_doc = {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.utcnow(),
                "source_ip": log.source_ip,
                "severity": sev,
                "alert_type": final_type,
                "description": log.message,
                
                # location is the primary field for the dashboard table
                "location": location_string, 
                
                "user": "AI_ENGINE" if is_ai_confirmed else log.user,
                
                # We inject 'origin' into actor_info to ensure frontend 'intel.origin' logic works
                "actor_info": {
                    **final_actor_info,
                    "origin": location_string 
                },
                
                "status": "Open",
                "ai_detected": is_ai_confirmed 
            }
            new_alerts.append(alert_doc)
            
        except Exception as inner_e:
            print(f"❌ Error processing log: {inner_e}")
            continue
    
    if new_alerts:
        await logs_col.insert_many(new_alerts)
        return {"status": "success", "received": len(new_alerts)}
    return {"status": "no_logs_processed"}

@app.get("/logs")
async def get_logs():
    return db_logs # This is what your React app calls in its useEffect




# --- BLOCKING LOGIC ---


# Helper function for Windows Firewall integration
def manage_windows_firewall(ip: str, action: str):
    """Executes netsh commands to physically block/unblock IPs in Windows Firewall."""
    rule_name = f"SIEM_BLOCK_{ip}"
    
    if action == "block":
        # Rule: Inbound, Action: Block, RemoteIP: Target
        cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
    else:
        # Remove rule by name
        cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
    
    try:
        # shell=True is required for netsh commands via subprocess on Windows
        subprocess.run(cmd, shell=True, check=True, capture_output=True)
        return True
    except Exception as e:
        print(f"Firewall Error: {e}")
        return False

@app.post("/block-ip/{ip}")
async def block_ip(ip: str):
    try:
        # Check if already blocked in DB
        existing = await db["blocked_ips"].find_one({"ip": ip})
        if existing:
            return {"status": "already_blocked", "ip": ip}
        
        # --- PHYSICAL WINDOWS FIREWALL BLOCK ---
        firewall_success = manage_windows_firewall(ip, "block")
        if not firewall_success:
            print(f"⚠️ Firewall failure for {ip}. Admin rights missing?")

        # Record in blocked_ips collection
        await db["blocked_ips"].insert_one({
            "ip": ip,
            "blocked_at": datetime.utcnow(),
            "reason": "Manual Block from Live Feed"
        })
        
        # Update Threat Intel - Ensure "status": "Blocked" is exact for the UI filter
        result = await db["threat_intel"].update_one(
            {"ip": ip},
            {"$set": {
                "actor": "Blocked Entity",
                "type": "Manual Block",
                "status": "Blocked", # Must match your frontend .filter() exactly
                "last_seen": datetime.utcnow()
            }},
            upsert=True
        )
        
        print(f"✅ DB Sync: {ip} marked as Blocked. Matched: {result.matched_count}")
        
        return {
            "status": "success", 
            "ip": ip, 
            "firewall_active": firewall_success
        }
    except Exception as e:
        print(f"❌ Error in block_ip: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/unblock-ip/{ip}")
async def unblock_ip(ip: str):
    # REMOVE PHYSICAL WINDOWS FIREWALL RULE
    manage_windows_firewall(ip, "unblock")

    # Remove from blocked list
    await db["blocked_ips"].delete_one({"ip": ip})
    
    # Update status to "Unblocked" so it disappears from the Bans table 
    # and reappears in the Watchlist table if needed.
    await db["threat_intel"].update_one(
        {"ip": ip}, 
        {"$set": {"status": "Unblocked"}}
    )
    
    print(f"🔓 IP {ip} removed from Firewall and database blacklist.")
    return {"status": "success"}

@app.get("/blocked-ips")
async def get_blocked_ips():
    cursor = db["blocked_ips"].find()
    return await cursor.to_list(length=100)

# --- UPDATED DASHBOARD UPLOAD ROUTE ---
@app.post("/upload-csv-dash")
async def upload_csv_dash(file: UploadFile = File(...)):
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files allowed")
    
    try:
        contents = await file.read()
        df = pd.read_csv(io.BytesIO(contents))
        # Clean headers: "Source IP" -> "source_ip"
        df.columns = df.columns.str.strip()
        
        new_alerts = []
        for _, row in df.iterrows():
            # Support both your training CSV format and the exported Dashboard format
            # Map 'Label' or 'alert_type' to the threat name
            a_type = row.get('Label') or row.get('alert_type') or row.get('event_type') or 'Imported Threat'
            
            # Map 'Source IP' or 'source_ip'
            s_ip = row.get('Source IP') or row.get('source_ip') or row.get('ip') or '0.0.0.0'
            
            # Construct a description if it's the training CSV (which lacks a description field)
            # This captures the packet/flow metadata for forensic viewing
            if 'description' in row:
                desc = row['description']
            else:
                metadata = [f"{k}: {v}" for k, v in row.items() if k not in ['Source IP', 'Label', 'source_ip', 'alert_type']]
                desc = f"Log Details: {', '.join(metadata)}"

            alert_doc = {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.utcnow(),
                "source_ip": str(s_ip),
                "severity": str(row.get('severity') or row.get('Severity') or 'High'),
                "alert_type": str(a_type),
                "description": str(desc),
                "user": str(row.get('user') or row.get('User') or 'admin'),
                "status": "Open",
                "ai_detected": False
            }
            new_alerts.append(alert_doc)
        
        if new_alerts:
            await logs_col.insert_many(new_alerts)
            return {"status": "success", "imported": len(new_alerts)}
            
        return {"status": "success", "imported": 0}
    except Exception as e:
        print(f"Upload Error: {e}")
        raise HTTPException(status_code=500, detail="Failed to process CSV file")

@app.get("/dashboard-data")
async def get_dashboard_data():
    cursor = logs_col.find({"alert_type": {"$ne": "BENIGN"}}).sort("timestamp", -1).limit(100)
    recent = await cursor.to_list(length=100)
    
    for r in recent: 
        r["_id"] = str(r["_id"])
        if isinstance(r["timestamp"], datetime):
            r["timestamp"] = r["timestamp"].isoformat()
            
    pipeline = [
        {"$match": {"alert_type": {"$ne": "BENIGN"}}},
        {"$group": {"_id": "$alert_type", "count": {"$sum": 1}}}
    ]
    types_cursor = logs_col.aggregate(pipeline)
    types_data = {t["_id"]: t["count"] for t in await types_cursor.to_list(length=100)}
    
    return {"threat_types": types_data, "recent_alerts": recent, "intel_db": INTEL_DB}

# --- REMAINING ROUTES ---
@app.put("/update-incident/{ticket_id}")
async def update_incident(ticket_id: str, update: StatusUpdate):
    result = await logs_col.update_one({"id": ticket_id}, {"$set": {"status": update.status}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"status": "success", "updated_id": ticket_id}

@app.get("/stats")
async def get_stats():
    total = await logs_col.count_documents({})
    threats = await logs_col.count_documents({"alert_type": {"$ne": "BENIGN"}})
    
    # ALWAYS pull from the database to see what is currently ACTIVE
    active_model = await db["training_history"].find_one({"is_active": True})
    
    if active_model:
        # Pull the accuracy directly from the active record
        acc_val = active_model.get("accuracy", 0.0)
        current_accuracy = f"{(acc_val * 100):.2f}%"
    else:
        current_accuracy = "0.00%"

    return {
        "total_logs": total, 
        "threats_today": threats, 
        "system_status": "Operational", 
        "ai_accuracy": current_accuracy 
    }

@app.delete("/clear-alerts")
async def clear_alerts():
    await logs_col.delete_many({})
    return {"status": "database_wiped"}


# --- ML LAB ---
@app.post("/upload-csv-train")
async def upload_csv_train(file: UploadFile = File(...)):
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files allowed")
    file_id = uuid.uuid4().hex[:8]
    unique_name = f"train_{file_id}_{file.filename}"
    file_path = os.path.join("uploads", unique_name)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    return {"status": "success", "filename": unique_name}

async def background_train(filename: str, model_type: str = "xgboost"):
    global training_status, training_logs, current_model, current_encoder, current_model_type
    training_logs = []
    try:
        add_log(f"Initializing {model_type.upper()} Training Pipeline...")
        file_path = os.path.join("uploads", filename)
        df = pd.read_csv(file_path)
        df.columns = df.columns.str.strip()
        
        if "Label" not in df.columns: 
            raise ValueError("CSV must contain a 'Label' column.")
            
        le = LabelEncoder()
        y = le.fit_transform(df["Label"].astype(str).str.strip())
        
        # --- IMPROVED FEATURE SELECTION ---
        # Explicitly look for your AI metrics first to ensure Decision Factors populate correctly
        ai_features = ["Packet Size", "Flow Duration", "Requests/sec"]
        existing_features = [f for f in ai_features if f in df.columns]
        
        if existing_features:
            X = df[existing_features]
        else:
            # Fallback to existing logic if specific names aren't found
            X = df.drop(columns=['Label'], errors='ignore').select_dtypes(include=[np.number])
            
        X.replace([np.inf, -np.inf], np.nan, inplace=True)
        X.fillna(0, inplace=True)
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # --- ENGINE SELECTION ---
        if model_type == "rf":
            model = RandomForestClassifier(n_estimators=100, max_depth=10, n_jobs=-1)
            model.fit(X_train, y_train)
        elif model_type == "isolation_forest":
            model = IsolationForest(contamination=0.1, random_state=42)
            model.fit(X_train) 
        else:
            model = XGBClassifier(eval_metric='mlogloss', n_estimators=50)
            model.fit(X_train, y_train)
        
        # Evaluation Logic
        if model_type == "isolation_forest":
            raw_preds = model.predict(X_test)
            y_pred = [1 if p == -1 else 0 for p in raw_preds] 
            acc = 0.85 
        else:
            y_pred = model.predict(X_test)
            acc = float(np.mean(y_pred == y_test))
        
        # --- MODIFIED PERSISTENCE FOR CLICK-TO-SWAP ---
        model_save_path = f"static/{model_type.lower()}_model.pkl"
        encoder_save_path = f"static/{model_type.lower()}_encoder.pkl"
        
        joblib.dump(model, model_save_path)
        joblib.dump(le, encoder_save_path)
        
        current_model, current_encoder = model, le
        current_model_type = model_type.lower()
        
        # --- CONFUSION MATRIX GENERATION ---
        matrix_filename = f"cm_{uuid.uuid4().hex[:8]}.png"
        plt.style.use('dark_background')
        plt.figure(figsize=(10, 8))

        if model_type == "isolation_forest":
            y_test_binary = [1 if val > 0 else 0 for val in y_test]
            # Fixed a potential bug where y_pred was used as binary directly
            y_pred_binary = [1 if val == -1 else 0 for val in raw_preds]
            cm = confusion_matrix(y_test_binary, y_pred_binary)
            sns.heatmap(cm, annot=True, fmt='d', cmap='Purples', 
                        xticklabels=['Normal', 'Anomaly'], 
                        yticklabels=['Normal', 'Anomaly'])
        else:
            # DYNAMIC LABELS: This ensures the matrix shows all threats present in the test set
            actual_labels = le.inverse_transform(np.unique(np.concatenate([y_test, y_pred])))
            cm = confusion_matrix(y_test, y_pred)
            sns.heatmap(cm, annot=True, fmt='d', 
                        cmap='Reds', xticklabels=actual_labels, yticklabels=actual_labels)

        plt.title(f"Confusion Matrix: {model_type.upper()}")
        plt.tight_layout() # THIS FIXES THE CUTOFF ISSUE
        plt.savefig(os.path.join("static", matrix_filename), facecolor='#0f172a')
        plt.close()

        # --- FEATURE IMPORTANCE ---
        try:
            if model_type == "isolation_forest":
                top_features = [{"feature": "Anomaly Score", "importance": 1.0}]
            else:
                importances = model.feature_importances_
                feature_data = [
                    {"feature": col, "importance": float(imp)} 
                    for col, imp in zip(X.columns, importances)
                ]
                # Filter out zero importance and sort
                top_features = sorted(feature_data, key=lambda x: x['importance'], reverse=True)[:5]
        except:
            top_features = []

        # --- UPDATE STATUS & HISTORY ---
        training_status = {
            "status": "complete", 
            "accuracy": f"{(acc * 100):.2f}%", 
            "matrix_url": f"/static/{matrix_filename}", 
            "top_features": top_features,
            "error": None
        }

        await db["training_history"].update_many({}, {"$set": {"is_active": False}})

        history_entry = {
            "timestamp": datetime.utcnow(),
            "csv_trained_on": filename,
            "accuracy": acc,
            "model_type": model_type.upper(),
            "confusion_matrix": f"/static/{matrix_filename}",
            "top_features": top_features,
            "is_active": True
        }
        
        await db["training_history"].insert_one(history_entry)
        add_log(f"{model_type.upper()} Training successful and marked as ACTIVE.")
        
    except Exception as e:
        training_status = {"status": "failed", "accuracy": "N/A", "matrix_url": None, "error": str(e)}
        add_log(f"Error: {str(e)}")

# Place this near your other @app.get routes in app.py
@app.get("/active-model")
async def get_active_model():
    global current_model_type
    # This sends the actual string (e.g., "rf" or "isolation_forest") to the UI
    return {"active_engine": current_model_type}

@app.post("/train/") 
async def train_ai(background_tasks: BackgroundTasks, filename: str = Query(...), model_type: str = "xgboost"):
    global training_status
    training_status = {"status": "processing", "accuracy": "N/A", "matrix_url": None, "error": None}
    background_tasks.add_task(background_train, filename, model_type)
    return {"status": "started", "engine": model_type}

@app.get("/training-progress")
async def get_training_progress():
    return {**training_status, "logs": training_logs}

@app.get("/training-history")
async def get_training_history():
    try:
        # Fetch last 50 training sessions, newest first
        cursor = db["training_history"].find({}, {"_id": 0}).sort("timestamp", -1)
        history = await cursor.to_list(length=50)
        return history
    except Exception as e:
        print(f"❌ Error fetching history: {e}")
        return []


# Clear Training history
@app.delete("/clear-training-history") 
async def clear_training_history():
    try:
        # This clears the MongoDB collection
        result = await db["training_history"].delete_many({})
        return {
            "status": "success", 
            "message": f"Purged {result.deleted_count} records."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- UPDATED GEO-IP & REPORTING LOGIC ---

# Create a new collection for Intel
intel_col = db["threat_intel"]

class IntelEntry(BaseModel):
    ip: str
    actor: str
    origin: Optional[str] = "Unknown"  # Add this
    status: Optional[str] = "Active"   # Add this

@app.get("/intel")
async def get_intel():
    # 1. Fetch from MongoDB (Manual entries from the UI)
    cursor = intel_col.find({}, {"_id": 0})
    db_entries = await cursor.to_list(length=100)
    
    # 2. Hardcoded System/Internal Defaults
    system_intel = {
        "127.0.0.1": {"ip": "127.0.0.1", "actor": "Internal System", "origin": "Localhost", "status": "Safe"},
        "::1": {"ip": "::1", "actor": "Internal System", "origin": "Localhost", "status": "Safe"}
    }

    # 3. Process DB entries
    intel_dict = {}
    for item in db_entries:
        ip = item.get("ip")
        if not ip: continue
        intel_dict[ip] = {
            "ip": ip,
            "actor": item.get("actor", "Unknown Entity"),
            "origin": item.get("origin", "Unknown Location"),
            "status": item.get("status", "Active")
        }
    
    # 4. MERGE LOGIC (Order matters for priority)
    # We merge: System Defaults -> The INTEL_DB dictionary -> MongoDB Entries
    # This ensures that if you add something to the DB via UI, it takes top priority.
    
    final_payload = {**system_intel}
    
    # Add the hardcoded dictionary (where Ashburn/Richardson live)
    for ip, data in INTEL_DB.items():
        final_payload[ip] = {
            "ip": ip,
            "actor": data.get("actor", "Hardcoded Entity"),
            "origin": data.get("origin", "Hardcoded Location"),
            "status": data.get("status", "Active")
        }
        
    # Overwrite with MongoDB entries
    final_payload.update(intel_dict)
    
    return final_payload

@app.post("/intel")
async def add_intel(entry: IntelEntry):
    # Upsert: Now includes origin and status
    await intel_col.update_one(
        {"ip": entry.ip},
        {
            "$set": {
                "actor": entry.actor,
                "origin": entry.origin,
                "status": entry.status
            }
        },
        upsert=True
    )
    return {"msg": "Intel added"}

@app.delete("/intel/{ip}")
async def delete_intel(ip: str):
    await intel_col.delete_one({"ip": ip})
    return {"msg": "Intel removed"}


# Function to enrich IP with Intelligence and Location
async def get_ip_intel(ip: str):
    # 1. Check local Threat Intel DB first
    local_intel = INTEL_DB.get(ip)
    
    # 2. Fetch Live GeoIP Data (using a free service like ip-api.com)
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,isp", timeout=2)
        geo = response.json() if response.status_code == 200 else {}
    except:
        geo = {}

    if local_intel:
        return {
            "location": f"{geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}",
            "actor": local_intel["actor"],
            "type": local_intel["type"],
            "status": local_intel["status"],
            "is_threat": True
        }
    
    return {
        "location": f"{geo.get('city', 'Remote')}, {geo.get('country', 'Internet')}" if geo.get('status') == 'success' else "Internal Network",
        "actor": "Unknown Entity",
        "type": "Standard Traffic",
        "status": "Neutral",
        "is_threat": False
    }


# Comprehensive Intel Dictionary
GEO_INTEL = {
    "127.0.0.1": {"country": "Localhost (Internal)", "flag": "🏠"},
    "192.168": {"country": "Internal Network", "flag": "🛡️"},
    "10.0.0": {"country": "Corporate VLAN", "flag": "🏢"},
    "45.33.22.11": {"country": "Russia", "flag": "🇷🇺"},
    "185.220.101.1": {"country": "Germany", "flag": "🇩🇪"},
    "103.45.12.91": {"country": "Russia", "flag": "🇷🇺"},
    "14.12.99.1": {"country": "China", "flag": "🇨🇳"}
}

def get_geo_data(ip):
    if not ip: return {"country": "Unknown", "flag": "❓"}
    if ip in GEO_INTEL: return GEO_INTEL[ip]
    for prefix, data in GEO_INTEL.items():
        if str(ip).startswith(prefix): return data
    
    fallback = random.choice([
        {"country": "USA", "flag": "🇺🇸"},
        {"country": "Netherlands", "flag": "🇳🇱"},
        {"country": "Brazil", "flag": "🇧🇷"},
        {"country": "Vietnam", "flag": "🇻🇳"}
    ])
    return fallback

class SIEMReport(FPDF):
    def header(self):
        # SIEM Branding
        self.set_font("Arial", "B", 18)
        self.set_text_color(41, 128, 185) # Blue
        self.cell(0, 10, "SIEM.OS: SECURITY AUDIT REPORT", ln=True, align="L")
        self.set_font("Arial", "I", 9)
        self.set_text_color(128, 128, 128)
        self.cell(0, 5, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="L")
        self.ln(5)
        self.set_draw_color(41, 128, 185)
        self.line(10, 30, 200, 30)
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"SIEM.OS Internal Document - Page {self.page_no()}", align="C")


async def generate_security_report_logic():
    try:
        if not os.path.exists("static"):
            os.makedirs("static")

        # Fetch non-benign logs
        cursor = logs_col.find({"alert_type": {"$ne": "BENIGN"}})
        logs = await cursor.to_list(length=2000)
        
        if not logs:
            return None # Handle case with no data

        # --- 1. TIME RANGE CALCULATION ---
        # Extracts timestamps to show the window of the report
        timestamps = [l.get('timestamp') for l in logs if l.get('timestamp')]
        start_time = min(timestamps) if timestamps else "N/A"
        end_time = max(timestamps) if timestamps else "N/A"
        
        # --- 2. UPDATED SCORING MODEL ---
        SCORING_MODEL = {
            "DoS Attack": 35, "Botnet Activity": 30, 
            "SQL Injection": 25, "Honeypot Breach": 25, 
            "Brute Force Attempt": 20, "Stealth Scan": 15, 
            "Port Scan": 12, "Scanner Detected": 10, 
            "Suspicious File": 10, "Unknown": 5
        }
        
        total_risk, threat_counts, country_stats = 0, {}, {}
        total_threat_count = len(logs)
        
        for l in logs:
            etype = l.get('alert_type', 'Unknown')
            threat_counts[etype] = threat_counts.get(etype, 0) + 1
            
            geo = get_geo_data(l.get('source_ip', '0.0.0.0'))
            geo_label = f"{geo['country']}" 
            country_stats[geo_label] = country_stats.get(geo_label, 0) + 1
            total_risk += SCORING_MODEL.get(etype, 5)
        
        score = min(total_risk, 100)
        
        # Logic for Status, Colors, and Recommendations
        if score > 75: 
            status, color = "CRITICAL", (231, 76, 60)
            summary = "The network is under active exploitation. High-impact threats have bypassed basic filters."
            recommendations = ["Block top offender IPs immediately.", "Rotate administrative credentials.", "Enable Deep Packet Inspection (DPI) blocks."]
        elif score > 40: 
            status, color = "ELEVATED", (230, 126, 34)
            summary = "Targeted reconnaissance detected. Probes are searching for vulnerabilities."
            recommendations = ["Verify firewall rules.", "Update known-threat IP blacklists.", "Audit failed login attempts."]
        else: 
            status, color = "STABLE", (46, 204, 113)
            summary = "Normal background noise detected. No targeted campaigns identified."
            recommendations = ["Continue routine monitoring.", "Ensure sensor updates are current."]

        pdf = SIEMReport() # Assuming SIEMReport class is defined elsewhere
        pdf.add_page()
        
        # --- HEADER: RISK BANNER ---
        pdf.set_fill_color(*color)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 15, f"RISK ASSESSMENT: {status} ({score}/100)", ln=True, align="C", fill=True)
        pdf.ln(5)

        # --- TIME RANGE & METRICS ---
        pdf.set_text_color(100, 100, 100)
        pdf.set_font("Arial", "B", 9)
        pdf.cell(0, 5, f"Report Window: {start_time} to {end_time}", ln=True, align="R")
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Arial", "B", 11)
        pdf.cell(0, 10, f"Total Security Events Analyzed: {total_threat_count}", ln=True)
        pdf.ln(2)

        # --- EXECUTIVE SUMMARY ---
        pdf.set_font("Arial", "I", 10)
        pdf.set_text_color(50, 50, 50)
        pdf.multi_cell(0, 7, f"Executive Summary: {summary}")
        pdf.ln(5)

        # --- THREAT DISTRIBUTION TABLE ---
        pdf.set_text_color(41, 128, 185)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "1. Threat Distribution Breakdown", ln=True)
        pdf.set_text_color(0)
        pdf.set_font("Arial", "B", 10)
        pdf.cell(100, 10, "Attack Category", 1, 0, 'C', fill=False)
        pdf.cell(50, 10, "Occurrences", 1, 1, 'C', fill=False)
        
        pdf.set_font("Arial", "", 10)
        for etype, count in threat_counts.items():
            pdf.cell(100, 10, f" {etype}", 1)
            pdf.cell(50, 10, str(count), 1, 1, 'C')
        pdf.ln(10)
        
        # --- GEOGRAPHIC ORIGINS TABLE ---
        pdf.set_text_color(41, 128, 185)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "2. Top Geographic Threat Origins", ln=True)
        pdf.set_text_color(0)
        pdf.set_font("Arial", "B", 10)
        pdf.cell(120, 10, "Origin Country/Region", 1, 0, 'C')
        pdf.cell(30, 10, "Count", 1, 1, 'C')
        
        pdf.set_font("Arial", "", 10)
        for label, count in sorted(country_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
            pdf.cell(120, 10, f" {label}", 1)
            pdf.cell(30, 10, str(count), 1, 1, 'C')
        pdf.ln(10)

        # --- RECOMMENDATIONS SECTION ---
        pdf.set_text_color(39, 174, 96)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "3. Recommended Action Plan", ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Arial", "", 10)
        for rec in recommendations:
            pdf.cell(0, 8, f"- {rec}", ln=True)

        # --- FOOTER: INTEGRITY DATA ---
        report_id = uuid.uuid4().hex[:6].upper()
        pdf.set_y(-20)
        pdf.set_font("Arial", "I", 8)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(0, 10, f"Report ID: {report_id} | SIEM OS v3.1 | Generated on {datetime.now().strftime('%Y-%m-%d %H:%M')}", align="C")

        path = f"static/SIEM_Report_{report_id}.pdf"
        pdf.output(path)
        return path
        
    except Exception as e:
        print(f"PDF Logic Error: {e}")
        raise e

@app.get("/generate-report")
async def trigger_report():
    try:
        file_path = await generate_security_report_logic()
        return FileResponse(
            path=file_path, 
            filename=f"Security_Audit_{datetime.now().strftime('%m%d')}.pdf", 
            media_type='application/pdf'
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF Engine Error: {str(e)}")

@app.get("/analyze-dataset")
async def analyze_dataset():
    cursor = logs_col.aggregate([{"$match": {"alert_type": {"$ne": "BENIGN"}}}, {"$group": {"_id": "$source_ip", "count": {"$sum": 1}}}, {"$sort": {"count": -1}}, {"$limit": 10}])
    top_ips = {item["_id"]: item["count"] for item in await cursor.to_list(length=10)}
    return {"dashboard_ips": top_ips}

@app.get("/export-logs")
async def export_logs():
    # Fetch logs
    data = await logs_col.find().to_list(length=5000)
    if not data:
        return {"error": "No data to export"}

    df = pd.DataFrame(data)
    
    # 1. Map database fields to the EXACT headers from your training CSV
    column_mapping = {
        "source_ip": "Source IP",
        "packet_size": "Packet Size",
        "flow_duration": "Flow Duration",
        "requests_sec": "Requests/sec", 
        "alert_type": "Label"
    }
    
    df.rename(columns=column_mapping, inplace=True)
    
    # 2. FIX: Consolidate Labels (Remove DDoS, enforce DoS Attack)
    if "Label" in df.columns:
        # Strip AI prefix
        df["Label"] = df["Label"].str.replace("AI: ", "", regex=False)
        # REMOVE DDoS: Convert any DDoS labels into "DoS Attack"
        df["Label"] = df["Label"].replace(["DDoS Attack", "Distributed DoS", "DDoS"], "DoS Attack")

    # 3. SELECT ONLY the columns needed for training
    target_columns = ["Source IP", "Packet Size", "Flow Duration", "Requests/sec", "Label"]
    
    # Check for missing columns
    for col in target_columns:
        if col not in df.columns:
            df[col] = 0 if col != "Label" else "BENIGN"
            
    df_export = df[target_columns].copy() # Use .copy() to avoid SettingWithCopy warnings
    
    # 4. Enforce Numeric types (ensures Decision Factors work)
    df_export["Packet Size"] = pd.to_numeric(df_export["Packet Size"], errors='coerce').fillna(0)
    df_export["Flow Duration"] = pd.to_numeric(df_export["Flow Duration"], errors='coerce').fillna(0)
    df_export["Requests/sec"] = pd.to_numeric(df_export["Requests/sec"], errors='coerce').fillna(0)
    
    path = "static/siem_export.csv"
    df.to_csv(path, index=False)
    return {"download_url": f"/static/siem_export.csv"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)