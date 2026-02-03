from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Optional
import re
import os
import uuid

app = FastAPI()

API_KEY = os.getenv("API_KEY")

# ------------------ Models ------------------

class MessageEvent(BaseModel):
    conversation_id: Optional[str] = None
    message: str
    sender: str  # "scammer"

class Intelligence(BaseModel):
    bank_accounts: List[str] = []
    upi_ids: List[str] = []
    phishing_urls: List[str] = []

class APIResponse(BaseModel):
    scam_detected: bool
    conversation_id: str
    agent_reply: str
    extracted_intelligence: Intelligence
    engagement_turns: int

# ------------------ Memory Store ------------------

MEMORY: Dict[str, List[str]] = {}

# ------------------ Scam Detection ------------------

SCAM_KEYWORDS = [
    "urgent", "verify", "account blocked", "otp",
    "payment", "upi", "bank", "click", "refund"
]

def detect_scam(text: str) -> bool:
    score = sum(1 for k in SCAM_KEYWORDS if k in text.lower())
    url_found = bool(re.search(r"https?://", text))
    return score >= 2 or url_found

# ------------------ Intelligence Extraction ------------------

def extract_intel(text: str) -> Intelligence:
    return Intelligence(
        bank_accounts=re.findall(r"\b\d{9,18}\b", text),
        upi_ids=re.findall(r"\b[\w.\-]+@[\w]+\b", text),
        phishing_urls=re.findall(r"https?://[^\s]+", text),
    )

# ------------------ Autonomous Agent ------------------

def honey_agent(history: List[str]) -> str:
    last = history[-1].lower()

    if "payment" in last or "upi" in last:
        return "Okay, I can try sending it. Can you confirm the exact UPI ID or account number?"

    if "link" in last or "verify" in last:
        return "I’m not very good with links 😅 Can you resend it or explain what I should see?"

    if "urgent" in last:
        return "Sorry, I was away. What exactly do I need to do now?"

    return "I want to fix this properly. Can you guide me step by step?"

# ------------------ API Endpoint ------------------

@app.post("/honeypot", response_model=APIResponse)
def honeypot_endpoint(
    event: MessageEvent,
    x_api_key: str = Header(...)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    convo_id = event.conversation_id or str(uuid.uuid4())
    MEMORY.setdefault(convo_id, []).append(event.message)

    scam = detect_scam(" ".join(MEMORY[convo_id]))
    intel = extract_intel(event.message)

    reply = ""
    if scam:
        reply = honey_agent(MEMORY[convo_id])

    return APIResponse(
        scam_detected=scam,
        conversation_id=convo_id,
        agent_reply=reply,
        extracted_intelligence=intel,
        engagement_turns=len(MEMORY[convo_id])
    )
