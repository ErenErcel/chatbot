import os
import json
import time
from fastapi.responses import JSONResponse
from fastapi import HTTPException
from fastapi import Request
from chatbot import get_response, get_chat_history, session_reset
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from fastapi.encoders import jsonable_encoder

# --- Depolama yardımcıları ---
def get_data_dir() -> str:  # Veri dosyaları için çalışma dizinini belirler/oluşturur
    # Esneklik için önce ortam değişkenini (CHATBOT_DATA_DIR) kullan
    base = os.environ.get("CHATBOT_DATA_DIR")
    if not base:
        base = os.path.join(os.path.expanduser("~"), ".chatbot_backend")
    os.makedirs(base, exist_ok=True)
    return base


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Geçici olarak tüm kaynaklara izin verildi (debug için)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ChatRequest(BaseModel):
    message: str


# Sağlık (health) uç noktası
@app.get("/health")
async def health():  # Servisin ayakta olduğunu bildirir
    return JSONResponse(content={"status": "ok"})


# Reset ephemeral in-memory conversation context
@app.post("/session/reset")
async def reset_session_endpoint():  # Oturum içi hafızayı sıfırlar
    try:
        return JSONResponse(content=session_reset())
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Hata ayıklama uç noktası: önemli dosya yollarının varlığı ve boyutunu raporlar
@app.get("/debug/paths")
async def debug_paths():  # Dosya yollarını ve durumlarını döndürür
    data_dir = get_data_dir()
    paths = {
        "data_dir": get_data_dir(),
        "ratings": "/Users/erenercel/Desktop/Vscode-workspace/chatbot_backend/ratings.json",
        "chat_history": "/Users/erenercel/Desktop/Vscode-workspace/chatbot_backend/chat_history.json",
    }
    info = {}
    for k, p in paths.items():
        if k == "data_dir":
            info[k] = p
            continue
        info[k] = {"path": p, "exists": os.path.exists(p), "size": os.path.getsize(p) if os.path.exists(p) else 0}
    return JSONResponse(content=info)



# Rating endpoint
@app.post("/rate")
async def rate(request: Request):  # Kullanıcı puanını (1–5) kaydeder
    # Ham gövdeyi oku (içerik türünden bağımsız olarak)
    raw = await request.body()
    rating = None

    # Önce JSON olarak yorumlamayı dene
    try:
        if raw:
            rating = json.loads(raw.decode("utf-8")).get("rating")
    except Exception:
        rating = None

    # Tip ve aralık doğrulaması yap
    try:
        rating = int(rating)
        assert 1 <= rating <= 5
    except Exception:
        raise HTTPException(status_code=400, detail="rating 1–5 arası olmalı")

    # ratings.json için sabit yol kullan
    path = "/Users/erenercel/Desktop/Vscode-workspace/chatbot_backend/ratings.json"

    buffer = []
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                buffer = json.load(f)
        except json.JSONDecodeError:
            buffer = []

    buffer.append({"ts": int(time.time()), "rating": rating})

    with open(path, "w", encoding="utf-8") as f:
        json.dump(buffer, f, indent=2, ensure_ascii=False)

    return JSONResponse(content={"ok": True})




@app.post("/chat")
async def chat_endpoint(chat: ChatRequest):  # Mesajı işler, yanıt döner ve geçmişe yazar
    user_input = chat.message

    response_data = get_response(user_input)

    # Sohbeti chat_history.json dosyasına ekle
    log_entry = {
        "ts": int(time.time()),
        "question": user_input,
        "answer": response_data.get("final_answer") if isinstance(response_data, dict) else str(response_data),
        "intent": response_data.get("intent") if isinstance(response_data, dict) else None,
        "source": response_data.get("source") if isinstance(response_data, dict) else None
    }
    # Sohbet geçmişini sabit bir yola kaydet
    log_file = "/Users/erenercel/Desktop/Vscode-workspace/chatbot_backend/chat_history.json"

    buffer = []
    if os.path.exists(log_file):
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                buffer = json.load(f)
        except json.JSONDecodeError:
            buffer = []
    buffer.append(log_entry)
    with open(log_file, "w", encoding="utf-8") as f:
        json.dump(buffer, f, indent=2, ensure_ascii=False)

    return JSONResponse(content=response_data)


@app.get("/history")
async def history_endpoint(keyword: Optional[str] = None, date: Optional[str] = None):  # Geçmişi anahtar kelime/tarihe göre döndürür
    results = get_chat_history(keyword, date)
    return JSONResponse(content={"results": results})


@app.get("/faq")
async def get_faq():  # SSS (örnek sorular) listesini döndürür
    data = {
        "questions": [
            "Maaşım ne zaman yatacak?",
            "İzin hakkım ne kadar?",
            "Bayramda çalışırsam ek ücret alır mıyım?",
            "Hafta sonu mesai sayılır mı?",
            "Avans talep edebilir miyim?",
            "SGK girişimi nasıl öğrenirim?",
            "Vardiyamı değiştirebilir miyim?",
            "Yıllık izin nasıl alınır?"
        ]
    }
    return JSONResponse(content=jsonable_encoder(data))

@app.get("/intents/stats")
async def intent_stats():  # Günlükten niyet (intent) istatistiklerini çıkarır
    try:
        log_file = "/Users/erenercel/Desktop/Vscode-workspace/chatbot_backend/chat_history.json"
        if not os.path.exists(log_file):
            return JSONResponse(content={"results": {}})

        with open(log_file, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []

        stats = {}
        for entry in data:
            intent = entry.get("intent")
            if intent:
                stats[intent] = stats.get(intent, 0) + 1

        sorted_stats = dict(sorted(stats.items(), key=lambda item: item[1], reverse=True))
        return JSONResponse(content={"results": sorted_stats})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
# Sadece okuma amaçlı dökümler (hızlı doğrulama için)
@app.get("/ratings/dump")
async def ratings_dump():  # Puanlar dosyasını ham olarak döndürür (debug)
    path = "/Users/erenercel/Desktop/Vscode-workspace/chatbot_backend/ratings.json"
    if not os.path.exists(path):
        return JSONResponse(content=[])
    try:
        with open(path, "r", encoding="utf-8") as f:
            return JSONResponse(content=json.load(f))
    except json.JSONDecodeError:
        return JSONResponse(content=[])

@app.get("/history/dump")
async def history_dump():  # Sohbet geçmişini ham olarak döndürür (debug)
    path = "/Users/erenercel/Desktop/Vscode-workspace/chatbot_backend/chat_history.json"
    if not os.path.exists(path):
        return JSONResponse(content=[])
    try:
        with open(path, "r", encoding="utf-8") as f:
            return JSONResponse(content=json.load(f))
    except json.JSONDecodeError:
        return JSONResponse(content=[])