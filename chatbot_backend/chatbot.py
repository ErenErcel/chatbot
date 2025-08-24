# Bu modül, kullanıcıdan gelen mesajları işler, kural tabanlı (rule-based) ve LLM yanıtlarını birleştirerek
# nihai cevabı üretir. İnsan kaynakları (İK) konularında özel portal ipuçları ekleyebilir, 
# oturum içi hafıza ve konuşma geçmişi yönetimi sağlar.

import json
import re
import datetime
import random
from llm_client import query_llm
from stanza_utils import process_text
from rule_engine import RuleEngine
from collections import deque

PORTAL_HINTS = [
    "Detaylar için İK portalına [Portal Linki] üzerinden ulaşabilirsiniz.",
    "İK portalı ([Portal Linki]) üzerinden kişisel kayıtlarınızı görüntüleyebilirsiniz.",
    "Hesabınızla İK portalına [Portal Linki] yoluyla giriş yapıp ilgili bilgileri kontrol edebilirsiniz.",
    "Kısa yol: İK portalı > Profil > Maaş/İzin bilgileri (erişim: [Portal Linki]).",
    "Güncel bilgiler İK portalında yer alır; erişim için: [Portal Linki].",
    "İK süreçlerine dair adımlar için İK portalını kullanabilirsiniz: [Portal Linki].",
    "İK portalı üzerinden ( [Portal Linki] ) ilgili sayfaya giderek inceleyebilirsiniz.",
    "Kurumsal erişim: İK portalı — [Portal Linki]."
]

def load_not_allowed_topics(path="filters/not_allowed_topics.txt"):  # Yasaklı konuları dosyadan yükler
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        # Dosya henüz mevcut değilse varsayılan olarak boş bir liste kullan
        return []

def build_not_allowed_regex(words):  # Yasaklı kelimeler için regex oluşturur
    if not words:
        return None
    escaped = [re.escape(w) for w in words]
    # Kelimenin tamamının eşleşmesini sağlamak için word-boundary kullanılır
    pattern = r"\b(?:" + "|".join(escaped) + r")\b"
    return re.compile(pattern, flags=re.IGNORECASE)

NOT_ALLOWED_TOPICS = load_not_allowed_topics()
NOT_ALLOWED_RE = build_not_allowed_regex(NOT_ALLOWED_TOPICS)

GREETING_WORDS = ["selam", "merhaba", "naber", "nasılsın", "günaydın", "iyi akşamlar", "iyi geceler"]

SESSION_CONTEXT = deque(maxlen=20)  # Son 20 konuşma tutulur: {"role": "user"|"bot", "text": str}
SESSION_FACTS = {}  # Oturumda hatırlanan basit anahtar-değer bilgileri, ör: {"user_name": "Eren", "bot_name": "Gemma"}

# Kullanıcı adını AYARLAMA: "benim adım X"
USER_NAME_SET_PAT = re.compile(r"\bbenim ad[ıi]m\s+([A-Za-zÇĞİÖŞÜçğıöşü]+)\b", re.IGNORECASE)
# Bot adını AYARLAMA: "senin adın X"
BOT_NAME_SET_PAT = re.compile(r"\bsenin ad[ıi]n\s+([A-Za-zÇĞİÖŞÜçğıöşü]+)\b", re.IGNORECASE)
# Kullanıcı adını SORMA: "adımı hatırlıyor musun?", "adım neydi?", "benim adım ne?"
USER_NAME_ASK_PAT = re.compile(
    r"\bad[ıi]m[ıi]?\s+(?:hat[ıi]rl[ıi]yor musun|neydi)\b|\bbenim ad[ıi]m ne\b",
    re.IGNORECASE,
)
# Bot adını SORMA: "senin adın ne?", "senin adın neydi?", "kendi adını hatırlıyor musun?"
BOT_NAME_ASK_PAT = re.compile(
    r"\bsenin ad[ıi]n\s+(?:ne|neydi|nedir|var mı)\b|\bkendi ad[ıi]n[ıi]?\s+hat[ıi]rl[ıi]yor musun\b",
    re.IGNORECASE,
)

def update_facts_from_user(text: str):  # Kullanıcıdan alınan bilgileri hafızaya kaydeder
    if not text:
        return
    # Kullanıcı kendi adını söyledi
    m_user = USER_NAME_SET_PAT.search(text)
    if m_user:
        name_val = m_user.group(1).strip()
        SESSION_FACTS["user_name"] = name_val
        SESSION_FACTS["name"] = name_val  # geriye dönük uyumluluk
        return

    # Kullanıcı botun adını belirtti
    m_bot = BOT_NAME_SET_PAT.search(text)
    if m_bot:
        SESSION_FACTS["bot_name"] = m_bot.group(1).strip()
        return

def answer_if_memory_query(text: str):  # Kullanıcı hafızadaki bilgileri sorarsa yanıtlar
    if not text:
        return None

    # Kullanıcının adını soruyor mu?
    if USER_NAME_ASK_PAT.search(text):
        name = SESSION_FACTS.get("user_name") or SESSION_FACTS.get("name")
        return name if name else "Henüz adını kaydetmemişim gibi görünüyor. İstersen 'Benim adım X' diyebilirsin."

    # Botun adını soruyor mu?
    if BOT_NAME_ASK_PAT.search(text):
        bot_name = SESSION_FACTS.get("bot_name")
        return bot_name if bot_name else "Henüz bir adım yok. İstersen 'Senin adın X' diyerek belirleyebilirsin."

    return None

def reset_session_context():  # Oturumdaki geçmişi ve bilgileri sıfırlar
  SESSION_CONTEXT.clear()
  SESSION_FACTS.clear()

def render_context_snippet(max_chars: int = 1200) -> str:  # Son konuşmaları kısa bir özet olarak döndürür
  # Kısa bir konuşma dökümü oluşturur: "K: ...\nB: ...\n"
  parts = []
  for item in SESSION_CONTEXT:
    prefix = "K:" if item["role"] == "user" else "B:"
    parts.append(f"{prefix} {item['text']}")
  text = "\n".join(parts)
  return text[-max_chars:] if len(text) > max_chars else text

def is_noise_text(t: str) -> bool:  # Girilen metnin anlamsız olup olmadığını kontrol eder
    s = (t or "").strip()
    if len(s) <= 1:
        return True
    # Sezgisel: Harf olmayan karakterler %60'tan fazlaysa veya hiç sesli harf yoksa anlamsız kabul edilir
    letters = sum(1 for ch in s if ch.isalpha())
    non_letters = len(s) - letters
    if len(s) > 0 and non_letters / len(s) > 0.6:
        return True
    vowels = set("aeıioöuüAEIİOÖUÜ")
    if not any(ch in vowels for ch in s):
        return True
    return False

rule_engine = RuleEngine()

def log_chat(user_input, response, response_type, intent=None):  # Sohbet geçmişini dosyaya kaydeder
    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "user_input": user_input,
        "response": response,
        "intent": intent,
        "type": response_type
    }
    with open("chat_history.json", "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")

TIME_RE = re.compile(r"\b\d{1,2}:\d{2}\b") #saat redexi
NUM_RE = re.compile(r"\b\d+[\.,]?\d*\b") #sayı redexi

PORTAL_INTENTS = {
    "maas_bilgisi",           # Maaşımı nereden öğrenebilirim?
    "sigorta_baslangic",     # Sigortam ne zaman başlar?
    "prim_odeme",            # Prim ödemesi alıyor muyum?
    "yemek_karti_yukleme",   # Yemek kartı ne zaman yüklenir?
}
PORTAL_Q_RE = re.compile(
    r"(maaş(?:ım)?\s+nereden\s+öğrenebilirim|sigortam\s+ne\s+zaman\s+başlar|prim\s+(?:ödemesi\s+)?al[ıi]yor\s+muyum|yemek\s+kart[ıi]\s+ne\s+zaman\s+y[üu]klenir)",
    re.IGNORECASE,
)

def contains_key_facts(text: str, ref: str) -> bool:  # Yanıtta önemli sayısal/tarihsel bilgilerin korunup korunmadığını kontrol eder
    if not text or not ref:
        return False
    times = set(TIME_RE.findall(ref))
    nums = set(NUM_RE.findall(ref))

    t = text
    r = ref

    if times:
        # Referanstaki tüm saat ifadeleri yanıtta da bulunmalı
        if not all(tk in t for tk in times):
            return False
    if nums:
        # Referanstaki en az bir sayısal ifade yanıtta da bulunmalı
        if not any(n in t for n in nums):
            return False

    if times or nums:
        return True

    # Sayı veya saat yoksa: normalize edip gevşek içerme kontrolü yapılır
    def _norm(s: str) -> str:
        s = s.lower()
        s = re.sub(r"\s+", " ", s).strip()
        return s

    tn = _norm(t)
    rn = _norm(r)

    return (rn in tn) or (tn in rn)

def format_final_response(rule_response, llm_response, intent=None, prefer_llm_for_rule: bool = False):  # Son cevabı kural ve LLM yanıtlarını birleştirerek oluşturur
    """
    Rule-based ve LLM cevabını ortak bir formatta birleştirir.
    Varsayılan: Kuralı esas al. 
    - prefer_llm_for_rule=True ise: kural + LLM birleşik "hybrid" yanıt üret.
    - Aksi halde: LLM çıktısı kuralın sayısal/tarih/saat bilgilerini KORUYORSA LLM göster; yoksa kural göster.
    """
    rule_response = (rule_response or "").strip()
    llm_response = (llm_response or "").strip()

    def _norm(s: str) -> str:
        return re.sub(r"\s+", " ", (s or "").strip().lower())

    source = "rule_based"
    if rule_response:
        if llm_response:
            if prefer_llm_for_rule:
                rr_n = _norm(rule_response)
                llm_n = _norm(llm_response)
                if rr_n in llm_n:
                    final = llm_response
                elif llm_n in rr_n:
                    final = rule_response
                else:
                    final = f"{rule_response} {llm_response}"
                source = "hybrid"
            else:
                if contains_key_facts(llm_response, rule_response):
                    final = llm_response
                    source = "llm"
                else:
                    final = rule_response
                    source = "rule_based"
        else:
            final = rule_response
            source = "rule_based"
    else:
        final = llm_response or "Cevap üretilemedi."
        source = "llm" if llm_response else "rule_based"

    return {
        "rule_based": rule_response,
        "llm": llm_response,
        "final_answer": final,
        "intent": intent,
        "source": source,
    }

def process_input_step(context):  # Kullanıcı girdisini işler ve önişleme yapar
    user_input = context["input"]
    update_facts_from_user(user_input)
    context["lemmas"] = process_text(user_input)
    return context

def rule_match_step(context):  # Kurallara göre eşleşen bir yanıt olup olmadığını kontrol eder
    result = rule_engine.match_rule(context["input"])
    if result:
        context["rule_response"] = result["rule_based"]
        context["intent"] = result.get("intent")
        context["tags"] = result.get("tags")
    else:
        context["rule_response"] = None
        context["intent"] = None
    return context

def llm_query_step(context):  # LLM'den cevap almak için gerekli adımları uygular
    user_input = context["input"].lower()
    portal_hint = random.choice(PORTAL_HINTS)

    # Filtreleme için küçük harfe çevrilmiş metin ve lemmalar birleştirilir
    lemmas = context.get("lemmas") or []
    combined_text = (user_input + " " + " ".join(lemmas)).lower()

    # Kullanıcı ad/isim belirliyorsa doğrudan yanıtla (LLM atlanır)
    set_user = USER_NAME_SET_PAT.search(context["input"])
    set_bot = BOT_NAME_SET_PAT.search(context["input"])
    if set_user or set_bot:
        uname = SESSION_FACTS.get("user_name")
        bname = SESSION_FACTS.get("bot_name")
        if set_user and set_bot and uname and bname:
            context["llm_response"] = f"Tamam, senin adın {uname}, benim adım {bname}."
            return context
        if set_user and uname:
            context["llm_response"] = f"Memnun oldum {uname}!"
            return context
        if set_bot and bname:
            context["llm_response"] = f"Tamam, adım {bname}."
            return context

    # Gürültü koruması: Girdi anlamsızsa, geçmiş kullanmadan kibarca yanıt ver
    if is_noise_text(user_input):
        context["llm_response"] = "Anladım, ama mesajın pek anlaşılır değil. Biraz daha detay verebilir misin?"
        return context

    # Kullanıcı oturum bilgisinden yanıtlanabilecek bir şey soruyorsa, doğrudan cevapla
    mem_ans = answer_if_memory_query(context["input"])
    if mem_ans is not None:
        context["llm_response"] = mem_ans
        return context

    convo_snippet = render_context_snippet()
    has_history = bool(convo_snippet.strip())

    # Selamlama kısayolu: Portal ipucu olmadan kibarca yanıtla
    if any(w in combined_text for w in GREETING_WORDS):
        prompt = (
            "SİSTEM TALİMATI:\n"
            "- Sadece kullanıcıya kısa bir selamlama ve yardım teklifi yaz. Meta yorum yapma.\n\n"
            f"KULLANICI MESAJI:\n{user_input}\n"
        )
        context["llm_response"] = query_llm(prompt)
        return context

    # Yasaklı kelime filtresi: Tam kelime olarak geçen yasaklı bir ifade varsa engelle
    if NOT_ALLOWED_RE and NOT_ALLOWED_RE.search(combined_text):
        context["llm_response"] = "Bu konu hakkında yardımcı olamıyorum."
        return context

    try:
        if context.get("rule_response"):
            # Sadece bazı İK soruları için portal ipucu + LLM ile yeniden ifade eklenir
            want_portal = (context.get("intent") in PORTAL_INTENTS) or bool(PORTAL_Q_RE.search(context["input"]))
            context["prefer_llm_for_rule"] = bool(want_portal)

            if want_portal:
                prompt = (
                    "SİSTEM TALİMATI:\n"
                    "- KURAL CEVABI temel alınacak, metnin özünü ve rakamsal/tarih/saat bilgilerini AYNEN koru.\n"
                    "- YANITINI yalnızca 'KULLANICI MESAJI'na ver; geçmişi sadece bağlam olarak kullan.\n"
                    "- Kısa ve net Türkçe yaz. Gerekirse maddeler kullan.\n"
                    "- Uydurma veya kural dışı bilgi ekleme. Belirsizse dürüstçe belirt.\n"
                    "- Aşağıdaki ipucunu bağlama uygun şekilde metne yedir (aynen kopyalamak zorunda değilsin):\n"
                    f"  > {portal_hint}\n\n"
                    + (f"ÖNCEKİ KONUŞMA (son 20):\n{convo_snippet}\n\n" if has_history else "")
                    + f"KULLANICI MESAJI:\n{user_input}\n\n"
                    + f"KURAL CEVABI:\n{context['rule_response']}\n"
                )
                context["llm_response"] = query_llm(prompt)
            else:
                # Diğer kural tabanlı eşleşmelerde portal ipucu ve LLM olmadan kural yanıtı döndürülür
                context["llm_response"] = ""
            return context
        else:
            prompt = (
                "SİSTEM TALİMATI:\n"
                "- YANITINI DAİMA yalnızca 'KULLANICI MESAJI'na ver; geçmişi sadece bağlam olarak kullan.\n"
                "- Kısa ve net Türkçe yaz. Gerekirse maddeler kullan.\n"
                "- Kullanıcının adını sadece doğrudan sorarsa belirt; aksi halde ad veya tek kelimeyle yanıt verme.\n"
                "- Uydurma bilgi verme; belirsizse açıkça söyle.\n"
                + (f"ÖNCEKİ KONUŞMA (son 20):\n{convo_snippet}\n\n" if has_history else "")
                + f"KULLANICI MESAJI:\n{user_input}\n"
            )
            context["llm_response"] = query_llm(prompt)
    except Exception as e:
        context["llm_response"] = f"[LLM HATA] {str(e)}"
        log_chat(user_input, context["llm_response"], "llm-error", intent=context.get("intent"))
    return context

def format_response_step(context):  # Nihai cevabı oluşturur ve oturum geçmişine ekler
    rule_response = context.get("rule_response")
    llm_response = context.get("llm_response")
    context["result"] = format_final_response(
        rule_response,
        llm_response,
        intent=context.get("intent"),
        prefer_llm_for_rule=bool(context.get("prefer_llm_for_rule"))
    )
    # Bu turu geçici belleğe kaydet (son 20 tutulur)
    try:
        SESSION_CONTEXT.append({"role": "user", "text": context.get("input", "")})
        SESSION_CONTEXT.append({"role": "bot", "text": context["result"].get("final_answer", "")})
    except Exception:
        pass
    # Kaynağı artık format_final_response belirliyor; burada tekrar yazmıyoruz.
    return context

def run_pipeline(user_input):  # Tüm sohbet işleme adımlarını sıralı şekilde çalıştırır
    context = {"input": user_input}
    try:
        steps = [process_input_step, rule_match_step, llm_query_step, format_response_step]
        for step in steps:
            context = step(context)
        return context["result"]
    except Exception as e:
        error_message = f"[HATA] NLP işleme başarısız: {str(e)}"
        log_chat(user_input, error_message, "error")
        return {
            "rule_based": None,
            "llm": None,
            "final_answer": error_message
        }

def _search_chat_history_internal(keyword=None, date_str=None):  # Sohbet geçmişinde anahtar kelime ve tarihe göre arama yapar
    try:
        with open("chat_history.json", "r", encoding="utf-8") as f:
            results = []
            for line in f:
                entry = json.loads(line)

                matches_keyword = True
                matches_date = True

                if keyword:
                    matches_keyword = re.search(keyword, entry["user_input"], re.IGNORECASE)

                if date_str:
                    try:
                        parsed_date = datetime.datetime.strptime(date_str + " 2025", "%d %B %Y").date()
                        entry_date = datetime.datetime.fromisoformat(entry["timestamp"]).date()
                        matches_date = (parsed_date == entry_date)
                    except:
                        continue

                if matches_keyword and matches_date:
                    results.append(entry)
        return results
    except FileNotFoundError:
        return []

def get_chat_history(keyword=None, date_str=None) -> list:  # Sohbet geçmişini dışarıya sunar
    return _search_chat_history_internal(keyword, date_str)

def get_response(user_input: str) -> dict:  # Kullanıcıdan gelen mesaja karşılık yanıt üretir
    return run_pipeline(user_input)

def session_reset():  # Oturumu sıfırlar
    reset_session_context()
    return {"ok": True}

if __name__ == "__main__":
    print("Chatbot'a hoş geldiniz! Çıkmak için 'q' yazın.\n")
    while True:
        user_input = input("Sen: ")
        if user_input.lower() == 'q':
            break
        if user_input.lower().startswith("geçmiş"):
            parts = user_input.split()
            keyword = None
            date = None

            if len(parts) >= 2:
                keyword = parts[1]
            if len(parts) >= 3:
                date = parts[2] + " " + parts[3] if len(parts) >= 4 else parts[2]

            results = _search_chat_history_internal(keyword, date)
            if not results:
                print("❌ Hiçbir eşleşme bulunamadı.")
            else:
                print(f"🔎 {len(results)} eşleşme bulundu:\n")
                for r in results:
                    print(f"🕓 {r['timestamp']}")
                    print(f"👤 {r['user_input']}")
                    print(f"🤖 ({r['type']}): {r['response']}\n")
            continue
        response = run_pipeline(user_input)
        log_chat(user_input, response["final_answer"], response_type=response.get("source"), intent=response.get("intent"))
        print("Bot:", response["final_answer"])