# Bu modül, JSON formatındaki insan kaynakları (IK) kurallarını yükler ve kullanıcı girdisi ile eşleştirir.
import json
import os
from stanza_utils import process_text

# RuleEngine sınıfı, kural tabanlı niyet tespiti ve yanıt verme işlemlerini yönetir.
class RuleEngine:
    # Kuralları belleğe yükler
    def __init__(self, rule_file_path="rules/ik_rules.json"):
        with open(rule_file_path, "r", encoding="utf-8") as f:
            self.rules = json.load(f)

    # Girdi metnini işler, kurallarla eşleştirir ve en iyi eşleşen kuralı döner
    def match_rule(self, user_input: str):
        # Girdi metnini lemmatize et
        lemmas = process_text(user_input)
        best_match = None
        highest_score = 0
        WEAK_KEYWORDS = {"ne", "kadar", "nasıl", "nereden", "nereye", "hangi", "kaç"}

        for rule in self.rules:
            score = 0
            # Kuraldaki anahtar kelimelerden lemmalarla eşleşenleri bul
            matched_keywords = [kw for kw in rule["keywords"] if kw in lemmas]
            # Güçlü anahtar kelimeleri filtrele
            strong_matches = [kw for kw in matched_keywords if kw not in WEAK_KEYWORDS]
            if not strong_matches:
                continue  # güçlü kelime yoksa bu kuralı atla
            if matched_keywords and all(kw in WEAK_KEYWORDS for kw in matched_keywords):
                continue  # sadece zayıf kelimeler eşleştiyse bu kuralı atla
            # Skor hesaplama: güçlü kelimelere 1, zayıf kelimelere 0.2 puan ver
            for kw in rule["keywords"]:
                if kw in lemmas:
                    if kw in WEAK_KEYWORDS:
                        score += 0.2
                    else:
                        score += 1
            if score > 0:
                # Eşleşen keyword sayısı ve öncelik üzerinden skor ağırlıklandırması
                weighted_score = score + rule.get("priority", 1)
                if weighted_score > highest_score:
                    highest_score = weighted_score
                    best_match = rule

        # En iyi eşleşen kural varsa ilgili bilgileri döndür
        if best_match:
            return {
                "intent": best_match.get("intent"),
                "tags": best_match.get("tags"),
                "rule_based": best_match.get("response"),
                "source": "rule_engine"
            }

        return None