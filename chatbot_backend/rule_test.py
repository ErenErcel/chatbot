from rule_engine import RuleEngine

# RuleEngine örneği oluştur
engine = RuleEngine()

# Test cümleleri
sentences = [
    "Yıllık iznim ne kadar?",
    "Maaşımı nasıl öğrenebilirim?",
    "Maaşım ne zaman yatırılır?",
    "İşe giriş prosedürü nedir?",
    "Bugün hava nasıl?"  # Eşleşmeyen soru
]

for sentence in sentences:
    result = engine.match_rule(sentence)
    print(f"Soru: {sentence}")
    print(f"Cevap: {result}")
    print("-" * 30)