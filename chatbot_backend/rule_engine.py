import json
from nlp.processor import TurkishNLP
import re

class RuleEngine:
    def __init__(self, rule_file_path="rules/ik_rules.json"):
        with open(rule_file_path, "r", encoding="utf-8") as f:
            self.rules = json.load(f)
        self.analyzer = TurkishNLP()

    def normalize_lemma(self, lemma):
        return re.sub(r"(ım|im|um|üm|ı|i|u|ü|m|n|ıı|mi|mu|nu)$", "", lemma)

    def get_response(self, message):
        lemmas = [self.normalize_lemma(token["lemma"]) for token in self.analyzer.analyze(message)]

        for keyword, response in self.rules.items():
            # Desteklenen çok sözcüklü anahtarları boşlukla ayırarak kontrol et
            keyword_lemmas = keyword.split()
            if all(kw in lemmas for kw in keyword_lemmas):
                return response

        return "Maalesef bu konuda bir bilgim yok."

    def match_rule(self, text):
        return self.get_response(text)