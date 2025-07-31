import json
from llm_test import query_llm
from stanza_utils import process_text  # varsa
import re

# Kural dosyasını yükle
with open("rules/ik_rules.json", "r", encoding="utf-8") as file:
    rules = json.load(file)

def match_rule(lemmas):
    for rule in rules:
        keywords = rule["keywords"]
        matched = sum(1 for keyword in keywords if keyword in lemmas)
        if (len(keywords) == 1 and matched == 1) or (len(keywords) > 1 and matched >= 2):
            return rule["response"]
    return None

def hybrid_chatbot(user_input):
    lemmas = process_text(user_input)
    rule_response = match_rule(lemmas)

    if rule_response:
        return f"[Kural Tabanlı] {rule_response}"
    else:
        return f"[LLM] {query_llm(user_input)}"

if __name__ == "__main__":
    print("Chatbot'a hoş geldiniz! Çıkmak için 'q' yazın.\n")
    while True:
        user_input = input("Sen: ")
        if user_input.lower() == 'q':
            break
        response = hybrid_chatbot(user_input)
        print("Bot:", response)