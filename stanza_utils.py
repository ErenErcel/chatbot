import stanza

# Türkçe pipeline yalnızca bir kez yüklenir
nlp = stanza.Pipeline("tr", processors="tokenize,mwt,pos,lemma", use_gpu=False)

def process_text(text):  # Girdi metnini işleyip lemmatize edilmiş kelimeleri döndürür
    """
    Girdi metnini işler ve lemmatize edilmiş kelime listesini döndürür.
    Örnek: "Maaşımı ne zaman alırım?" -> ["maaş", "almak"]
    """
    doc = nlp(text)
    lemmas = []

    for sentence in doc.sentences:
        for word in sentence.words:
            # Sadece anlamlı kelimeleri almak için POS filtreleme eklenebilir
            lemmas.append(word.lemma.lower())

    return lemmas