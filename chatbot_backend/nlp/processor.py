# nlp/processor.py
# Bu dosya, Stanza kullanarak Türkçe metin işleme için bir sınıf tanımlar.

import stanza

# Türkçe metinleri Stanza ile işlemek için sınıf
class TurkishNLP:
    # Stanza pipeline'ını Türkçe için tokenize, mwt, pos ve lemma işlemcileriyle başlatır
    def __init__(self):
        self.nlp = stanza.Pipeline(lang="tr", processors="tokenize,mwt,pos,lemma")

    # Girdi metni işler ve kelimelerin metin, lemma ve POS etiketlerini içeren liste döner
    def analyze(self, text):
        doc = self.nlp(text)
        result = []
        for sent in doc.sentences:
            for word in sent.words:
                result.append({
                    "text": word.text,
                    "lemma": word.lemma,
                    "pos": word.upos
                })
        return result