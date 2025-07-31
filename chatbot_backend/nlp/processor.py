# nlp/processor.py

import stanza

class TurkishNLP:
    def __init__(self):
        self.nlp = stanza.Pipeline(lang="tr", processors="tokenize,mwt,pos,lemma")

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