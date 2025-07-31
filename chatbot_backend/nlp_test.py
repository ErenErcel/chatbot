from nlp.processor import TurkishNLP

analyzer = TurkishNLP()
tokens = analyzer.analyze("Yıllık iznim ne kadar?")
tokens = analyzer.analyze("Maaşımı nasıl öğrenebilirim?")


for token in tokens:
    print(token)

    