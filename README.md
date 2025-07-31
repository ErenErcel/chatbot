nlp.py:Kullanıcının yazdığı metni Stanza ile parçalayıp anlamak için NLP ön işlemelerini yapar.
rules.py:Kuralları JSON dosyasından okuyup anahtar kelime eşleşmelerine göre yanıt mantığını içerir.
chatbot.py:Kural tabanlı ve LLM destekli hibrit chatbotun karar mekanizmasını çalıştırır.
llm_client.py:Ollama üzerinden Llama3 gibi büyük dil modellerine istek atmak için API istemcisidir.
llm_test.py:LLM tarafının doğru çalışıp çalışmadığını test etmek için kullanılan dosyadır.
nlp_test.py:Türkçe NLP çıktılarının (lemma, pos, kök) düzgün çalışıp çalışmadığını test eder.
rule_engine.py:Kuralları çalıştıran, eşleşme puanlarını hesaplayan ve en uygun yanıtı döndüren motordur.
rule_test.py:Kural sisteminin doğru şekilde eşleşip eşleşmediğini test etmek için yazılmış test dosyasıdır.
stanza_utils.py:Stanza’nın Türkçe modeliyle gelen ham NLP çıktısını daha kullanılabilir hale getiren yardımcı fonksiyonları içerir.
