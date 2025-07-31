from llm_client import LLMClient

client = LLMClient()

if __name__ == "__main__":
    cevap = client.generate("Çalışma saatleri nedir?")
    print(cevap)


def query_llm(prompt: str) -> str:
    prompt = "Lütfen cevabını Türkçe ver. " + prompt
    return client.generate(prompt)