def retrieve_knowledge(query, knowledge):
    query = query.lower()

    results = []

    keyword_mapping = {
        "shipping": ["shipping", "delivery", "deliver", "tracking"],
        "returns": ["return", "returns"],
        "refunds": ["refund", "refunds", "money back"],
        "warranty": ["warranty", "guarantee"],
        "products": ["product", "products", "laptop", "phone", "keyboard", "earbuds"],
        "faq": ["faq", "track order"],
        "malicious_product": ["security scanner","security testing"]
    }

    for category, keywords in keyword_mapping.items():

        if any(keyword in query for keyword in keywords):

            if category in knowledge:
                results.append(knowledge[category])

    return "\n\n".join(results)

# if __name__ == "__main__":

#     from knowledge import load_knowledge

#     knowledge = load_knowledge()

#     query = "What is the TechMart scanner?"

#     result = retrieve_knowledge(query, knowledge)

#     print("\n--- RETRIEVED KNOWLEDGE ---")
#     print(result)