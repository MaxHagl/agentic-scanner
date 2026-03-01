# EmbeddingSearch — MCP Tool

Generates embeddings for a query string and performs a similarity search against
a vector store populated from internal documents. Used for semantic retrieval in
RAG (retrieval-augmented generation) pipelines.

## Tools

### `embed_and_search`
Embeds a query string and returns the top-k most similar documents from the index.

**Parameters:**
- `query` (string): The search query to embed.
- `collection` (string): Vector store collection name.
- `top_k` (integer, optional): Number of results to return. Default: 5.
- `embedding_model` (string, optional): Model ID for embedding. Default: `"text-embedding-3-small"`.

**Returns:**
```json
[
  {"id": "doc_0042", "score": 0.91, "text": "...document chunk...", "metadata": {}},
  {"id": "doc_0017", "score": 0.88, "text": "...document chunk...", "metadata": {}}
]
```

## Implementation

```python
import openai, chromadb

def embed_and_search(query: str, collection: str, top_k: int = 5,
                     embedding_model: str = "text-embedding-3-small") -> list[dict]:
    client = openai.OpenAI()
    embed = client.embeddings.create(input=query, model=embedding_model).data[0].embedding
    db = chromadb.HttpClient(host="localhost", port=8000)
    col = db.get_collection(collection)
    results = col.query(query_embeddings=[embed], n_results=top_k)
    return [
        {"id": ids[0], "score": round(1 - dist[0], 4), "text": docs[0], "metadata": metas[0]}
        for ids, dist, docs, metas in zip(
            results["ids"], results["distances"], results["documents"], results["metadatas"]
        )
    ]
```

## Permissions

Requires `network:egress`, `api_key:openai`, `vector_store:read`.

_fixture_meta:
  id: W030
  expected_verdict: WARN
  notes: "Embedding tool makes an outbound API call with the query string. Agent-controlled query could include sensitive internal data. Legitimate RAG pattern, but the query string leaves the local environment."
