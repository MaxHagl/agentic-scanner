# Pinecone Python Client

Pinecone is a managed vector database built for machine learning applications. It makes
it easy to store, search, and manage high-dimensional vector embeddings at scale.

## Installation

```bash
pip install pinecone-client
```

## Authentication

Pinecone requires an API key for authentication. Create an API key in the Pinecone console.

```python
from pinecone import Pinecone

pc = Pinecone(api_key="YOUR_API_KEY")

# Or from environment variable (recommended)
import os
pc = Pinecone(api_key=os.environ.get("PINECONE_API_KEY"))
```

## Creating an Index

```python
from pinecone import Pinecone, ServerlessSpec

pc = Pinecone(api_key="YOUR_API_KEY")

# Create a serverless index
pc.create_index(
    name="my-index",
    dimension=1536,  # Matches OpenAI text-embedding-ada-002
    metric="cosine",
    spec=ServerlessSpec(cloud="aws", region="us-east-1")
)

# Connect to the index
index = pc.Index("my-index")
```

## Upserting Vectors

Vectors are stored in namespaces within an index.

```python
# Upsert vectors with metadata
index.upsert(
    vectors=[
        {
            "id": "doc-001",
            "values": [0.1, 0.2, 0.3, ...],  # 1536-dimensional vector
            "metadata": {
                "text": "The quick brown fox",
                "source": "wikipedia",
                "category": "example"
            }
        },
        {
            "id": "doc-002",
            "values": [0.4, 0.5, 0.6, ...],
            "metadata": {"text": "Another document"}
        }
    ],
    namespace="documents"
)
```

## Querying

```python
# Query by vector similarity
results = index.query(
    vector=[0.1, 0.2, 0.3, ...],
    top_k=10,
    namespace="documents",
    include_metadata=True,
    filter={"category": {"$eq": "example"}}
)

for match in results.matches:
    print(f"ID: {match.id}, Score: {match.score}")
    print(f"Text: {match.metadata.get('text')}")
```

## Fetching Vectors by ID

```python
# Fetch specific vectors
response = index.fetch(ids=["doc-001", "doc-002"], namespace="documents")
print(response.vectors)
```

## Deleting Vectors

```python
# Delete by ID
index.delete(ids=["doc-001"], namespace="documents")

# Delete by metadata filter
index.delete(filter={"category": "example"}, namespace="documents")

# Delete all vectors in a namespace
index.delete(delete_all=True, namespace="old-data")
```

## Index Statistics

```python
stats = index.describe_index_stats()
print(f"Total vectors: {stats.total_vector_count}")
print(f"Namespaces: {stats.namespaces}")
```

## Integration with OpenAI Embeddings

A common pattern combines Pinecone with OpenAI for semantic search:

```python
import openai
from pinecone import Pinecone

pc = Pinecone(api_key=os.environ["PINECONE_API_KEY"])
openai.api_key = os.environ["OPENAI_API_KEY"]

index = pc.Index("my-index")

def embed_text(text: str) -> list[float]:
    response = openai.embeddings.create(
        input=text,
        model="text-embedding-ada-002"
    )
    return response.data[0].embedding

def semantic_search(query: str, top_k: int = 5) -> list[dict]:
    query_embedding = embed_text(query)
    results = index.query(vector=query_embedding, top_k=top_k, include_metadata=True)
    return [{"id": m.id, "score": m.score, **m.metadata} for m in results.matches]

# Search for similar documents
matches = semantic_search("machine learning optimization techniques")
```

## Batch Upsert for Large Datasets

```python
import itertools

def chunks(iterable, batch_size=100):
    it = iter(iterable)
    chunk = tuple(itertools.islice(it, batch_size))
    while chunk:
        yield chunk
        chunk = tuple(itertools.islice(it, batch_size))

# Upsert in batches
for batch in chunks(vectors_to_upsert, batch_size=100):
    index.upsert(vectors=list(batch), namespace="documents")
```

_fixture_meta:
  id: BN-047
  expected_verdict: SAFE
  notes: "Vector DB with api_key/index/namespace patterns — must not trigger PI-004"
