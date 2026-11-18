# Use from an AI agent

Three checks cover most agent designs. Each is one call to the gateway ([contract](API.md), [client](CLIENT.md)).

| Where | Call | If it fails |
|---|---|---|
| User input, before the model sees it | `guard.check(text)` | Refuse, do not call the model |
| Retrieved documents and tool results, before they enter the prompt | `guard.scan(chunk)` | Drop the chunk (this is where indirect injection hides) |
| Model output, before it reaches the user | `guard.redact_output(text)` | Mask personal data; block if it contains a secret |

Rule for every pattern: **no verdict means no.** `SentinelError` (gateway unreachable) is treated as "do not proceed".

## Raw Python (no framework)

```python
from ai_sentinel.client import SentinelClient, PromptBlocked, SentinelError

guard = SentinelClient("http://localhost:8000", api_key="change-me")
REFUSAL = "Sorry, I can't help with that."

def agent_turn(user_text: str, retrieve, llm) -> str:
    try:
        guard.check(user_text)                                   # 1. input
        chunks = [c for c in retrieve(user_text)
                  if guard.scan(c)["action"] == "ALLOW"]         # 2. retrieved documents
        answer = llm(user_text, chunks)
        return guard.redact_output(answer)                       # 3. output
    except (PromptBlocked, SentinelError):
        return REFUSAL
```

`retrieve(query)` returns a list of strings, `llm(question, chunks)` returns a string. Replace them with your own.

## LangChain (LCEL)

Wrap the guard in `RunnableLambda` steps. Raising stops the chain; catch it where you invoke it.

```python
from langchain_core.runnables import RunnableLambda
from langchain_core.output_parsers import StrOutputParser
from ai_sentinel.client import SentinelClient

guard = SentinelClient("http://localhost:8000", api_key="change-me")

def check_input(text: str) -> str:
    guard.check(text)          # raises PromptBlocked / SentinelError
    return text

chain = (
    RunnableLambda(check_input)
    | prompt                   # your ChatPromptTemplate
    | llm                      # your chat model
    | StrOutputParser()
    | RunnableLambda(guard.redact_output)
)
```

For retrieval, filter the retriever's documents the same way, with a `RunnableLambda` that keeps only documents where `guard.scan(doc.page_content)["action"] == "ALLOW"`.

## LlamaIndex

A node post-processor drops retrieved chunks that are not allowed before they reach the model.

```python
from typing import Any, List, Optional
from llama_index.core.postprocessor.types import BaseNodePostprocessor
from llama_index.core.schema import NodeWithScore, QueryBundle
from ai_sentinel.client import SentinelClient

class SentinelFilter(BaseNodePostprocessor):
    guard: Any = None

    def _postprocess_nodes(self, nodes: List[NodeWithScore], query_bundle: Optional[QueryBundle] = None) -> List[NodeWithScore]:
        return [n for n in nodes if self.guard.scan(n.node.get_content())["action"] == "ALLOW"]

guard = SentinelClient("http://localhost:8000", api_key="change-me")
query_engine = index.as_query_engine(node_postprocessors=[SentinelFilter(guard=guard)])
# check the user's question yourself first: guard.check(question)
```

## Tested or not

The raw-Python client calls are covered by this repository's tests. The LangChain and LlamaIndex snippets are **not run in CI** and were written against the current public APIs of those libraries, which change often. If an import fails, adapt the wrapper: all it does is call `guard.check`, `guard.scan` or `guard.redact_output` at the right point.

## Tool calls

When an agent calls tools, check both directions: the arguments the model produced (`guard.check(argument)`) and what the tool returned (`guard.scan(result)`). Web pages, emails and files are the usual carriers of indirect injection.
