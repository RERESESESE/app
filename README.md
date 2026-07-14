# appimport os

from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_community.vectorstores import FAISS
from langchain_core.tools import tool
from langchain_huggingface import HuggingFaceEmbeddings
from langgraph.checkpoint.memory import MemorySaver
from langgraph.prebuilt import create_react_agent

load_dotenv()

INDEX_DIR = "vectorstore"
EMBEDDING_MODEL = "jhgan/ko-sroberta-multitask"

SYSTEM_PROMPT = """당신은 대한민국헌법 전문 상담 AI입니다.

역할:
- 사용자의 상황을 듣고 관련된 헌법 조문을 찾아 쉽게 설명합니다.
- 국민이 헌법상 어떤 권리(기본권)를 갖는지 알려줍니다.
- 답변 시 반드시 search_constitution 도구로 실제 조문을 검색한 뒤,
  검색된 조문 내용에 근거해서만 답변합니다. 조문을 지어내지 마세요.

답변 규칙:
1. 관련 조문 번호(예: 헌법 제10조)를 명시하고 핵심 내용을 인용합니다.
2. 법률 용어는 일반인이 이해할 수 있게 풀어 설명합니다.
3. 헌법에 없는 내용(개별 법률, 판례 세부사항 등)은 헌법 범위를 벗어난다고
   솔직하게 밝히고, 관련될 수 있는 법 분야만 안내합니다.
4. 답변 마지막에 다음 고지를 반드시 포함합니다:
   "※ 이 답변은 일반적인 헌법 정보 제공이며 법률 자문이 아닙니다.
      구체적인 사안은 변호사, 대한법률구조공단(132) 등 전문가와 상담하세요."
"""


def build_retriever_tool():
    """FAISS 인덱스를 로드해 헌법 검색 도구를 생성."""
    if not os.path.exists(INDEX_DIR):
        raise FileNotFoundError(
            f"'{INDEX_DIR}' 인덱스가 없습니다. "
            "먼저 `python fetch_law.py` 와 `python prepare_data.py` 를 실행하세요."
        )

    embeddings = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL)
    vs = FAISS.load_local(INDEX_DIR, embeddings, allow_dangerous_deserialization=True)
    retriever = vs.as_retriever(search_kwargs={"k": 5})

    @tool
    def search_constitution(query: str) -> str:
        """대한민국헌법에서 질문과 관련된 조문을 검색합니다.
        사용자의 상황, 권리, 법적 질문에 답하기 전에 반드시 먼저 사용하세요.
        query에는 검색할 주제나 상황을 한국어로 입력합니다.
        예: '표현의 자유', '체포될 때의 권리', '재산권 제한'"""
        docs = retriever.invoke(query)
        if not docs:
            return "관련 조문을 찾지 못했습니다."
        results = []
        for d in docs:
            results.append(f"[{d.metadata.get('source', '')}]\n{d.page_content}")
        return "\n\n---\n\n".join(results)

    return search_constitution


def build_agent():
    """LangGraph ReAct 에이전트 생성 (대화 메모리 포함)."""
    llm = ChatAnthropic(
        model="claude-sonnet-4-6",
        max_tokens=2048,
        temperature=0.2,
    )
    tools = [build_retriever_tool()]
    memory = MemorySaver()  # thread_id 별 대화 기록 유지

    agent = create_react_agent(
        llm,
        tools,
        prompt=SYSTEM_PROMPT,
        checkpointer=memory,
    )
    return agent


def ask(agent, question: str, thread_id: str = "default") -> str:
    """에이전트에 질문하고 최종 답변 텍스트를 반환."""
    config = {"configurable": {"thread_id": thread_id}}
    result = agent.invoke(
        {"messages": [{"role": "user", "content": question}]},
        config=config,
    )
    return result["messages"][-1].content
