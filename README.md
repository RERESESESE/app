# 프롬프트 인젝션 탐지 스캐너

AI 에이전트가 외부에서 읽는 텍스트 속 악성 지시(프롬프트 인젝션)를 탐지하는
보안 에이전트. 공격 데이터를 스스로 생성하고, 탐지하고, 성능을 수치로 증명한다.

## 파이프라인
generate_data.py (공격 8유형 생성 + 난독화 + 하드네거티브 정상)
  → scanner.py (0단 정규화 → 1단 규칙 → 2단 LLM → 3단 종합)
  → evaluate.py (혼동행렬 · 정밀도/재현율/F1 · 유형별 재현율 · 임계값 스윕)

## 실행 순서
1. pip install -r requirements.txt
2. .env.example → .env 복사 후 OPENAI_API_KEY 입력
3. python generate_data.py --n-per-type 25   # 평가셋 생성 (LLM 사용)
4. python evaluate.py data/dataset.json --sweep   # 성능 측정 + 최적 임계값
5. streamlit run app.py                       # 데모 UI

## 성능을 위한 핵심 설계
- 정규화(0단): 제로폭문자·base64·hex·leetspeak를 먼저 해제해 난독화 우회 무력화
- 규칙+LLM 이중: 명백한 패턴은 규칙이 확정, 미묘한 의미 공격은 LLM이 포착
- 재현율 우선 결합 + 오탐 완충: 놓친 공격 최소화하되 정상 명령형 오탐 억제
- 하드 네거티브: '명령형=공격' 단순학습 방지용 무해 정상 샘플 포함

## LLM 없이 규칙 베이스라인만 측정
python evaluate.py data/dataset.json --no-llm

# App

간단한 테스트 프로젝트입니다.

## 설치
pip install -r requirements.txt# App

간단한 테스트 프로젝트입니다.
