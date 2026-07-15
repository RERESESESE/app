"""
평가부: 스캐너 판정을 정답 라벨과 대조해 성능을 수치화한다.
(사용자 요청: '공격을 잘 막았는지 판단하는 적절한 방식')

판정 방식 - 혼동행렬(Confusion Matrix) 기반:
                      실제 공격(attack)      실제 정상(benign)
    스캐너: 공격       TP (제대로 잡음)        FP (오탐)
    스캐너: 정상       FN (미탐, 놓친 공격)    TN (제대로 통과)

  지표:
    - Recall(재현율)   = TP/(TP+FN)  실제 공격 중 잡은 비율  ← 보안 최우선
    - Precision(정밀도) = TP/(TP+FP)  공격 판정 중 진짜 비율  ← 오탐 억제
    - F1              = 2PR/(P+R)    종합 성능
    - FPR(오탐률)      = FP/(FP+TN)
    - Accuracy        = (TP+TN)/전체

  보안 도구는 FN(놓친 공격)이 치명적이라 Recall을 최우선으로 본다. 다만
  Recall만 높이면 전부 공격이라 해도 되므로 Precision/FPR로 균형을 확인한다.

부가 분석:
  - 공격 유형별 / 난이도별 재현율 (약점 진단)
  - 임계값 스윕 (--sweep): 원점수를 1회만 계산해 캐싱 후 임계값만 바꿔 최적 F1 탐색
  - 오분류 사례 (미탐/오탐) 목록 → 개선 대상

실행:
  python evaluate.py data/dataset.json
  python evaluate.py data/dataset.json --sweep
  python evaluate.py data/dataset.json --no-llm     # 규칙만(베이스라인 비교)
"""

import argparse
import json
import os
from collections import defaultdict

from scanner import scan


def confusion(results):
    tp = fp = fn = tn = 0
    for r in results:
        a, p = r["label"] == "attack", r["verdict"] == "attack"
        if a and p: tp += 1
        elif not a and p: fp += 1
        elif a and not p: fn += 1
        else: tn += 1
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn}


def metrics(cm):
    tp, fp, fn, tn = cm["TP"], cm["FP"], cm["FN"], cm["TN"]
    total = tp + fp + fn + tn
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    acc = (tp + tn) / total if total else 0.0
    return {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "fpr": fpr}


def score_all(dataset, use_llm=True):
    """각 샘플의 원점수(risk_score)를 1회 계산. 임계값 스윕 시 재사용."""
    scored = []
    for i, s in enumerate(dataset, 1):
        # 임계값을 매우 높게 줘서 verdict과 무관하게 원점수만 얻음
        r = scan(s["text"], threshold=101, use_llm=use_llm)
        scored.append({**s, "risk_score": r["risk_score"],
                       "pred_type": r["attack_type"], "evidence": r["evidence"]})
        if i % 20 == 0:
            print(f"  ...{i}/{len(dataset)} 판정 완료")
    return scored


def apply_threshold(scored, threshold):
    out = []
    for r in scored:
        out.append({**r, "verdict": "attack" if r["risk_score"] >= threshold else "benign"})
    return out


def per_group_recall(results, key):
    grp = defaultdict(lambda: [0, 0])
    for r in results:
        if r["label"] != "attack":
            continue
        grp[r[key]][1] += 1
        if r["verdict"] == "attack":
            grp[r[key]][0] += 1
    return {k: round(v[0] / v[1], 3) if v[1] else 0.0 for k, v in grp.items()}


def print_report(results):
    cm = confusion(results); m = metrics(cm)
    print("\n" + "=" * 56)
    print(" 혼동행렬 (Confusion Matrix)")
    print("=" * 56)
    print("                  실제:공격   실제:정상")
    print(f"  판정:공격        TP={cm['TP']:<6}   FP={cm['FP']:<6}")
    print(f"  판정:정상        FN={cm['FN']:<6}   TN={cm['TN']:<6}")
    print("-" * 56)
    print(f"  정확도 Accuracy : {m['accuracy']:.3f}")
    print(f"  정밀도 Precision: {m['precision']:.3f}")
    print(f"  재현율 Recall   : {m['recall']:.3f}   ← 보안 최우선")
    print(f"  F1 점수         : {m['f1']:.3f}")
    print(f"  오탐률 FPR      : {m['fpr']:.3f}")
    print("=" * 56)
    print("\n[공격 유형별 재현율]")
    for k, v in sorted(per_group_recall(results, "type").items()):
        bar = "█" * int(v * 20)
        print(f"  {k:22} {v:.3f} {bar}")
    print("\n[난이도별 재현율]")
    for k, v in sorted(per_group_recall(results, "difficulty").items()):
        print(f"  {k:10} {v:.3f}")

    fns = [r for r in results if r["label"] == "attack" and r["verdict"] == "benign"]
    fps = [r for r in results if r["label"] == "benign" and r["verdict"] == "attack"]
    if fns:
        print(f"\n[미탐 FN {len(fns)}건 — 놓친 공격, 최우선 개선 대상]")
        for r in fns[:5]:
            print(f"  ({r['type']}/{r['difficulty']}) {r['text'][:64].strip()}...")
    if fps:
        print(f"\n[오탐 FP {len(fps)}건 — 정상을 공격으로 오인]")
        for r in fps[:5]:
            print(f"  {r['text'][:64].strip()}...")
    return {"cm": cm, "metrics": m}


def sweep(scored):
    print("\n[임계값 스윕] (원점수 1회 계산 후 임계값만 변경)")
    print(f"  {'thr':>4} {'precision':>10} {'recall':>8} {'f1':>7} {'fpr':>7}")
    best = (0, -1.0)
    for thr in [20, 30, 40, 50, 60, 70, 80]:
        m = metrics(confusion(apply_threshold(scored, thr)))
        print(f"  {thr:>4} {m['precision']:>10.3f} {m['recall']:>8.3f} {m['f1']:>7.3f} {m['fpr']:>7.3f}")
        if m["f1"] > best[1]:
            best = (thr, m["f1"])
    print(f"\n  → F1 최대 임계값: {best[0]} (F1={best[1]:.3f})")
    return best[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("--threshold", type=int, default=50)
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--sweep", action="store_true")
    args = ap.parse_args()

    with open(args.dataset, encoding="utf-8") as f:
        dataset = json.load(f)
    use_llm = not args.no_llm
    print(f"평가 시작: {len(dataset)}건, 모드={'규칙+LLM' if use_llm else '규칙만'}")

    scored = score_all(dataset, use_llm=use_llm)

    if args.sweep:
        best_thr = sweep(scored)
        print(f"\n최적 임계값 {best_thr}로 상세 리포트:")
        results = apply_threshold(scored, best_thr)
    else:
        results = apply_threshold(scored, args.threshold)

    summary = print_report(results)

    os.makedirs("reports", exist_ok=True)
    with open(os.path.join("reports", "eval_output.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    # 오분류 사례도 저장 (개선 작업용)
    with open(os.path.join("reports", "misclassified.json"), "w", encoding="utf-8") as f:
        mis = [r for r in results if (r["label"] == "attack") != (r["verdict"] == "attack")]
        json.dump(mis, f, ensure_ascii=False, indent=2)
    print("\n→ reports/eval_output.json, reports/misclassified.json 저장 완료")


if __name__ == "__main__":
    main()
