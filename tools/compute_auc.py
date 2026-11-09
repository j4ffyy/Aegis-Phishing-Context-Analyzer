import pandas as pd
from sklearn.metrics import roc_auc_score

p_llm = "evidence/E-43_llm-authored-eval/E-43_llm_predictions.csv"
p_ph = "evidence/E-42_philippine-taglish/E-42_philippine_evaluation.csv"

d_llm = pd.read_csv(p_llm)
print("=== LLM Set (E-43, N=60) ===")
print("roc_auc_score(label, score):", roc_auc_score(d_llm["label"], d_llm["score"]))
print("roc_auc_score(label, s_nlp):", roc_auc_score(d_llm["label"], d_llm["s_nlp"]))
print("roc_auc_score(label, s_heuristic):", roc_auc_score(d_llm["label"], d_llm["s_heuristic"]))

d_ph = pd.read_csv(p_ph)
print("\n=== Philippine Set (E-42, N=60) ===")
print("roc_auc_score(label, full_score):", roc_auc_score(d_ph["label"], d_ph["full_score"]))
print("roc_auc_score(label, heur_score):", roc_auc_score(d_ph["label"], d_ph["heur_score"]))
print("roc_auc_score(label, s_nlp):", roc_auc_score(d_ph["label"], d_ph["s_nlp"]))

