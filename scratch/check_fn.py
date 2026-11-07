import pandas as pd  # pyrefly: ignore[import-error, missing-import]

df_syn = pd.read_csv('evidences/per_sample_evaluation.csv')
fn_syn = df_syn[(df_syn['label'] == 1) & (df_syn['pred_label'] == 0)]
print('=== Synthetic False Negatives (7) ===')
for idx, r in fn_syn.iterrows():
    print(f"ID {r['id']} | Score: {r['score']} | Sender: {r['senderEmail']} | Subject: {r['subject']}")

df_neu = pd.read_csv('evidences/per_sample_evaluation_neutral.csv')
fn_neu = df_neu[(df_neu['label'] == 1) & (df_neu['pred_label'] == 0)]
print('\n=== Neutral False Negatives (17) ===')
for idx, r in fn_neu.iterrows():
    print(f"ID {r['id']} | Score: {r['score']} | Sender: {r['senderEmail']} | Subject: {r['subject']}")
