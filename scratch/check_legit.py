import pandas as pd  # pyrefly: ignore[import-error, missing-import]

df_syn = pd.read_csv('evidences/per_sample_evaluation.csv')
legit_syn = df_syn[df_syn['label'] == 0]
print(f"Legit Synthetic - min: {legit_syn['score'].min()}, max: {legit_syn['score'].max()}, mean: {legit_syn['score'].mean()}")

df_neu = pd.read_csv('evidences/per_sample_evaluation_neutral.csv')
legit_neu = df_neu[df_neu['label'] == 0]
print(f"Legit Neutral - min: {legit_neu['score'].min()}, max: {legit_neu['score'].max()}, mean: {legit_neu['score'].mean()}")
print("Legit score distribution (neutral):", legit_neu['score'].value_counts().to_dict())
