## eval-clean

| Model | n | Precision | Recall | F1 | Precision @ 90% recall | ROC-AUC | ECE |
|---|---|---|---|---|---|---|---|
| qlora | 152 | 0.684 | 0.919 | 0.784 | 0.760 | 0.850 | 0.156 |

## juliet-frozen

| Model | n | Precision | Recall | F1 | Precision @ 90% recall | ROC-AUC | ECE |
|---|---|---|---|---|---|---|---|
| qlora | 1000 | 1.000 | 0.976 | 0.988 | 1.000 | 0.998 | 0.072 |

## juliet-frozen-v1

| Model | n | Precision | Recall | F1 | Precision @ 90% recall | ROC-AUC | ECE |
|---|---|---|---|---|---|---|---|
| qlora | 1000 | 1.000 | 0.980 | 0.990 | 1.000 | 0.998 | 0.075 |

## test

| Model | n | Precision | Recall | F1 | Precision @ 90% recall | ROC-AUC | ECE |
|---|---|---|---|---|---|---|---|
| semgrep alone | 2249 | 0.510 | 1.000 | 0.676 | 0.510 | 0.500 | 0.000 |
| qlora | 2249 | 0.652 | 1.000 | 0.789 | 0.675 | 0.825 | 0.085 |

## sample200

| Model | n | Precision | Recall | F1 | Precision @ 90% recall | ROC-AUC | ECE |
|---|---|---|---|---|---|---|---|
| base3shot | 200 | 0.500 | 1.000 | 0.667 | 0.608 | 0.700 | 0.331 |
