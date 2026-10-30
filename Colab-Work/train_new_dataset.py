"""
Multi-Variable Feature Training Script for NIDS
Supports:
 - Standard 12 Time-Based Variables
 - Extended 25 Multi-Variable Network Features

Usage:
    python train_new_dataset.py --folder . --features extended
"""
import os
import glob
import argparse
import pickle
import numpy as np
import pandas as pd

import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

TIME_FEATURES = [
    'Fwd IAT Std', 'Bwd IAT Std', 'Flow IAT Std',
    'Fwd IAT Max', 'Flow IAT Mean', 'Flow IAT Max',
    'Fwd IAT Mean', 'Fwd IAT Total', 'Flow Duration',
    'Bwd IAT Max', 'Idle Max', 'Idle Mean'
]

EXTENDED_FEATURES = [
    'Fwd IAT Std', 'Bwd IAT Std', 'Flow IAT Std',
    'Fwd IAT Max', 'Flow IAT Mean', 'Flow IAT Max',
    'Fwd IAT Mean', 'Fwd IAT Total', 'Flow Duration',
    'Bwd IAT Max', 'Idle Max', 'Idle Mean',
    'Fwd IAT Min', 'Bwd IAT Min', 'Flow IAT Min',
    'Bwd IAT Total', 'Bwd IAT Mean',
    'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Header Length', 'Bwd Header Length',
    'Active Mean', 'Idle Min'
]

def load_data(folder_path, feature_list):
    csv_files = glob.glob(os.path.join(folder_path, "*.csv"))
    print(f"[+] Found {len(csv_files)} CSV dataset files in: {os.path.abspath(folder_path)}")
    
    if not csv_files:
        raise ValueError(f"No CSV files found in: {folder_path}")

    df_list = []
    total_rows = 0

    for file_path in csv_files:
        fname = os.path.basename(file_path)
        
        header_df = pd.read_csv(file_path, nrows=2)
        raw_cols = list(header_df.columns)
        col_map = {c: c.strip() for c in raw_cols}
        
        target_col = None
        for c in raw_cols:
            if col_map[c] in ['Label', 'label', 'is_attack', 'target', 'Class', 'class']:
                target_col = c
                break
                
        if not target_col:
            continue
            
        feat_map = {}
        for c in raw_cols:
            cleaned = col_map[c]
            if cleaned in feature_list:
                feat_map[cleaned] = c
                
        missing = [f for f in feature_list if f not in feat_map]
        if missing:
            continue

        use_cols = [target_col] + [feat_map[f] for f in feature_list]

        sub_df = pd.read_csv(file_path, usecols=use_cols, low_memory=False)
        sub_df.rename(columns=col_map, inplace=True)

        # Convert label to binary: 0 = BENIGN, 1 = ATTACK
        sub_df['Label'] = sub_df[col_map[target_col]].astype(str).apply(lambda x: 0 if x.strip().upper() == 'BENIGN' else 1)
        if col_map[target_col] != 'Label':
            sub_df.drop(columns=[col_map[target_col]], inplace=True, errors='ignore')

        for feat in feature_list:
            sub_df[feat] = pd.to_numeric(sub_df[feat], errors='coerce').astype('float32')

        df_list.append(sub_df)
        total_rows += len(sub_df)
        print(f" -> Loaded {fname}: {len(sub_df):,} rows.")

    print(f"\n[+] Combining datasets ({total_rows:,} total rows)...")
    combined_df = pd.concat(df_list, ignore_index=True)
    return combined_df

def train_model(folder_path, output_model_path, model_type='lightgbm', feature_mode='extended'):
    feature_list = EXTENDED_FEATURES if feature_mode == 'extended' else TIME_FEATURES
    print(f"\n" + "="*60)
    print(f"  MULTI-VARIABLE TRAINING: {len(feature_list)} VARIABLES ({feature_mode.upper()} MODE)")
    print("="*60)

    df = load_data(folder_path, feature_list)
    print(f"[+] Total Dataset Shape: {df.shape[0]:,} rows, {df.shape[1]} columns")

    X = df[feature_list]
    y = df['Label']

    # Clean nan / infinity
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

    print(f"[+] Splitting {len(X):,} records into Train (80%) and Test (20%) sets...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    clf = lgb.LGBMClassifier(n_estimators=150, learning_rate=0.1, num_leaves=31, random_state=42, n_jobs=-1, verbose=-1)
    
    print(f"[+] Training LightGBM on ALL {len(X_train):,} training records across {len(feature_list)} variables...")
    clf.fit(X_train, y_train)

    print("[+] Evaluating multi-variable model performance...")
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    
    print(f"\n" + "="*50)
    print(f"  MULTI-VARIABLE DATASET TRAINING COMPLETE!")
    print(f"  Total Variables Trained: {len(feature_list)}")
    print(f"  Test Set Accuracy: {acc * 100:.2f}%")
    print("="*50 + "\n")
    
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['BENIGN (0)', 'ATTACK (1)'], digits=4))

    # Save output model
    abs_output_path = os.path.abspath(output_model_path)
    os.makedirs(os.path.dirname(abs_output_path), exist_ok=True)
    with open(abs_output_path, 'wb') as f:
        pickle.dump(clf, f)

    # Backup save
    backup_path = os.path.abspath('../src/flask-api/models/model.pkl')
    if os.path.exists(os.path.dirname(backup_path)):
        with open(backup_path, 'wb') as f:
            pickle.dump(clf, f)

    print(f"[+] Multi-variable model saved successfully to:")
    print(f"   -> {abs_output_path}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Multi-Variable NIDS Model Training")
    parser.add_argument('--folder', type=str, default='.', help="Path to dataset folder")
    parser.add_argument('--model', type=str, default='lightgbm', help="Model architecture")
    parser.add_argument('--features', type=str, default='extended', choices=['time', 'extended'], help="Feature variables mode")
    parser.add_argument('--output', type=str, default='../src/flask-api/app/models/model.pkl', help="Output pickle model path")
    args = parser.parse_args()

    train_model(args.folder, args.output, args.model, args.features)
