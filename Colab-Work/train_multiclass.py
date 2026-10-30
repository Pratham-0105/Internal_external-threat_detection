"""
Multi-Class Model Training Script for Network Intrusion Detection (CICIDS-2017)
Standardizes CICIDS-2017 attack types into 8 classes:
  0: BENIGN
  1: DDoS
  2: PortScan
  3: DoS
  4: Brute Force
  5: Web Attack
  6: Botnet
  7: Infiltration

Uses LightGBM multi-class boosting on 25 normalized network traffic flow features.
Saves:
  - app/models/multiclass_model.pkl
  - app/models/multiclass_metadata.json
"""

import os
import glob
import json
import pickle
import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

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

# Standardized class taxonomy
CLASS_MAP = {
    'BENIGN': 0,
    'DDOS': 1,
    'PORTSCAN': 2,
    'DOS': 3,
    'BRUTE FORCE': 4,
    'WEB ATTACK': 5,
    'BOTNET': 6,
    'INFILTRATION': 7
}

CLASS_NAMES = [
    'BENIGN',
    'DDoS',
    'PortScan',
    'DoS',
    'Brute Force',
    'Web Attack',
    'Botnet',
    'Infiltration'
]

def map_raw_label(raw_label):
    clean = str(raw_label).strip()
    clean_upper = clean.upper()
    
    if clean_upper == 'BENIGN':
        return 'BENIGN'
    elif 'DDOS' in clean_upper:
        return 'DDoS'
    elif 'PORTSCAN' in clean_upper:
        return 'PortScan'
    elif 'DOS' in clean_upper or 'HEARTBLEED' in clean_upper:
        return 'DoS'
    elif 'PATATOR' in clean_upper:
        return 'Brute Force'
    elif 'WEB ATTACK' in clean_upper:
        return 'Web Attack'
    elif 'BOT' in clean_upper:
        return 'Botnet'
    elif 'INFILTRATION' in clean_upper or 'INFILTERATION' in clean_upper:
        return 'Infiltration'
    else:
        return 'BENIGN'

def load_and_preprocess(folder_path, max_per_class=30000):
    csv_files = glob.glob(os.path.join(folder_path, "*.csv"))
    print(f"[*] Found {len(csv_files)} CSV files in {os.path.abspath(folder_path)}")
    
    collected_dfs = []
    
    for file_path in csv_files:
        fname = os.path.basename(file_path)
        try:
            # First read 2 rows to detect columns
            head_df = pd.read_csv(file_path, nrows=2, encoding='latin-1')
            col_map = {c: c.strip() for c in head_df.columns}
            
            target_col = None
            for c in head_df.columns:
                if col_map[c].lower() in ['label', 'is_attack', 'target', 'class']:
                    target_col = c
                    break
                    
            if not target_col:
                continue
                
            # Find feature columns
            feat_map = {}
            for c in head_df.columns:
                cleaned = col_map[c]
                if cleaned in EXTENDED_FEATURES:
                    feat_map[cleaned] = c
                    
            missing = [f for f in EXTENDED_FEATURES if f not in feat_map]
            if missing:
                print(f"[-] Skipping {fname}: missing {len(missing)} features ({missing[:3]})")
                continue
                
            usecols = [target_col] + [feat_map[f] for f in EXTENDED_FEATURES]
            
            df = pd.read_csv(file_path, usecols=usecols, encoding='latin-1', low_memory=False)
            df.rename(columns=col_map, inplace=True)
            
            # Map labels
            df['Taxonomy'] = df['Label'].apply(map_raw_label)
            
            # Convert features to numeric float32
            for f in EXTENDED_FEATURES:
                df[f] = pd.to_numeric(df[f], errors='coerce').astype('float32')
                
            # Keep features and Taxonomy
            clean_sub = df[EXTENDED_FEATURES + ['Taxonomy']].copy()
            collected_dfs.append(clean_sub)
            print(f"[+] Loaded {fname}: {len(clean_sub):,} rows (Taxonomy: {clean_sub['Taxonomy'].value_counts().to_dict()})")
        except Exception as e:
            print(f"[!] Error processing {fname}: {e}")
            
    if not collected_dfs:
        raise RuntimeError("No valid data could be loaded!")
        
    full_df = pd.concat(collected_dfs, ignore_index=True)
    print(f"\n[*] Total Consolidated Dataset: {len(full_df):,} rows")
    print("[*] Distribution before balanced sampling:")
    print(full_df['Taxonomy'].value_counts())
    
    # Balanced sampling so dominant classes (BENIGN, DoS, DDoS, PortScan) don't starve smaller classes
    sampled_list = []
    for taxonomy_name, group in full_df.groupby('Taxonomy'):
        if len(group) > max_per_class:
            sampled_group = group.sample(n=max_per_class, random_state=42)
        else:
            sampled_group = group
        sampled_list.append(sampled_group)
        
    balanced_df = pd.concat(sampled_list, ignore_index=True)
    print(f"\n[+] Balanced Sampled Dataset: {len(balanced_df):,} rows")
    print(balanced_df['Taxonomy'].value_counts())
    
    # Map to integer class labels
    balanced_df['ClassId'] = balanced_df['Taxonomy'].map(lambda x: CLASS_MAP.get(x.upper(), 0))
    
    # Replace inf and NaN
    X = balanced_df[EXTENDED_FEATURES].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    # Underscore column names to match model standard (e.g. Fwd_IAT_Std)
    normalized_cols = [c.replace(' ', '_') for c in EXTENDED_FEATURES]
    X.columns = normalized_cols
    
    y = balanced_df['ClassId'].values
    
    return X, y

def train_multiclass():
    dataset_folder = os.path.dirname(os.path.abspath(__file__))
    output_model_path = os.path.abspath(os.path.join(dataset_folder, '..', 'src', 'flask-api', 'app', 'models', 'multiclass_model.pkl'))
    metadata_path = os.path.abspath(os.path.join(dataset_folder, '..', 'src', 'flask-api', 'app', 'models', 'multiclass_metadata.json'))
    
    os.makedirs(os.path.dirname(output_model_path), exist_ok=True)
    
    X, y = load_and_preprocess(dataset_folder, max_per_class=25000)
    
    print("\n[*] Splitting into Train (80%) and Test (20%) with stratification...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"[*] Training Multi-Class LightGBM (8 Classes, {len(X.columns)} Features)...")
    clf = lgb.LGBMClassifier(
        objective='multiclass',
        num_class=8,
        n_estimators=160,
        learning_rate=0.08,
        num_leaves=35,
        max_depth=8,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
        verbose=-1
    )
    
    clf.fit(X_train, y_train)
    
    print("\n[*] Evaluating Multi-Class Model...")
    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    
    report = classification_report(
        y_test, 
        y_pred, 
        labels=list(range(8)),
        target_names=CLASS_NAMES, 
        digits=4,
        output_dict=False
    )
    report_dict = classification_report(
        y_test,
        y_pred,
        labels=list(range(8)),
        target_names=CLASS_NAMES,
        digits=4,
        output_dict=True
    )
    
    print(f"\n{'='*60}")
    print(f"  MULTI-CLASS MODEL TRAINING COMPLETE!")
    print(f"  Overall Accuracy: {acc * 100:.2f}%")
    print(f"{'='*60}\n")
    print(report)
    
    # Save trained model
    with open(output_model_path, 'wb') as f:
        pickle.dump(clf, f)
    print(f"[+] Saved model to: {output_model_path}")
    
    # Save metadata
    metadata = {
        'model_type': 'LightGBM Multi-Class Classifier',
        'classes': CLASS_NAMES,
        'class_map': CLASS_MAP,
        'features': list(X.columns),
        'accuracy': float(acc),
        'classification_report': report_dict
    }
    with open(metadata_path, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2)
    print(f"[+] Saved metadata to: {metadata_path}")

if __name__ == '__main__':
    train_multiclass()
