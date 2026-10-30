"""
Explainable AI (XAI) & Multi-Class Threat Categorization Engine.
Analyzes feature vector attributes to provide human-interpretable feature attributions
and precise attack vector classification.
"""

def analyze_xai_and_category(features, probability, is_attack, dpi_res=None, anomaly_res=None, model=None, feature_df=None, predicted_class=None, multiclass_breakdown=None):
    """
    Computes feature contribution explanations and assigns multi-class category labels,
    incorporating real LightGBM TreeSHAP attributions, ML Multi-Class taxonomy, DPI findings, and Zero-Day scores.
    """
    xai_attributions = []

    flow_iat_mean = features.get('Flow IAT Mean', features.get('Flow_IAT_Mean', 0.0))
    flow_duration = features.get('Flow Duration', features.get('Flow_Duration', 0.0))
    total_fwd_pkts = features.get('Total Fwd Packets', features.get('Total_Fwd_Packets', 0.0))
    idle_max = features.get('Idle Max', features.get('Idle_Max', 0.0))
    fwd_iat_std = features.get('Fwd IAT Std', features.get('Fwd_IAT_Std', 0.0))

    # 1. Check DPI findings first for Layer 7 explanations
    if dpi_res and dpi_res.get('dpi_flagged'):
        for finding in dpi_res.get('findings', []):
            xai_attributions.append({
                "feature": f"L7 Payload Signature: {finding['signature']}",
                "value": f"Pattern: {finding['matched_pattern']}",
                "severity": finding.get('severity', 'CRITICAL'),
                "reason": f"DPI Engine matched malicious signature snippet: {finding.get('snippet', '')[:60]}..."
            })

    # 2. Check Zero-Day Anomaly Detection
    if anomaly_res and anomaly_res.get('is_zero_day'):
        xai_attributions.append({
            "feature": "Zero-Day Anomaly Score",
            "value": f"{anomaly_res.get('anomaly_score', 0)}%",
            "severity": "CRITICAL" if anomaly_res.get('anomaly_score', 0) > 75 else "HIGH",
            "reason": "Flow vector statistically deviated outside baseline normal distribution."
        })

    # Taxonomy mapping for ML Multi-Class predictions
    TAXONOMY_MAP = {
        'DDoS': ("DDoS SYN Flood", "DDOS"),
        'PortScan': ("PortScan Probe", "PORTSCAN"),
        'DoS': ("DoS / Slowloris Flood", "DOS"),
        'Brute Force': ("Brute Force (SSH/FTP)", "BRUTE_FORCE"),
        'Web Attack': ("Web Exploit (SQLi/XSS)", "WEB_ATTACK"),
        'Botnet': ("Botnet C2 Traffic", "BOTNET"),
        'Infiltration': ("Infiltration / Privilege Escalation", "INFILTRATION"),
    }

    # 3. Determine Multi-Class Category
    if dpi_res and dpi_res.get('dpi_flagged'):
        category = f"DPI Flagged: {dpi_res['findings'][0]['signature']}"
        category_code = "DPI_ATTACK"
    elif not is_attack:
        category = "Normal Web Session"
        category_code = "NORMAL"
    elif predicted_class and predicted_class in TAXONOMY_MAP:
        category, category_code = TAXONOMY_MAP[predicted_class]
        p_val = multiclass_breakdown.get(predicted_class, 0.0) if multiclass_breakdown else probability
        xai_attributions.append({
            "feature": f"Multi-Class ML Taxonomy ({predicted_class})",
            "value": f"Confidence {p_val * 100:.1f}%",
            "severity": "CRITICAL" if p_val > 0.8 else "HIGH",
            "reason": f"LightGBM multi-class model classified flow fingerprint as {predicted_class} with {p_val * 100:.1f}% certainty."
        })
    elif total_fwd_pkts >= 3 and flow_iat_mean < 10000.0:
        category = "DDoS SYN Flood"
        category_code = "DDOS"
    elif flow_duration < 50000.0 and total_fwd_pkts >= 2:
        category = "PortScan Probe"
        category_code = "PORTSCAN"
    elif idle_max > 500000.0:
        category = "Botnet C2 Traffic"
        category_code = "BOTNET"
    else:
        category = "Web Exploit (SQLi)"
        category_code = "WEB_ATTACK"

    # 4. Compute Genuine TreeSHAP Values if Model & Feature DataFrame are available
    shap_calculated = False
    if model is not None and feature_df is not None and hasattr(model, 'booster_'):
        try:
            contrib = model.booster_.predict(feature_df, pred_contrib=True)
            shap_values = contrib[0][:-1]  # Exclude base bias
            feature_names = list(feature_df.columns)

            # Sort features by absolute contribution impact
            impact_pairs = sorted(zip(feature_names, shap_values), key=lambda x: abs(x[1]), reverse=True)

            for feat_name, shap_val in impact_pairs[:4]:
                if abs(shap_val) > 0.005:
                    shap_calculated = True
                    raw_val = features.get(feat_name, features.get(feat_name.replace('_', ' '), 0.0))
                    impact_dir = "increased attack probability" if shap_val > 0 else "decreased threat probability"
                    severity = "CRITICAL" if abs(shap_val) > 1.5 else "HIGH" if abs(shap_val) > 0.5 else "MEDIUM"
                    clean_name = feat_name.replace('_', ' ')
                    xai_attributions.append({
                        "feature": f"{clean_name} (TreeSHAP)",
                        "value": f"{raw_val:g} (SHAP impact: {shap_val:+.3f})",
                        "severity": severity,
                        "reason": f"Mathematical TreeSHAP attribution of {shap_val:+.3f} {impact_dir}."
                    })
        except Exception as e:
            print(f"TreeSHAP calculation fallback: {e}")

    # 5. Fallback Heuristic Feature Attributions if SHAP was not computed
    if not shap_calculated:
        if is_attack:
            if flow_iat_mean < 15000.0 and flow_iat_mean > 0:
                xai_attributions.append({
                    "feature": "Flow IAT Mean",
                    "value": f"{flow_iat_mean:.2f} µs",
                    "severity": "CRITICAL",
                    "reason": "Extreme rapid packet burst rate indicative of automated flood attack."
                })

            if total_fwd_pkts > 2:
                xai_attributions.append({
                    "feature": "Total Fwd Packets",
                    "value": f"{int(total_fwd_pkts)} pkts",
                    "severity": "HIGH",
                    "reason": "High forward packet count within a single temporal window."
                })

            if idle_max > 500000.0:
                xai_attributions.append({
                    "feature": "Idle Max",
                    "value": f"{idle_max:.2f} µs",
                    "severity": "HIGH",
                    "reason": "Long periodic idle gaps characteristic of botnet C2 beaconing."
                })

            if fwd_iat_std > 1000.0:
                xai_attributions.append({
                    "feature": "Fwd IAT Std",
                    "value": f"{fwd_iat_std:.2f} µs",
                    "severity": "MEDIUM",
                    "reason": "Irregular forward packet inter-arrival variance."
                })

            if not xai_attributions:
                xai_attributions.append({
                    "feature": "Flow Duration",
                    "value": f"{flow_duration:.2f} µs",
                    "severity": "MEDIUM",
                    "reason": "Overall flow temporal signature deviated from baseline model."
                })
        else:
            xai_attributions.append({
                "feature": "Flow IAT Mean",
                "value": f"{flow_iat_mean:.2f} µs",
                "severity": "LOW",
                "reason": "Standard human interaction interval."
            })
            xai_attributions.append({
                "feature": "Total Fwd Packets",
                "value": f"{int(total_fwd_pkts)} pkts",
                "severity": "LOW",
                "reason": "Normal packet count volume."
            })

    return {
        "category": category,
        "category_code": category_code,
        "attributions": xai_attributions
    }
