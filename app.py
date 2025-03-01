import streamlit as st
import pandas as pd
import joblib
import psutil
import numpy as np
import time

# Load trained models
rf_model = joblib.load("random_forest_model.pkl")
xgb_model = joblib.load("xgboost_model.pkl")

# Streamlit UI
st.title("🚀 Ransomware Early Detection & Response System")

st.write("🔍 **Real-Time Monitoring Enabled** - The system automatically detects ransomware activity.")

model_choice = st.selectbox("Select Model", ["Random Forest", "XGBoost"])

# List of 70 features (excluding 'Family')
expected_features = [
    "CreateProcessInternalW", "CreateServiceA", "CreateServiceW", "CryptExportKey", "CryptGenKey",
    "DeviceIoControl", "EnumServicesStatusA", "EnumServicesStatusW", "FindWindowA", "GetAdaptersAddresses",
    "GetComputerNameA", "GetComputerNameW", "GetDiskFreeSpaceExW", "GetDiskFreeSpaceW", "GlobalMemoryStatusEx",
    "InternetOpenA", "IsDebuggerPresent", "LdrGetDllHandle", "LookupPrivilegeValueW", "MoveFileWithProgressW",
    "NtAllocateVirtualMemory", "NtCreateFile", "NtCreateKey", "NtGetContextThread", "NtMapViewOfSection",
    "NtProtectVirtualMemory", "NtQuerySystemInformation", "NtResumeThread", "NtSetContextThread", "NtSetValueKey",
    "NtTerminateProcess", "NtUnmapViewOfSection", "NtWriteFile", "Process32NextW", "RegOpenKeyExA", "RegOpenKeyExW",
    "RegSetValueExA", "RegSetValueExW", "SetFileAttributesW", "SetWindowsHookExA", "SetWindowsHookExW",
    "ShellExecuteExW", "WriteConsoleA", "WriteConsoleW", "WriteProcessMemory", "row_sum", "Process", "System Info",
    "Memory", "Registry", "File System", "Services", "Network", "GUI Interactions", "Privileges", "Devices",
    "Cryptography", "Threads", "Process (%)", "System Info (%)", "Memory (%)", "Registry (%)", "File System (%)",
    "Services (%)", "Network (%)", "GUI Interactions (%)", "Privileges (%)", "Devices (%)", "Cryptography (%)",
    "Threads (%)"
]

# Function to extract process data
def get_running_processes():
    process_data = []
    for process in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent', 'memory_percent']):
        process_info = process.info
        process_data.append([
            process_info['cpu_percent'],
            process_info['memory_percent']
        ])
    
    df = pd.DataFrame(process_data, columns=['Process (%)', 'Memory (%)'])

    # Ensure all required features exist, fill missing ones with 0
    for col in expected_features:
        if col not in df.columns:
            df[col] = 0  # Fill missing features

    return df[expected_features]  # Ensure correct order

# Start monitoring
if st.button("Start Monitoring"):
    st.write("🔄 **Monitoring System Activity...**")

    while True:
        # Capture system activity
        live_data = get_running_processes()

        if not live_data.empty:
            X_live = live_data.iloc[0].values.reshape(1, -1)  # Ensure correct shape

            # Check feature shape
            if X_live.shape[1] != len(expected_features):
                st.write(f"⚠️ Feature Mismatch: Expected {len(expected_features)} features, but got {X_live.shape[1]}")
                break

            # Make prediction
            if model_choice == "Random Forest":
                prediction = rf_model.predict(X_live)[0]
            else:
                prediction = xgb_model.predict(X_live)[0]

            st.write(f"⚠️ **Potential Threat Detected:** {prediction}")

        time.sleep(5)  # Check every 5 seconds
