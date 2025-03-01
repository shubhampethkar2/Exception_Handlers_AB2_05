import streamlit as st
import pandas as pd
import joblib
import psutil
import numpy as np
import time
import plotly.express as px

# Load trained Random Forest model
rf_model = joblib.load("random_forest_model.pkl")

# Streamlit UI
st.set_page_config(page_title="Ransomware Detection", layout="wide")

st.title("🚀 Ransomware Early Detection & Response System")
st.markdown("🔍 **Real-Time Monitoring Enabled** - Automatically detects ransomware threats.")

# Status Indicator
status_placeholder = st.empty()
status_placeholder.info("🟢 **System Idle** - Click 'Start Monitoring' to begin.")

# Placeholder for real-time metrics and results
col1, col2 = st.columns(2)
with col1:
    st.subheader("📊 CPU Usage Over Time")
    cpu_chart_placeholder = st.empty()
    st.subheader("💾 Memory Usage Over Time")
    mem_chart_placeholder = st.empty()
    
with col2:
    st.subheader("⚠️ Detected Threats Log")
    detected_threats_placeholder = st.empty()

# Threat logs
threat_logs = []

# List of 70 expected features (excluding 'Family')
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

# Function to get system metrics
def get_system_metrics():
    cpu_usage = psutil.cpu_percent(interval=1)
    mem_usage = psutil.virtual_memory().percent
    return cpu_usage, mem_usage

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
    
    # Ensure all required features exist
    for col in expected_features:
        if col not in df.columns:
            df[col] = 0  # Fill missing features

    return df[expected_features]  # Ensure correct order

# Start Monitoring
if st.button("🚨 Start Monitoring"):
    status_placeholder.warning("🟡 **Monitoring Active...**")

    cpu_usage_list = []
    mem_usage_list = []
    threats_detected = False
    
    for i in range(30):  # Runs for 30 iterations (adjustable)
        # Capture system activity
        live_data = get_running_processes()

        # Get system metrics
        cpu_usage, mem_usage = get_system_metrics()
        cpu_usage_list.append(cpu_usage)
        mem_usage_list.append(mem_usage)

        # Update CPU & Memory charts
        cpu_chart_placeholder.line_chart(pd.DataFrame(cpu_usage_list, columns=["CPU Usage (%)"]))
        mem_chart_placeholder.line_chart(pd.DataFrame(mem_usage_list, columns=["Memory Usage (%)"]))

        if not live_data.empty:
            X_live = live_data.iloc[0].values.reshape(1, -1)

            # Make prediction using Random Forest
            prediction = rf_model.predict(X_live)[0]

            if prediction == 1:  # Assuming 1 = Ransomware detected
                threats_detected = True
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                threat_logs.append({"Time": timestamp, "Threat Detected": "Yes"})
                detected_threats_placeholder.write(pd.DataFrame(threat_logs))
                st.error(f"⚠️ **Potential Threat Detected at {timestamp}**")

        time.sleep(3)  # Check every 3 seconds
    
    # Final status update
    if threats_detected:
        status_placeholder.error("🔴 **Monitoring Completed - Threats Detected!**")
    else:
        status_placeholder.success("🟢 **Monitoring Completed - No Threats Found!**")
