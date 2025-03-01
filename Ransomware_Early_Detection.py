#!/usr/bin/env python
# coding: utf-8

# In[39]:


import pandas as pd
import numpy as np
import joblib
import streamlit as st
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier


# In[10]:


df1 = pd.read_csv("C:/Users/pethk/Downloads/Early-stage-Ransomware-Detection-based-on-Pre-Attack-Internal-API-Calls-main/esrd_multiclass_dataset.csv")
    


# In[9]:


df2 = pd.read_csv("C:/Users/pethk/Downloads/Early-stage-Ransomware-Detection-based-on-Pre-Attack-Internal-API-Calls-main/output_processed_2.csv")
    


# In[11]:


print(df1.info())  # Check column types & missing values
print(df2.info())  


# In[12]:


print(df1.head())  # Show first few rows
print(df2.head())


# In[13]:


print(df1.isnull().sum())  # Count missing values
print(df2.isnull().sum())




# In[14]:


print(df1.duplicated().sum())  # Check duplicates
print(df2.duplicated().sum())


# In[16]:


print(df2.columns)



# In[17]:


print(df2["Family"].unique())  # Check unique values in 'Family'



# In[18]:


print(df2["Family"].value_counts())


# In[24]:


X = df.drop(columns=['Family'])
y = df['Family']



# In[31]:


X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)


# In[32]:


# Train Random Forest model
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)


# In[33]:


rf_model.fit(X_train, y_train)


# In[34]:


rf_pred = rf_model.predict(X_test)
rf_accuracy = accuracy_score(y_test, rf_pred)


# In[37]:


le = LabelEncoder()
y_train_encoded = le.fit_transform(y_train)
y_test_encoded = le.transform(y_test)


# In[40]:


# Train XGBoost model
xgb_model = XGBClassifier(use_label_encoder=False, eval_metric="mlogloss")
xgb_model.fit(X_train, y_train_encoded)  # Train using encoded labels
xgb_pred = xgb_model.predict(X_test)
xgb_accuracy = accuracy_score(y_test_encoded, xgb_pred)  # Compare with encoded labels


# In[41]:


st.success(f"XGBoost Accuracy: {xgb_accuracy:.2f}")


# In[42]:


# Model Selection for Prediction
st.write("### Select Model for Ransomware Prediction")
model_choice = st.selectbox("Choose Model:", ["Random Forest", "XGBoost"])


# In[44]:


if st.button("Predict on Sample Data"):
    sample_data = X_test.iloc[0].values.reshape(1, -1)
    if model_choice == "Random Forest":
        prediction = rf_model.predict(sample_data)[0]
    else:
        prediction = xgb_model.predict(sample_data)[0]

    st.write(f"**Predicted Ransomware Family:** {prediction}")



# In[ ]:




