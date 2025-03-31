# 🚨 Incident Response: Impossible Travel Alert 🚨

<img src="https://github.com/user-attachments/assets/1486c704-9935-4ee1-8ba3-7f976b97f291" width="50%">

## 📝 **Overview**
Organizations enforce strict security measures to prevent unauthorized access, including:

- 🌍 Restricting logins from unusual geographic locations.
- 🔄 Preventing account sharing and credential misuse.
- 🛡️ Blocking the use of non-approved VPNs.

This detection identifies instances where a user logs in from **multiple geographic locations** within a short period, suggesting potential credential compromise.

### **Log Source:**
Sign-in activity is recorded in **Azure AD SigninLogs**, which is ingested into **Microsoft Sentinel** via **Log Analytics Workspace**.

---

## 🚦 **Configuring the Sentinel Alert Rule**
### **Objective:**
Set up a **Scheduled Query Rule** in Sentinel to detect anomalous sign-in patterns.

### **Trigger Conditions:**
- A single user logs in from **two or more distinct locations** within **7 days**.

### **KQL Query:**
```kql
let TimePeriod = 7d;
let MaxAllowedLocations = 1;
SigninLogs
| where TimeGenerated > ago(TimePeriod)
| summarize LocationsCount = dcount(Location) by UserPrincipalName
| where LocationsCount > MaxAllowedLocations
```

### **Rule Settings:**
- **Rule Name:** Impossible Travel Alert
- **Description:** Detects logins from multiple distinct geographic regions.
- ✅ **Enable rule** and schedule query execution **every 4 hours**.
- 📅 Query analyzes the **last 24 hours** of data.
- ❌ **Do not suppress** after an alert is generated.

### **Entity Mapping:**
- **User ID:** `UserId → AadUserId`
- **Display Name:** `UserPrincipalName → Value`

---

## 🔍 **Incident Investigation Workflow**

### **Validating the Alert:**
1. ✅ Assign the incident and change the status to **Active**.
2. 🔄 Use **Investigate** in Sentinel to explore related entities.
3. 📊 Run a query to analyze the user’s recent activity:

```kql
let TimePeriod = 7d;
SigninLogs
| where TimeGenerated > ago(TimePeriod)
| where UserPrincipalName == "user@example.com"
| project TimeGenerated, UserPrincipalName, City, State, Country
| order by TimeGenerated desc
```

![image](https://github.com/user-attachments/assets/5a43249d-8063-4c98-a819-0cf235ed5c81)



### **Observed Findings:**
| Account | Locations in 7 Days | Behavior Assessment |
|---------|--------------------|--------------------|
| User A  | 2 (Nearby Cities)  | Normal Activity   |



---

## 🛠️ **Response & Mitigation Actions**

### **Remediation Steps:**
- **Benign Activity:** Locations were within a 2-hour car ride. Users logged into locations within reasonable proximity and timeframes. No further action required.
- **Suspicious Activity:**
  - 🔍 **Expand analysis** using:
    ```kql
    AzureActivity
    | where tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]) == "AzureADObjectID"
    ```
  - 🚨 **If suspicious behavior is detected**, disable the account and escalate. 
  - 🚨 **Reset credentials** and enforce MFA for affected accounts.
  - 🔒 **Block anomalous IPs** and restrict access via Conditional Access Policies.

---

## 🔄 **Post-Incident Actions**
1. **Security Enhancements:**
   - Implement **geo-fencing** for Azure AD logins.
   - Strengthen **MFA policies** for high-risk sign-ins.
2. **Incident Documentation:**
   - Record findings and add insights to the security knowledge base.

---

## ✅ **Incident Closure**
- **Outcome:** Categorize as **Benign Positive** or **False Positive**. (Based on curent findings)
- **Final Steps:**
  - Update documentation and close the case.
  - Conduct a **post-mortem analysis** for continuous improvement.

📌 **Status:** Closed as **Benign Positive**.

---

**🔍 Lessons Learned:**
- Not all impossible travel alerts are security breaches.
- Proximity-aware analysis can reduce false positives.
- Strengthening location-based security policies enhances protection.

📢 **Stay proactive and keep security tight!** 🛡️

---
## Created By:
- **Author Name**: Winston Hibbert
- **Author Contact**: www.linkedin.com/in/winston-hibbert-262a44271/
- **Date**: March 30, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `March 30, 2025`  | `Winston Hibbert`   
