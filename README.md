# CST8919 LAB2 : BUILDING A WEB APP WITH THREAT DETECTION USING AZURE MONITOR AND KGL.

----

### OBJECTIVE

---

In this lab we have done:
- Creating a simple demo python application.
- Deployed that application to azure app service.
- Enabled diagnostics using azure monitor.
- Used kusto query language to analyze logs.
- created an alert rule to detect suspicious activity and sent it to email.

---
#### Part 1: Create and deploy flask application to azure.

#### Part 2: Enable monitoring using azure monitor.

#### Part 3: Using KQL query to find all the failed attempts.

#### ❗Challenges faced while doing this Labwork.
according to the requirements i have used this command to find all the failed attempts for logging into the system.


```kql
AppLogs
| where Message contains "FAILED login"
| extend IP = extract(@"from ([\d\.]+)", 1, Message)
| summarize FailedAttempts = count() by IP, bin(TimeGenerated, 10m)
| where FailedAttempts >= 5
```
But unfortunately i got some error and then i changed my query to this

```kql

SigninLogs
| where ResultType != 0  // Non-successful login attempts
| summarize FailedAttempts = count() by IPAddress, bin(TimeGenerated, 10m)
| where FailedAttempts >= 5
| order by TimeGenerated desc

```

and I still got the same error 

```
'where' operator: Failed to resolve table or column expression named 'SigninLogs'
Request id: 2ba28ba4-349b-4428-9f13-a29a44e67c6e

```

![Screenshot 2025-06-18 at 7 49 43 PM](https://github.com/user-attachments/assets/98c95670-a9c7-4d18-997a-9ce06d58dbf6)


#### Part 4: Create an alert rule:

According to the requirements i have tried doing all the tasks.
