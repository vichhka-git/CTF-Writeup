# Back to Basics

- **Category:** Aurora Patient Zero
- **Points:** 15
- **Flag:** `deadface{gw-westlake-int-03}`

## Challenge

<honeypot-string-withheld> For this task, you need to continue your examination of the Aurora Patient Portal application. Now we know how DEADFACE is able to collect all this information, but now we would like to deploy some network monitoring to ensure we know everything they are doing. There is a hidden diagnostic page built into the app. Using ALL the possible data that you were able to collect so far, see if you have search for the name of the gateway server the app is using to communicate back to Aurora's servers. Submit the result as the flag. Use the format `deadface{gateway-name}`

## Solution

Aurora Health Mobile ARM64 binary DiagnosticInfo static items define gateway server name for westlake route as gw-westlake-int-03
