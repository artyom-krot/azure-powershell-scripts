# azure-powershell-scripts
Different helpful scripts, that can be used for Azure deployment automation



### AzureRM\Firewall\webapp_access_for_build_agent.ps1
Add and remove access rule for any build agent you are running deployment from.
Just run the script before deployment and after if you need to temporary allow access to your web app from build agent.
parameters:
-resourceGroupName
-appServiceName
-ipAddress [ipv4]
-ruleName 
-rulePriority [1, 1000000]
-Action [grantAccess, removeAccess]
