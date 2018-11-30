param(
    [parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $resourceGroupName,

    [parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $appServiceName,

    [parameter(Mandatory = $false)]
    [ValidateScript({$_ -match [IPAddress]$_ })]
    [string]
    $ipAddress,

    [parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]
    $ruleName = "buildAgent-access",

    [parameter(Mandatory = $false)]
    [ValidateRange(1,1000000)]
    [int]
    $rulePriority = 1,

    [parameter(Mandatory = $false)]
    [ValidateSet("grantAccess","removeAccess")]
    [String]
    $Action = "removeAccess"
)

function Add-WebAppIPRestrictionRule {
    Param(
        [parameter(Mandatory = $true)]
        $resourceGroupName,

        [parameter(Mandatory = $true)]
        $appServiceName,

        [parameter(Mandatory = $false)]
        $ipAddress,

        [parameter(Mandatory = $false)]
        $ruleName,
        
        [parameter(Mandatory = $false)]
        $rulePriority = 1
    )
              
    If (!(Get-AzureRmContext)) {
        Write-Host "Please login to your Azure account"
        Login-AzureRmAccount
    }

    $APIVersion = ((Get-AzureRmResourceProvider -ProviderNamespace Microsoft.Web).ResourceTypes | Where-Object ResourceTypeName -eq sites).ApiVersions[0]
    Try {
        $webAppConfig = (Get-AzureRmResource -ResourceType Microsoft.Web/sites/config -ResourceName $appServiceName -ResourceGroupName $resourceGroupName -ApiVersion $APIVersion)
    }
    Catch {
        $_.Exception;
        Exit 1
    }
    $IpSecurityRestrictions = $webAppConfig.Properties.ipsecurityrestrictions
    
    # Get Build agent public Ip address
    If ([string]::IsNullOrEmpty($ipAddress)) {
        try {
            $buildAgentPublicIpInfo = Invoke-RestMethod "http://ipinfo.io/json"
        }
        catch {
            Write-Error "Unable to get public address of the local machine";
            Exit 1
        }
        $ipAddress = $buildAgentPublicIpInfo.ip 
    }

    $buildAgentAccessRule = [PSCustomObject] @{
        ipAddress = "$($ipAddress)/32".ToString()
        priority  = $rulePriority
        name      = $ruleName
        action    = "Allow"
    }

    if($null -eq $IpSecurityRestrictions){
        $IpSecurityRestrictions = @()
    }

    [System.Collections.ArrayList]$ArrayList = $IpSecurityRestrictions
    $ArrayList.Add($buildAgentAccessRule) | Out-Null

    $webAppConfig.properties.ipSecurityRestrictions = $ArrayList
    Try {
        Set-AzureRmResource -ResourceId $webAppConfig.ResourceId -Properties $webAppConfig.properties  -ApiVersion $APIVersion -Force | Out-Null
        Write-Host "Access rule $($buildAgentAccessRule.name)[$($buildAgentAccessRule.ipAddress): Priority=$($buildAgentAccessRule.priority)] has been added to webApp $appServiceName"
    }
    Catch {
        $_.Exception;
        Exit 1
    }
}

function Remove-WebAppIPRestrictionRule {
    Param(
        [parameter(Mandatory = $true)]
        $resourceGroupName,

        [parameter(Mandatory = $true)]
        $appServiceName,

        [parameter(Mandatory = $false)]
        $ruleName
    )
              
    If (!(Get-AzureRmContext)) {
        Write-Host "Please login to your Azure account"
        Login-AzureRmAccount
    }
 
    $APIVersion = ((Get-AzureRmResourceProvider -ProviderNamespace Microsoft.Web).ResourceTypes | Where-Object ResourceTypeName -eq sites).ApiVersions[0]
    Try {
        $webAppConfig = (Get-AzureRmResource -ResourceType Microsoft.Web/sites/config -ResourceName $appServiceName -ResourceGroupName $resourceGroupName -ApiVersion $APIVersion)
    }
    Catch {
        $_.Exception;
        Exit 1
    }
    $IpSecurityRestrictions = $webAppConfig.Properties.ipsecurityrestrictions

    if($null -eq $IpSecurityRestrictions){
        Write-Host "There are no any firewall rules for webApp $appServiceName";
        Break;
    }

    [System.Collections.ArrayList]$ArrayList = $IpSecurityRestrictions
    $rulesToDelete = $ArrayList | Where-Object {$_.name -like $ruleName}
    
    if ($rulesToDelete)
    {
        foreach ($ruleToDelete in $rulesToDelete) {
            $ArrayList.Remove($ruleToDelete) | Out-Null
            Write-Host "Remove access rule $($ruleToDelete.name)[$($ruleToDelete.ipAddress)] for webApp $appServiceName"
        }

        $WebAppConfig.properties.ipSecurityRestrictions = $ArrayList

        Try {
            Set-AzureRmResource -ResourceId $WebAppConfig.ResourceId -Properties $WebAppConfig.properties  -ApiVersion $APIVersion -Force | Out-Null
            Write-Host "Access rules have been removed for WebApp $appServiceName"
        }
        Catch {
            $_.Exception;
            Exit 1
        }
    }
    else {
        Write-Warning "There is no access rule $ruleName for webApp $appServiceName"
    }
}


switch ($Action)
{
    "grantAccess" {
        Write-Host "Add access rule";
        Add-WebAppIPRestrictionRule -resourceGroupName $resourceGroupName -appServiceName $appServiceName -ruleName $ruleName
    }
    "removeAccess" {
        Write-Host "Remove access rule";
        Remove-WebAppIPRestrictionRule -resourceGroupName $resourceGroupName -appServiceName $appServiceName -ruleName $ruleName
    }
}