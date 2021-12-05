<#
    This script creates sample user accounts in Azure Active Directory based on the German-SampleData.csv file. The CSV file was generated with
    the fake address generator from the site http://www.fakenamegenerator.com/ 

    You need to create an application principal in Azure first that has the permissions to create uses in Azure Active Directory.
    Add the application id and the application secret in the properties in the settings objects fro Azure germany and Azure international.

    Also enter the name of your Azure tenant.

    You need the AZureRM PowerShell module.
#>

#Import-Module AzureRM

# Get script path to load other files
$global:scriptFolder = Split-Path $MyInvocation.MyCommand.Path

#region variables

#endregion variables

#region functions

function Get-ConfigurationSet($configurationName)
{
    $configurationSet = $null

    switch($configurationName)
    {
        AzureInternational{
            $configurationSet = @{
                "TokenURL" = "https://login.microsoftonline.com/{0}/oauth2/v2.0/token" # The v2 token endpoint
                "Scope" = "https://graph.microsoft.com/.default" # This is the ressource we want an access token for
                "FormData" = "client_id={0}&scope={1}&client_secret={2}&grant_type=client_credentials" # This is sent to the token endpoint to get an accces token for the scope (the ressource we want to access)
                "AppID" = "" # The ID of the application (aka username)
                "AppSecret" = "" # The secret of the app (aka password)
                "TenantName" = "fabricam"
                "UPN" = ("{0}.onmicrosoft.com" -f ($settingsAzureGermany.TenantName))
                "GraphURL" = "https://graph.microsoft.com"
            }
        }
        AzureGermany{
            $configurationSet = @{
                "TokenURL" = "https://login.microsoftonline.de/{0}/oauth2/v2.0/token" # The v2 token endpoint
                "Scope" = "https://graph.microsoft.de" # This is the ressource we want an access token for. The German Cloud only supports 
                "FormData" = "client_id={0}&resource={1}&client_secret={2}&grant_type=client_credentials" # This is sent to the token endpoint to get an accces token for the scope (the ressource we want to access)
                "AppID" = "" # The ID of the application (aka username)
                "AppSecret" = "" # The secret of the app (aka password)
                "TenantName" = "contoso"
                "UPN" = ("{0}.onmicrosoft.de" -f $settingsAzureGermany.TenantName)
                "GraphURL" = "https://graph.microsoft.de"
            }
        }
    }

    $configurationSet
}

function New-AzureUserSchema($parameters)
{
    $userSchema = '{
        "accountEnabled": true,
        "city": "[City]",
        "country": "[Country]",
        "displayName": "[DisplayName]",
        "givenName": "[GivenName]",
        "mailNickname": "[MailNickName]",
        "passwordPolicies": "DisablePasswordExpiration",
        "passwordProfile": {
            "password": "[Password]",
            "forceChangePasswordNextSignIn": false
        },
        "postalCode": "[PostalCode]",
        "preferredLanguage": "de-DE",
        "state": "[StateFull]",
        "streetAddress": "[StreetAddress]",
        "surname": "[Surname]",
        "usageLocation": "DE",
        "userPrincipalName": "[UPN]"
    }'

    $userSchema = $userSchema.Replace("[City]", $parameters.City)
    $userSchema = $userSchema.Replace("[Country]", $parameters.Country)
    $userSchema = $userSchema.Replace("[DisplayName]", $parameters.DisplayName)
    $userSchema = $userSchema.Replace("[GivenName]", $parameters.GivenName)
    $userSchema = $userSchema.Replace("[MailNickName]", ("{0}{1}"-f $parameters.GivenName.Substring(0,1), $parameters.Surname))
    $userSchema = $userSchema.Replace("[Password]", $parameters.Password)
    $userSchema = $userSchema.Replace("[PostalCode]", $parameters.ZipCode)
    $userSchema = $userSchema.Replace("[StateFull]", $parameters.StateFull)
    $userSchema = $userSchema.Replace("[StreetAddress]", $parameters.StreetAddress)
    $userSchema = $userSchema.Replace("[Surname]", $parameters.Surname)
    $userSchema = $userSchema.Replace("[UPN]", $parameters.UPN)

    $userSchema
}

function Get-AccessTokenForApp
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)][string] $TenantName = $(throw "TenantName parameter not set"),
		[Parameter(Mandatory=$true)][string] $AppID = $(throw "AppID parameter not set"),
		[Parameter(Mandatory=$true)][string] $AppSecret = $(throw "AppSecret parameter not set"),
        [Parameter(Mandatory=$true)][string] $EndPointURL = $(throw "EndPointURL parameter not set"),
        [Parameter(Mandatory=$true)][string] $FormData = $(throw "BodyData parameter not set"),
        [Parameter(Mandatory=$true)][string] $Scope = $(throw "Scope parameter not set")
    )

    [Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null

    # URL to get an access token
    $tokenEndpoint = $EndPointURL -f $TenantName

    $body = $FormData -f ([System.Web.HttpUtility]::UrlEncode($AppID)), $Scope, ([System.Web.HttpUtility]::UrlEncode($AppSecret))

    # Get access token and use the authentication information of our app to access the token url
    $accessToken = Invoke-RestMethod -Method "POST" -Uri $tokenEndpoint -Body $body

    $accessToken.access_token
}

function Get-UserInformation
{
   [CmdletBinding()]
    Param(
		[Parameter(Mandatory=$true)][string] $AccessToken = $(throw "AccessToken parameter not set"),
        [Parameter(Mandatory=$true)][string] $GraphURL = $(throw "GraphURL parameter not set"),
        [string] $UserPrincipalName
    )

    $result = @()

    # Base URL to get user information
    $userEndpoint = "{0}/beta/users" -f $GraphURL

    # If we have an email address search only for a user with this email address
    if ($UserPrincipalName)
    {
        $userEndpoint = "{0}/{1}" -f $userEndpoint, $UserPrincipalName
    }

    $headers = @{}
    $headers.Add("Content-type", "application/json")
    $headers.Add("Authorization", ("Bearer {0}" -f $AccessToken))

    try
    {
        $userData = Invoke-RestMethod -Method "GET" -Uri $userEndpoint -Headers $headers

        $result = $userData.value

        # Check if we have more results and get them from server
        while ($userData.'@odata.nextLink')
        {
            $userData = Invoke-RestMethod -Method "GET" -Uri $userData.'@odata.nextLink' -Headers $headers
            $result = $result + $userData.value
        }
    }
    catch
    {
        if($_.Exception.Message -like "The remote server returned an error: (404) Not Found.")
        {
            Write-Host ("User '{0}' does not exists in tenant." -f $UserPrincipalName)
        }

        $result = $null
    }

    $result
}

function Create-AzureUser
{
   [CmdletBinding()]
    Param(
		    [Parameter(Mandatory=$true)][string] $AccessToken = $(throw "AccessToken parameter not set"),
            [Parameter(Mandatory=$true)][string] $UserSchema = $(throw "UserSchema parameter not set"),
            [Parameter(Mandatory=$true)][string] $GraphURL = $(throw "GraphURL parameter not set")
    )

    $userData = $null

    # URL to get user information
    $userEndpoint = "{0}/beta/users" -f $GraphURL

    $headers = @{}
    $headers.Add("Content-type", "application/json")
    $headers.Add("Authorization", ("Bearer {0}" -f $AccessToken))

    # Send body with UTF-8 encoding. Otherwise it will not correctly transmit special chars like umlauts
    $userData = Invoke-RestMethod -Method "POST" -Uri $userEndpoint -Headers $headers -Body ([System.Text.Encoding]::UTF8.GetBytes($UserSchema))

    $userData
}

function Delete-AzureUser
{
   [CmdletBinding()]
    Param(
		[Parameter(Mandatory=$true)][string] $AccessToken = $(throw "AccessToken parameter not set"),
        [Parameter(Mandatory=$true)][string] $UserPrincipalName = $(throw "UserPrincipalName parameter not set"),
        [Parameter(Mandatory=$true)][string] $GraphURL = $(throw "GraphURL parameter not set")
    )

    # Base URL to get user information
    $userEndpoint = "{0}/beta/users" -f $GraphURL
    $userEndpoint = "{0}/{1}" -f $userEndpoint, $UserPrincipalName

    $headers = @{}
    $headers.Add("Content-type", "application/json")
    $headers.Add("Authorization", ("Bearer {0}" -f $AccessToken))

    try
    {
        Invoke-RestMethod -Method "DELETE" -Uri $userEndpoint -Headers $headers

        Write-Host ("User '{0}' successfully deleted." -f $UserPrincipalName)
    }
    catch
    {
        if($_.Exception.Message -like "The remote server returned an error: (404) Not Found.")
        {
            Write-Host ("User '{0}' does not exists in tenant." -f $UserPrincipalName)
        }
        elseif($_.Exception.Message -like "The remote server returned an error: (403) Forbidden.")
        {
             Write-Host ("No permission to delete '{0}'." -f $UserPrincipalName)
        }

        $userData = $null
    }
}


function Replace-Umlaut
{
   [CmdletBinding()]
    Param(
		    [Parameter(Mandatory=$true)][string] $InputString = $(throw "InputString not set")
    )

    $result = $InputString.Replace("�", "Ue").Replace("�","ue").Replace("�","Ae").Replace("�","ae").Replace("�", "Oe").Replace("�","oe").Replace("�", "ss").Replace("�", "e")

    $result
}

#endregion

# Get the configuraiton settings for Azure international or Azure Germany
$settings = Get-ConfigurationSet "AzureInternational"

# Delete users flag
$deleteAllUsers = $false

# Read sample data
$sampleData = Import-Csv (Join-Path $global:scriptFolder "German-SampleData.csv") -Delimiter `t -Encoding UTF8

# Get access token and use the authentication information (application id and application secret) of our app to access the token url
$accessToken = Get-AccessTokenForApp -TenantName $settings.'TenantName' -AppID $settings.'AppID' -AppSecret $settings.'AppSecret' -EndPointURL $settings.'TokenURL' -FormData $settings.'FormData' -Scope $settings.'Scope'

if ($null -eq $accessToken)
{
    Exit
}

if ($deleteAllUsers)
{
    # Get information about users and delete them afterwards
    $userInformation = Get-UserInformation -AccessToken $accessToken -GraphURL $settings.'GraphURL'

    foreach ($user in $userInformation)
    {
        Delete-AzureUser -UserPrincipalName $user.userPrincipalName -AccessToken $accessToken -GraphURL $settings.'GraphURL'
    }
}

Get-UserInformation -AccessToken $accessToken -GraphURL $settings.'GraphURL'

foreach ($userData in $sampleData)
{
    # Replace some special chars like umlauts
    $userData.UPN = Replace-Umlaut -InputString $userData.UPN
    $userData.GivenName = Replace-Umlaut -InputString $userData.GivenName
    $userData.Surname = Replace-Umlaut -InputString $userData.Surname
    $userData.DisplayName = Replace-Umlaut -InputString $userData.DisplayName
    $userData.UPN = "{0}.{1}@si365mst1.onmicrosoft.de" -f $userData.GivenName, $userData.Surname

    $userSchema = New-AzureUserSchema $userData

    # First check if the user already exists
    $userInformation = Get-UserInformation -AccessToken $accessToken -UserPrincipalName $userData.UPN -GraphURL $settings.'GraphURL'

    if ($userInformation -eq $null)
    {
        # A user with this UPN was not found so we can create one
        Write-Host ("A user with the UPN '{0}' was not found in the tenant. We can create one with this UPN." -f $userData.UPN)

        $userResult = Create-AzureUser -AccessToken $accessToken -UserSchema $userSchema -GraphURL $settings.'GraphURL'

        Write-Host ("User with UPN '{0}' successfully created in the tenant." -f $userData.UPN)
    }
}
