<#
    This script creates sample data in Active Directory based on the German-SampleData.csv file
#>

Import-Module ActiveDirectory

# Get script path to load other files
$global:scriptFolder = Split-Path $MyInvocation.MyCommand.Path

#region functions

function Replace-Umlaut
{
   [CmdletBinding()]
    Param(
		    [Parameter(Mandatory=$true)][string] $InputString = $(throw "InputString not set")
    )

    $result = $InputString.Replace("Ü", "Ue").Replace("ü","ue").Replace("Ä","Ae").Replace("ä","ae").Replace("Ö", "Oe").Replace("ö","oe").Replace("ß", "ss").Replace("é", "e")

    $result
}
#endregion

# Read sample data
$sampleData = Import-Csv (Join-Path $global:scriptFolder "German-SampleData.csv") -Delimiter `t -Encoding UTF8

foreach ($userData in $sampleData)
{
    # Replace some special chars like umlauts
    $userData.UPN = Replace-Umlaut -InputString $userData.UPN
    $userData.GivenName = Replace-Umlaut -InputString $userData.GivenName
    $userData.Surname = Replace-Umlaut -InputString $userData.Surname
    $userData.DisplayName = Replace-Umlaut -InputString $userData.DisplayName
    $userData.UPN = "{0}.{1}@pre-system.de" -f $userData.GivenName, $userData.Surname

    # Check if user already exists
    $samAccountName = ("{0}{1}"-f $userData.GivenName.Substring(0,1), $userData.Surname)
    $displayName = ("{0}, {1}"-f $userData.Surname, $userData.GivenName)

    try
    {
        $user = Get-ADUser -Identity $samAccountName

        Write-Host ("User with UPN '{0}' already exists" -f $userData.UPN)
    }
    catch
    {
        if ($_.CategoryInfo.Category -eq "ObjectNotFound")
        {
            New-ADUser -City $userData.City -Department $userData.Department -DisplayName $displayName -GivenName $userData.GivenName -Surname $userData.Surname -Name $displayName `
            -UserPrincipalName $userData.UPN -SamAccountName $samAccountName `
            -AccountPassword (ConvertTo-SecureString -AsPlainText $userData.Password -Force) -Path "OU=Test Accounts,DC=shep-net,DC=de" `
            -Enabled $true

            if ($?){Write-Host ("User with UPN '{0}' successfully created" -f $userData.UPN)}
        }
        else
        {
            $_.Exception.Message
        }
    }
}
