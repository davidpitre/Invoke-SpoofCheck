<#
	.SYNOPSIS
		Spoof Check - Pulic email domain spoof check
	
	.DESCRIPTION
		Run checks against a single domain to determine if it is possible to spoof email
		If the result "Spoofable" is returned true, it is possible in some way to spoof emails sent for that domain. 
	
	.NOTES
	===========================================================================
	 Created on:   		08/04/2020
	 Created by:   		David Pitre
	 Filename:     		Invoke-SpoofCheck.ps1
	 Version:			0.1
	 Classification:	Public

	 TODO
	 1.	Include functions that abuse each of the misconfigurations for SPF and DMARC
	 2. Output results to a report
	===========================================================================

	.EXAMPLE
		PS C:\> Invoke-SpoofCheck -DomainName google.com
	
	.LINK
		https://github.com/davidpitre/Invoke-SpoofCheck

#>
[CmdletBinding(ConfirmImpact = 'None',
			   PositionalBinding = $false)]
[OutputType([object])]
param
(
	[Parameter(Mandatory = $false,
			   HelpMessage = 'Public company domain name including tld e.g. customer.com')]
	[string]$DomainName
)

# ValidateSet input in paremeter block does not effectivley handle error message. 
if ([string]$DomainName -cnotmatch '(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]')
{
	throw "The domain name entered is not valid" # Regex pattern test for input validation. Confirm supplied data matches a domain e.g. customer.com
}
else
{
	Write-Verbose -Message "DomainName input validation: success"
}

$DomainObject = New-Object -TypeName PSCustomObject
$DomainObject | Add-Member -membertype NoteProperty -Name "DomainName" -Value $DomainName
$DomainObject | Add-Member -membertype NoteProperty -Name "SPFRecord" -Value $null
$DomainObject | Add-Member -membertype NoteProperty -Name "SPFFailureType" -Value $null
$DomainObject | Add-Member -membertype NoteProperty -Name "DMARCRecord" -Value $null
$DomainObject | Add-Member -membertype NoteProperty -Name "DMARCPolicy" -Value $null
$DomainObject | Add-Member -membertype NoteProperty -Name "Spoofable" -Value $false

function Get-SpfRecord
{
	param
	(
		[string]$DomainName
	)
	
	BEGIN
	{
		Write-Verbose -Message "Get-SpfRecord: Begin"
	}
	PROCESS
	{
		try
		{
			[array]$Results = Resolve-DnsName -Name $DomainName -Type TXT -ErrorAction SilentlyContinue
			if (-not ([array]$Results))
			{
				Write-Verbose -Message "Domain does not host a SPF Record"
				[object]$DomainObject.SPFRecord = [bool]$false
			}
			else
			{
				[object]$DomainObject.SPFRecord = ([array]$Results | Where-Object -Property Strings -match "^v=spf1").strings
			}
		}
		catch
		{
			throw "Unable to query the SPF Record for the domain {0}" -f $DomainName
		}
	}
	END
	{
		Write-Verbose -Message "Get-SpfRecord: Engd"
	}
}

function Get-DmarcRecord
{
	param
	(
		[string]$DomainName
	)
	
	BEGIN
	{
		Write-Verbose -Message "Get-DmarcRecord: Begin"
	}
	PROCESS
	{
		try
		{
			[array]$Results = Resolve-DnsName -Name "_dmarc.$($DomainName)" -Type TXT -ErrorAction SilentlyContinue
			if (-not ([array]$Results))
			{
				Write-Verbose -Message "Domain does not host a DMARC Record"
			}
			else
			{
				[object]$DomainObject.DMARCRecord = ([array]$Results | Where-Object -Property Strings -match "^v=DMARC1").Strings
			}
		}
		catch
		{
			throw "Unable to query the Dmarc Record for the domain {0}" -f $DomainName
		}
	}
	END
	{
		Write-Verbose -Message "Get-DmarcRecord: End"
	}
}

function Invoke-ValidateSPFRecord
{
	param
	(
		[string]$SPFRecord
	)
	
	BEGIN
	{
		Write-Verbose -Message "Invoke-ValidateSPFRecord: Begin"
	}
	PROCESS
	{
		if ([string]$SPFRecord -match "~all")
		{
			[object]$DomainObject.SPFFailureType = "Soft"
		}
		elseif ([string]$SPFRecord -match "-all")
		{
			[object]$DomainObject.SPFFailureType = "Hard"
		}
		elseif ([string]$SPFRecord -match "\?all")
		{
			[object]$DomainObject.SPFFailureType = "Neutral"
		}
	}
	END
	{
		Write-Verbose -Message "Invoke-ValidateSPFRecord: End"
	}
}

function Invoke-ValidateDmarcRecord
{
	param
	(
		[string]$DmarcRecord
	)
	
	BEGIN
	{
		Write-Verbose -Message "Invoke-ValidateDmarcRecord: Begin"
	}
	PROCESS
	{
		if ([string]$DmarcRecord -match "p=quarantine")
		{
			[object]$DomainObject.DMARCPolicy = "Quaruntine"
		}
		elseif ([string]$DmarcRecord -match "p=reject")
		{
			[object]$DomainObject.DMARCPolicy = "Reject"
		}
	}
	END
	{
		Write-Verbose -Message "Invoke-ValidateDmarcRecord: End"
	}
}

function Invoke-SpoofCheck
{
	BEGIN
	{
		Write-Verbose -Message "Invoke-SpoofCheck: Begin"
	}
	PROCESS
	{
		Get-SpfRecord -DomainName $DomainName
		Get-DmarcRecord -DomainName $DomainName
		Invoke-ValidateSPFRecord -SPFRecord $DomainObject.SPFRecord
		Invoke-ValidateDmarcRecord -DmarcRecord $DomainObject.DMARCRecord
		If ([object]$DomainObject.SPFRecord -eq $null -or `
			[object]$DomainObject.SPFFailureType -eq "Soft" -or `
			[object]$DomainObject.DMARCRecord -eq $null -or `
			[object]$DomainObject.DMARCPolicy -eq $null)
		{
			[object]$DomainObject.Spoofable = [bool]$true
		}
		if ([object]$DomainObject)
		{
			return [bool]$true
		}
		else
		{
			Write-Verbose -Message "Invoke-SpoofCheck: The DomainObject is null"
		}
	}
	END
	{
		Write-Verbose -Message "Invoke-SpoofCheck: End"
	}
}

if (Invoke-SpoofCheck)
{
	return [object]$DomainObject
}
