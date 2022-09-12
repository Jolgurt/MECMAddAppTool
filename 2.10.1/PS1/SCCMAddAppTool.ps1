### Global Variables ###
# When compiled with PS2EXE the variable MyCommand contains no path anymore
if ($MyInvocation.MyCommand.CommandType -eq "ExternalScript")
{ # Powershell script
	$ScriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
}
else
{ # PS2EXE compiled script
	$ScriptPath = Split-Path -Parent -Path ([Environment]::GetCommandLineArgs()[0])
}
$LocalDrive = "C:"
#if this is running from a mapped drive, replace the drive letter with the root
if(-not($ScriptPath.StartsWith("\\")) -and -not($ScriptPath.StartsWith($LocalDrive))){
    $ThisScriptRoot = (Get-PSDrive ($ThisScript.Split(":")[0])).DisplayRoot
    if($ThisScriptRoot -ne $null){
        $ScriptPath = Join-Path $ThisScriptRoot $ScriptPath.Split(":")[1]
    }
}
$SettingsXML = "$ScriptPath\SCCMAddAppSettings.xml"
$PkgNameFormat = "Manufacturer_Product_Version"
$scriptVersion = "2.10.1"

### About
$about = "*************************************************************************`n"
$about += "  ScriptName:   SCCM AddApp Tool`n"
$about += "  ScriptVersion:  $scriptVersion`n"
$about += "  Created by:      Joel Chettle`n"
$about += "  Description:    Creates software groups in Active Directory and`n" 
$about += " 	           applications/packages in SCCM, including the`n"
$about += " 	           collections and deployments if capable, per`n"
$about += " 	           configurations defined in a settings xml.`n"
$about += "  Requirements: Must be ran under an account with privileges to AD`n"
$about += " 	           and SCCM.`n"
$about += " 	           Must have Configuration Manager Console and`n"
$about += " 	           AdminTools installed.`n"
$about += "*************************************************************************`n"
$about += "  Notes:`n"
$about += "     1) Can only create a Detection method using a product code.`n"
$about += "         And the version check is not implemented.`n"
$about += "     2) Does not add Operating System Requirements to Deployment`n"
$about += "         Types when using 2 MSI's (x86/x64)`n"
$about += "     3) Can only select one Catalog Category`n"
$about += "     4) Cannot use dll files for the Application Icon`n"
$about += "     5) The more categories that exist in SCCM, the longer it will take`n"
$about += "         the form to load/reset`n"
$about += "*************************************************************************`n`n"

Function Main{
### This function performs the steps to create the Application in AD and SCCM when user clicks "Create" button on the GUI ###
    $Date = (Get-Date).ToShortDateString()
    $Comment = $Date + " - " + $env:USERNAME
    $ADGroup =  $PackageName.Replace($PkgDelimiter," ")
    $CollectionName = $PackageName + "-Install"
    if($isApp){
        $whatType = "Application"
    }else{
        $whatType = "Package"
    }
    $BetaName = $PkgPrefix + $PackageName
    $Manufacturer = $PackageName.Split($PkgDelimiter)[0]
    $Product = $PackageName.Split($PkgDelimiter)[1]
    $ManuProduct = $Manufacturer + " " + $Product
    $Version = $PackageName.Substring($PackageName.IndexOf($PkgDelimiter)+1)
    $Version = $Version.Substring($Version.IndexOf($PkgDelimiter)+1)
    $TotalSteps = 5
    #adjust total of the progress bar depending on steps required
    if($isApp){$TotalSteps = $TotalSteps + 1} #cleanup rev history
    if(-not($isManual)){$TotalSteps = $TotalSteps + 3} #creating deployments
    if($isMSIx64){$TotalSteps = $TotalSteps + 1} #additional deployment type
    if($AddPCs){$TotalSteps = $TotalSteps + 1} #adding machines to AD group
    $CurrentStep = 0

    DM "======================================================"
    DM " $ADGroup"
    DM (" " + (Get-Date))
    DM "======================================================"

    $eap = $ErrorActionPreference
    $ErrorActionPreference = "SilentyContinue"
#region################ Active Directory block ###################################################
    if(-not($DoStepAD)){
        $Skip = $true
    }else{
        DM "Creating AD group..." -NNL
        #check if already exists.  YesNo box to continue.
        $Skip = $null
        $Error.Clear()
        $test = Get-ADGroup $ADGroup
        if($Error[0] -eq $null){
            $Skip = SkipPrompt "Active Directory group" $ADGroup
            if($Skip -eq $false){Return}
        }
    }
    #create
    if(-not($Skip)){
        $Error.Clear()
        New-ADGroup $ADGroup -Path $ADPath -GroupScope $ADGroupScope -Description $ADDescription
        if((ErrorChecker) -eq $false){Return}
        #validate
        if((Validate "Get-ADGroup `"$ADGroup`"") -eq $false){
            $Msg = "Failed to create Active Directory group."
            if((ErrorChecker $Msg) -eq $false){Return}
        }
    }
    $CurrentStep++
    $ProgressBar.Value = $CurrentStep/$TotalSteps * 100

    #add machines
    if($AddPCs){
        DM "Adding machines to AD group..."
        $PCNames = $PCNames.Replace(" ","")
        foreach($targetPC in ($PCNames.Split(",").Split(";"))){
            $ADtarget = $null
            $ADtarget = Get-ADComputer $targetPC
            if($ADtarget -eq '' -or $ADtarget -eq $null){
                DM "$targetPC not found in AD. Skipping." "Orange"
	        }else{
                $Error.Clear()
                Add-ADGroupMember (Get-ADGroup $ADGroup) $ADtarget
                if($Error[0] -ne $null){
                    DM "Error adding $targetPC to AD group. Continuing..." "Red"
                }
            }
        }
        $CurrentStep++
        $ProgressBar.Value = $CurrentStep/$TotalSteps * 100
    }
#endregion########################################################################################
#region################ SCCM Collection block ####################################################
    Set-Location $Sitecode
    if(-not($DoStepCollection)){
        $Skip = $true
    }else{
        $CollectionFolder = ".\$CollectionFolder"
        DM "Creating Collection..." -NNL
        #check if already exists.  YesNo box to continue.
        $Skip = $null
        $test = Get-CMDeviceCollection -Name $CollectionName
        if($test -ne $null){
            $Skip = SkipPrompt "Device Collection" $CollectionName
            if($Skip -eq $false){Return}
        }
    }
    #create
    if(-not($Skip)){
        $StartTime = [DateTime]"$Date 12:00 AM"
        $Schedule = New-CMSchedule -RecurCount $RefreshIntCount -RecurInterval $RefreshInterval -Start $StartTime
        $Error.Clear()
        $Collection = New-CMDeviceCollection -Name $CollectionName -LimitingCollectionName $LimitingCollection -Comment $Comment -RefreshSchedule $Schedule
        if((ErrorChecker) -eq $false){Return}
        if($DoStepAD){
            $Query = "select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where SystemGroupName = ""$ADDomain\\$ADGroup"""
            Add-CMDeviceCollectionQueryMembershipRule -Collection $Collection -QueryExpression $Query -RuleName $PackageName
        }
        #validate
        if((Validate "Get-CMDeviceCollection -Name $CollectionName") -eq $false){
            $Msg = "Failed to create Device Collection."
            if((ErrorChecker $Msg) -eq $false){Return}
        }
        $CurrentStep++
        $ProgressBar.Value = $CurrentStep/$TotalSteps * 100
        if(-not(Test-Path $CollectionFolder)){
            DM "Creating folder..."
            New-Item $CollectionFolder -ItemType directory
            $timeout = 0
            do{Start-Sleep -Seconds 1;$timeout++}while(-not(Test-Path $CollectionFolder) -and $timeout -lt 20)
        }
        DM "Moving Collection..."
        $Error.Clear()
        Move-CMObject -InputObject $Collection -FolderPath $CollectionFolder
        if((ErrorChecker) -eq $false){DM "Failed to move Collection. Look for it in root folder." "Orange"}
        $CurrentStep++
        $ProgressBar.Value = $CurrentStep/$TotalSteps * 100
    }else{
        $CurrentStep = $CurrentStep + 2
        $ProgressBar.Value = $CurrentStep/$TotalSteps * 100
    }
#endregion########################################################################################
#region################ SCCM Application block ###################################################
    $ApplicationPath = ".\$whatType\$ApplicationFolder"
    DM "Creating $whatType..." -NNL
    #check if already exists.  YesNo box to continue.
    $Skip = $null
    if($isApp){
        $test = Get-CMApplication -Name $PackageName
            if($test -ne $null){
            $Skip = SkipPrompt $whatType $PackageName
            if($Skip -eq $false){Return}
        }
        $test = Get-CMApplication -Name $BetaName
        if($test -ne $null){
            $Skip = SkipPrompt $whatType $BetaName
            if($Skip -eq $false){Return}
        }
    }else{
        $test = Get-CMPackage -Name $BetaName
        if($test -ne $null){
            $Skip = SkipPrompt $whatType $BetaName
            if($Skip -eq $false){Return}
        }
    }
    #create
    if(-not($Skip)){
        $Error.Clear()
        if($isApp){
            $Application = New-CMApplication -Name $BetaName -Description $Comment -ReleaseDate $Date -AutoInstall $AllowTaskSeqInstall -LocalizedApplicationName $ManuProduct -Publisher $Manufacturer -SoftwareVersion $Version
            Set-CMApplication -Name $BetaName -DistributionPointSetting $PrestageDP
            if($AppAdmCat -ne "" -and $AppAdmCat -ne $null){
                Set-CMApplication -Name $BetaName -AppCategories $AppAdmCat
            }
            if($AppDesc -ne "" -and $AppDesc -ne $null){
                Set-CMApplication -Name $BetaName -LocalizedApplicationDescription $AppDesc
            }
            if($AppKeys -ne "" -and $AppKeys -ne $null){
                Set-CMApplication -Name $BetaName -Keyword $AppKeys
            }
            if($AppIcon -ne "" -and $AppIcon -ne $null){
                Set-CMApplication -Name $BetaName -IconLocationFile $AppIcon
            }
            if($AppCat -ne "" -and $AppCat -ne $null){
                Set-CMApplication -Name $BetaName -UserCategories $AppCat
            }
            $tester = "Get-CMApplication -Name $BetaName"  
        }else{
            $Application = New-CMPackage -Name $BetaName -Description $Comment
            $tester = "Get-CMPackage -Name $BetaName"
        }
        if((ErrorChecker) -eq $false){Return}
        #validate
        if((Validate $tester) -eq $false){
            $Msg = "Failed to create $whatType."
            if((ErrorChecker $Msg) -eq $false){Return}
        }
        $CurrentStep++
        $ProgressBar.Value = $CurrentStep/$TotalSteps * 100
        if(-not(Test-Path $ApplicationPath)){
            DM "Creating folder..."
            New-Item $ApplicationPath -ItemType directory
            $timeout = 0
            do{Start-Sleep -Seconds 1;$timeout++}while(-not(Test-Path $ApplicationPath) -and $timeout -lt 20)
        }
        DM "Moving $whatType..."
        $Error.Clear()
        Move-CMObject -InputObject $Application -FolderPath $ApplicationPath
        if((ErrorChecker) -eq $false){DM "Failed to move $whatType. Look for it in root folder." "Orange"}
        $CurrentStep++
        $ProgressBar.Value = $CurrentStep/$TotalSteps * 100
    }else{
        $CurrentStep = $CurrentStep + 2
        $ProgressBar.Value = $CurrentStep/$TotalSteps * 100
    }
#endregion########################################################################################
#region################ SCCM Deployment block ####################################################
    if(-not($isManual)){
        if($isMSIx64){
            $Bits = @(" (x86)"," (x64)")
        }else{
            $Bits = @("")
        }
        foreach($Bit in $Bits){
            DM "Creating Deployment Type$Bit..." -NNL
            $DeploymentType = $PackageName + $Bit
            #check if already exists.  YesNo box to continue.
            $Skip = $null
            $test = Get-CMDeploymentType -ApplicationName $BetaName -DeploymentTypeName $DeploymentType
            if($test -ne $null){
                $Skip = SkipPrompt "Deployment Type" $DeploymentType
                if($Skip -eq $false){Return}
            }
            #create
            if(-not($Skip)){
                $InstFullPath = Join-Path $SourcePath $InstFileName
                if($isMSI){
                    $Log = "/{0} {1}\{2}_MSI_Install.log" -f $LogOption,$LogPath,$PackageName
                    if($Bit -eq " (x64)"){
                        $InstFullPath = Join-Path $SourcePath $MSINamex64
                        $MSTName = $MSTNamex64
                    }
                    $InstFileName = $InstFullPath.Split("\")[-1]
                    if($isTransform){
                        $MSTName = $MSTName.Split("\")[-1]
                        $InstCMD = "msiexec /i `"$InstFileName`" TRANSFORMS=`"$MSTName`" $MSIargs $Log"
                    }else{
                        $InstCMD = "msiexec /i `"$InstFileName`" $MSIargs $Log"
                    }
                    $Log = "/{0} {1}\{2}_MSI_Uninstall.log" -f $LogOption,$LogPath,$PackageName
                    $ProdID = (Get-MSIProps $InstFullPath.ToString()).ProductCode
                    $UninstallCMD = "msiexec /x $ProdID $UninstallArgs $Log"
                    if($AllowBranchCache){
                        $Error.Clear()
                        Add-CMMSiDeploymentType -ApplicationName $BetaName -DeploymentTypeName $DeploymentType -ContentLocation $InstFullPath -Force -Comment $Comment -InstallCommand $InstCMD -UninstallCommand $UninstallCMD -MaximumRuntimeMins $maxDeployTime -SourceUpdateProductCode $ProdID -InstallationBehaviorType $InstallBehavior -EnableBranchCache
                    }else{
                        $Error.Clear()
                        Add-CMMSiDeploymentType -ApplicationName $BetaName -DeploymentTypeName $DeploymentType -ContentLocation $InstFullPath -Force -Comment $Comment -InstallCommand $InstCMD -UninstallCommand $UninstallCMD -MaximumRuntimeMins $maxDeployTime -SourceUpdateProductCode $ProdID -InstallationBehaviorType $InstallBehavior
                    }
                }elseif($isAppV){
                    $Error.Clear()
                    Add-CMAppv5XDeployment​Type -ApplicationName $BetaName -DeploymentTypeName $DeploymentType -ContentLocation $InstFullPath -Force -Comment $Comment
                }elseif($isScript){
                    $Error.Clear()
                    Add-CMScriptDeploymentType -ApplicationName $BetaName -DeploymentTypeName $DeploymentType -ContentLocation $SourcePath -Force -Comment $Comment -InstallCommand $InstFileName -UninstallCommand $MSTName -ProductCode $ProdCode -MaximumRuntimeMins $maxDeployTime -InstallationBehaviorType $InstallBehavior
                }
                if((ErrorChecker) -eq $false){Return}
                #validate
                $timeout = 0
                do{
                    Start-Sleep -Seconds 1
                    $test = Get-CMDeploymentType -ApplicationName $BetaName -DeploymentTypeName $DeploymentType
                    if($test -ne $null){
                        DM "Success" "Green"
                        $timeout = 10
                    }
                    $timeout++
                }while($timeout -lt 10)
                if($test -eq $null){
                    $Msg = "Failed to create Deployment Type."
                    if((ErrorChecker $Msg) -eq $false){Return}
                }
                #Fix Branch cache > Add-CMScriptDeploymentType does not work using -EnableBranchCache. Using depreciated Set with -AllowClientsToShareContentOnSameSubnet
                if($isScript){
                    DM "Modifying Deployment Type..."
                    $Error.Clear()
                    Set-CMDeploymentType -ApplicationName $BetaName -DeploymentTypeName $DeploymentType -MsiOrScriptInstaller -AllowClientsToShareContentOnSameSubnet $AllowBranchCache
                    if((ErrorChecker) -eq $false){Return}
                }
            }
            $CurrentStep++
            $ProgressBar.Value = $CurrentStep/$TotalSteps * 100
        }
        if($isMSIx64){
            DM "Operating system requirements were not added to the Deployment Types. Please enter manually if needed." "Orange"
        }

        DM "Distributing Content..."
        $Error.Clear()
        Start-CMContentDistribution -ApplicationName $BetaName -DistributionPointGroupName $DPGroup
        if((ErrorChecker) -eq $false){Return}
        $CurrentStep++
        $ProgressBar.Value = $CurrentStep/$TotalSteps * 100

        if($DoStepDeployment){
            DM "Creating Deployment..."
            $Error.Clear()
            #for some reason in this latest version it uses local time for Available and UTC for Deadline. so to get to match, have to add hour difference to Available
            $UTChourDiff = (New-TimeSpan -Start (Get-Date) -End (Get-Date).ToUniversalTime()).TotalHours
            Start-CMApplicationDeployment -Name $BetaName -CollectionName $CollectionName -Comment $Comment -AvailableDateTime (Get-Date).AddHours($UTChourDiff) -DeadlineDateTime (Get-Date) -DeployPurpose Required -UserNotification $UserNotification -SendWakeUpPacket $SendWakeup
            if((ErrorChecker) -eq $false){Return}
            if($PkgrTestCollection -ne "" -and $PkgrTestCollection -ne $null){
                Start-CMApplicationDeployment -Name $BetaName -CollectionName $PkgrTestCollection -Comment $Comment -AvailableDateTime (Get-Date).AddHours($UTChourDiff) -DeployPurpose Available -UserNotification $UserNotification -SendWakeUpPacket $SendWakeup
            }
        }
        $CurrentStep++
        $ProgressBar.Value = $CurrentStep/$TotalSteps * 100
    }else{
        DM "Since Manual was selected you must create the Deployment." "Orange"
    }
#endregion########################################################################################
#region################ Application Cleanup block ################################################
    if($isApp){
        DM "Cleaning Application Revision History..."
        #remove all revisions except most current
        $Revisions = Get-CMApplicationRevisionHistory -Name $BetaName
        if($Revisions.Count -gt 1){
            for($Rev=1; $Rev -lt $Revisions.Count; $Rev++){
                Remove-CMApplicationRevisionHistory -Name $BetaName -Revision $Rev -Force
            }
        }
        $CurrentStep++
        $ProgressBar.Value = $CurrentStep/$TotalSteps * 100
        #remove temp icon file
        if($AppIcon -ne "" -and $AppIcon -ne $null){
            if((Get-Item $AppIcon).DirectoryName -eq (Get-Item $env:TEMP).FullName){
                Remove-Item $AppIcon -Force | Out-Null
            }
        }
    }
#endregion########################################################################################

    Reset-Form
    DM "Completed"
    DM "======================================================"
}

Function Get-MSIProps{
## This function gets the Product Code and Version from a given MSI.  Credit for this code from https://winadminnotes.wordpress.com/2010/04/05/accessing-msi-file-as-a-database/
param($MSIFileName)
    $temp = New-Object PsCustomObject
    $WindowsInstaller = New-Object -com WindowsInstaller.Installer
    $Database = $WindowsInstaller.GetType().InvokeMember(“OpenDatabase”, “InvokeMethod”, $Null, $WindowsInstaller, @($MSIFileName,0))
    $Properties = @("ProductCode","ProductVersion")
    foreach($Property in $Properties){
        $Query = “SELECT Value FROM Property WHERE Property = '{0}'” -f $Property
        $View = $Database.GetType().InvokeMember(“OpenView”, “InvokeMethod”, $Null, $Database, ($Query))
        $View.GetType().InvokeMember(“Execute”, “InvokeMethod”, $Null, $View, $Null)
        $Record = $View.GetType().InvokeMember(“Fetch”, “InvokeMethod”, $Null, $View, $Null)
        $PropertyValue = $Record.GetType().InvokeMember(“StringData”, “GetProperty”, $Null, $Record, 1)
        Add-Member -In $temp -Name $Property -Value $PropertyValue -MemberType NoteProperty
    }
    Return $temp
}

Function Import-Settings{
## This function grabs the values from the settings XML entered by the user and stores them in Variables ###
    if(-not(Test-Path $SettingsXML)){Return $false}
    [xml]$Settings = Get-Content $SettingsXML
    [System.Collections.ArrayList]$AllowNulls = @("ADDescription","PkgPrefix","ScriptInstallCMD","ScriptUninstallCMD","TestMachines","PkgrTestCollection")
    [System.Collections.ArrayList]$BooleanVals = @("SelectAll","CreateAD","CreateCollection","CreateDeployment","AllowTaskSeqInstall","AllowBranchCache","SendWakeup")
    foreach($XMLSet in ($Settings.Settings.ChildNodes).Name){
        $Value = ($Settings.Settings.$XMLSet).Trim()
        if(($Value -eq "" -or $Value -eq $null) -and -not($AllowNulls.Contains($XMLSet))){
            $OkHolder = ShowBox "$XMLSet is not valid. Please enter a value in settings XML.`n$SettingsXML" "Error" "Error"
            Return $false
        }elseif($Value -eq $null -and $AllowNulls.Contains($XMLSet)){
            Set-Variable -Name $XMLSet -Value "" -Scope Global
        }elseif($BooleanVals.Contains($XMLSet)){
            Set-Variable -Name $XMLSet -Value (Convert-ToBoolean $Value) -Scope Global
        }else{
            Set-Variable -Name $XMLSet -Value $Value -Scope Global
        }
    }
    $tempHash = @{}
    foreach($tester in $Settings.Settings.TestMachines.Tester){$tempHash.Add($tester.User, $tester.'#text')}
    Set-Variable -Name TestMachines -Value $tempHash -Scope Global
    Return $true
}

Function Convert-ToBoolean{
## This function converts String true/false data from XML to a boolean value
param($ConvertStr)
    #if anything other than true, default to false
    if($ConvertStr.ToUpper() -eq "TRUE"){
        Return $true
    }else{
        Return $false
    }
}

Function Set-Vars{
### This function grabs the values from the GUI entered by the user and stores them in Variables ###
	Set-Variable -Name PackageName -Value $TextBoxAppName.Text -Scope Global
    Set-Variable -Name isApp -Value $RadioBtnApp.Checked -Scope Global
    Set-Variable -Name isManual -Value $RadioBtnManual.Checked -Scope Global
    Set-Variable -Name isMSI -Value $RadioBtnMSI.Checked -Scope Global
    Set-Variable -Name isAppV -Value $RadioBtnAppV.Checked -Scope Global
    Set-Variable -Name isScript -Value $RadioBtnScript.Checked -Scope Global
    Set-Variable -Name SourcePath -Value $LabelSourcePath.Text -Scope Global
    Set-Variable -Name InstFileName -Value $TextBoxInstFile.Text -Scope Global
    Set-Variable -Name isTransform -Value $CheckBoxTransform.Checked -Scope Global
    Set-Variable -Name MSTName -Value $TextBoxTransform.Text -Scope Global
    Set-Variable -Name isMSIx64 -Value $CheckBoxx64.Checked -Scope Global
    Set-Variable -Name MSINamex64 -Value $TextBoxMSIx64.Text -Scope Global
    Set-Variable -Name MSTNamex64 -Value $TextBoxTransformx64.Text -Scope Global
    Set-Variable -Name ProdCode -Value $TextBoxProdCode.Text -Scope Global
    Set-Variable -Name AppAdmCat -Value (($ListViewAdmCategory.CheckedItems |ForEach-Object {$_.name}) -join ',') -Scope Global
    Set-Variable -Name AppDesc -Value $TextBoxDesc.Text -Scope Global
    Set-Variable -Name AppCat -Value $ComboBoxCategory.SelectedItem -Scope Global
    Set-Variable -Name AppKeys -Value $TextBoxKeywords.Text -Scope Global
    Set-Variable -Name AppIcon -Value $TextBoxIcon.Text -Scope Global
    Set-Variable -Name DoStepAD -Value $CheckBoxADGroup.Checked -Scope Global
    Set-Variable -Name DoStepCollection -Value $CheckBoxCollection.Checked -Scope Global
    Set-Variable -Name DoStepDeployment -Value $CheckBoxDeployment.Checked -Scope Global
    Set-Variable -Name AddPCs -Value $CheckBoxAddPCs.Checked -Scope Global
    Set-Variable -Name PCNames -Value $TextBoxAddPCs.Text -Scope Global
}

Function Check-Input{
### This function validates user input ###
    #From GUI
    if($PackageName -eq "" -or $PackageName -eq $null -or $PackageName.Split($PkgDelimiter).Count -lt 3){
        $OkHolder = ShowBox ("Package name not valid. Use format: {0}" -f $PkgNameFormat.Replace("_",$PkgDelimiter)) "Error" "Error"
        Return $false
    }
    #remove valid special characters and check the rest
    $TestPkgName = $PackageName
    @("-","_",".","(",")",$PkgDelimiter) | %{$TestPkgName = $TestPkgName.Replace($_,"")}
    if($TestPkgName -notmatch '^[0-9a-zA-Z]+$'){
        $badChar = [System.Text.RegularExpressions.Regex]::Replace($TestPkgName,"[0-9a-zA-Z]","")
        $OkHolder = ShowBox "Package name contains a space or non-alphanumeric character: $badChar" "Error" "Error"
        Return $false
    }
    if($isApp){$maxlength=64}else{$maxlength=50}
    if(($PackageName.Length + $PkgPrefix.Length) -gt $maxlength){
        $OkHolder = ShowBox ("Package name (including Prefix) is too long: {0}. Max is {1} characters." -f ($PackageName.Length + $PkgPrefix.Length),$maxlength) "Error" "Error"
        Return $false
    }
    if(-not($isManual) -and -not($isScript) -and -not(Test-Path (Join-Path $SourcePath $InstFileName))){
        $OkHolder = ShowBox "File not valid. Could not locate: $SourcePath\$InstFileName" "Error" "Error"
        Return $false
    }
    if($isTransform -and -not(Test-Path (Join-Path $SourcePath $MSTName))){
        $OkHolder = ShowBox "File not valid. Could not locate: $SourcePath\$MSTName" "Error" "Error"
        Return $false
    }
    if($isMSIx64 -and -not(Test-Path (Join-Path $SourcePath $MSINamex64))){
        $OkHolder = ShowBox "File not valid. Could not locate: $SourcePath\$MSINamex64" "Error" "Error"
        Return $false
    }
    if($isTransform -and $isMSIx64 -and -not(Test-Path (Join-Path $SourcePath $MSTNamex64))){
        $OkHolder = ShowBox "File not valid. Could not locate: $SourcePath\$MSTNamex64" "Error" "Error"
        Return $false
    }
    if($isApp -and $AppIcon -ne "" -and -not(Test-Path $AppIcon)){
        $OkHolder = ShowBox "Icon not valid. Could not locate: $AppIcon" "Error" "Error"
        Return $false
    }
    if($isScript -and ($ProdCode -eq "" -or $ProdCode -eq $null -or $ProdCode -notmatch '^[0-9a-fA-F{}-]+$')){
        $OkHolder = ShowBox "Product code not valid." "Error" "Error"
        Return $false
    }
    if($AddPCs -and ($PCNames -eq "" -or $PCNames -eq $null)){
        $OkHolder = ShowBox "Machine names not valid." "Error" "Error"
        Return $false
    }
    if($DoStepAD){
        $AdminTools = $false
        foreach($module in (Get-Module -ListAvailable)){
            if($module.Name -eq "ActiveDirectory"){
                $AdminTools = $true
                Break
            }
        }
        if($AdminTools -eq $false){
            $OkHolder = ShowBox "Administrative Tools is required." "Error" "Error"
            Return $false
        }
    }
    #From XML
    if($DoStepAD -and $ADGroupScope -ne "DomainLocal" -and $ADGroupScope -ne "Global" -and $ADGroupScope -ne "Universal"){
        $OkHolder = ShowBox "ADGroupScope not valid in settings XML. Valid values are DomainLocal, Global, Universal." "Error" "Error"
        Return $false
    }
    if(-not($sitecode.Contains(":"))){
        Set-Variable -Name sitecode -Value ($sitecode + ":") -Scope Global
    }
    if(-not($CollectionFolder.ToUpper().StartsWith("DEVICECOLLECTION\"))){
        $OkHolder = ShowBox "CollectionFolder not valid in settings XML. Valid values must be under DeviceCollection\." "Error" "Error"
        Return $false
    }
    if($RefreshInterval -ne "Minutes" -and $RefreshInterval -ne "Hours" -and $RefreshInterval -ne "Days"){
        $OkHolder = ShowBox "RefreshInterval not valid in settings XML. Valid values are Minutes, Hours, Days." "Error" "Error"
        Return $false
    }
    $testDeci = Try{[decimal]$RefreshIntCount}Catch{0}
    if($testDeci -le 0){
        $OkHolder = ShowBox "RefreshIntCount not valid in settings XML. Must be a numeric value greater than 0." "Error" "Error"
        Return $false
    }
    if(($RefreshInterval -eq "Minutes" -and $testDeci -gt 59) -or ($RefreshInterval -eq "Hours" -and $testDeci -gt 23) -or ($RefreshInterval -eq "Days" -and $testDeci -gt 31)){
        $OkHolder = ShowBox "RefreshIntCount not valid in settings XML. Must be a numeric with maximum value per interval: Minutes-59, Hours-23, Days-31." "Error" "Error"
        Return $false
    }
    if($PrestageDP -ne "AutoDownload" -and $PrestageDP -ne "DeltaCopy" -and $PrestageDP -ne "NoDownload"){
        $OkHolder = ShowBox "PrestageDP not valid in settings XML. Valid values are AutoDownload, DeltaCopy, NoDownload." "Error" "Error"
        Return $false
    }
    if($InstallBehavior -ne "InstallForUser" -and $InstallBehavior -ne "InstallForSystem" -and $InstallBehavior -ne "InstallForSystemIfResourceIsDeviceOtherwiseInstallForUser"){
        $OkHolder = ShowBox "InstallBehavior not valid in settings XML. Valid values are InstallForUser, InstallForSystem, InstallForSystemIfResourceIsDeviceOtherwiseInstallForUser." "Error" "Error"
        Return $false
    }
    $testDeci = Try{[decimal]$maxDeployTime}Catch{0}
    if($testDeci -lt 15 -or $testDeci -gt 720){
        $OkHolder = ShowBox "maxDeployTime not valid in settings XML. Must be a numeric value between 15 and 720." "Error" "Error"
        Return $false
    }
    if($UserNotification -ne "DisplayAll" -and $UserNotification -ne "DisplaySoftwareCenterOnly" -and $UserNotification -ne "HideAll"){
        $OkHolder = ShowBox "UserNotification not valid in settings XML. Valid values are DisplayAll, DisplaySoftwareCenterOnly, HideAll." "Error" "Error"
        Return $false
    }
    if($PkgDelimiter -match '^[0-9a-zA-Z]+$'){
        $OkHolder = ShowBox "Package delimiter not valid in settings XML. It must be a non-alphanumeric character." "Error" "Error"
        Return $false
    }
    $badChars = @("/","\",":","|","*","?","<",">","`""," ",".")
    $hasBadChar = $false
    foreach($char in $badChars){
        if($PkgDelimiter.Contains($char)){
            $hasBadChar = $true
            Break
        }
    }
    if($hasBadChar){
        $OkHolder = ShowBox "Package delimiter not valid in settings XML. It cannot contain a space or any of the following characters: /\:|*?<>`"." "Error" "Error"
        Return $false
    }
    if($LogOption.StartsWith("/")){
        Set-Variable -Name LogOption -Value ($LogOption.TrimStart("/")) -Scope Global
    }
    if(-not($LogOption.ToUpper().StartsWith("L"))){
        $OkHolder = ShowBox "LogOption not valid in settings XML. Valid values start with 'L'." "Error" "Error"
        Return $false
    }
    Return $true
}

Function Check-Prereqs{
### This function validates prerequisites ###
    if($PSVersionTable.PSVersion.Major -lt 3){
        $OkHolder = ShowBox "PowerShell 3.0 or greater is required." "Error" "Error"
        Return $false
    }
    if($env:SMS_ADMIN_UI_PATH -eq $null){
        $OkHolder = ShowBox "System Center Configuration Manager Console is required." "Error" "Error"
        Return $false
    } 
    if(-not(Test-Path $SettingsXML)){
        $OkHolder = ShowBox "Required settings XML could not be found or accessed.`n$SettingsXML" "Error" "Error"
        Return $false
    }
	Return $true
}

Function ShowBox{
### This function is used to display a popup box on the screen if needed ###
param($msg,$title,$whatIcon,[switch]$YesNo)
    switch($whatIcon){
		"Error"{$icon = [Windows.Forms.MessageBoxIcon]::Error}
		"Warn"{$icon = [Windows.Forms.MessageBoxIcon]::Warning}
		default{$icon = [Windows.Forms.MessageBoxIcon]::Information}
	}
    if($YesNo){
        $UserChoice = [Windows.Forms.MessageBox]::Show($msg, $title, [Windows.Forms.MessageBoxButtons]::YesNo, $icon)
        Return $UserChoice
    }else{
	    [Windows.Forms.MessageBox]::Show($msg, $title, [Windows.Forms.MessageBoxButtons]::Ok, $icon)
    }
}

Function Display-Message{
### This function writes output to the GUI log window ###
param($msg,$color='Black',[switch]$NNL)
	if(-not($NNL)){$msg += "`r`n"}
	$OutputBox.SelectionColor = $color
	$OutputBox.AppendText($msg)
	$OutputBox.ScrollToCaret()
}
Set-Alias -name DM -value Display-Message

Function ErrorChecker{
### This function is used to stop Main if an Error is detected ###
param($customError="")
    if($Error[0] -ne $null -or $customError -ne ""){
        if($customError -ne ""){
            $ErrorMsg = $customError
        }else{
            $ErrorMsg = $Error[0].Exception
        }
        $OkHolder = ShowBox $ErrorMsg "Error" "Error"
        DM "Failed" "Red"
        DM "Script Ended..."
        DM "======================================================"
        $RunButton.Enabled = $true
        $ResetButton.Enabled = $true
        $QuitButton.Enabled = $true
        $ProgressBar.Value = 0
        $StatusStripLabel.Text = "Ready"
        $StatusStrip.Update()
        $ErrorActionPreference = $eap
        Set-Location $LocalDrive
        Return $false
    }else{
        Return $true
    }
}

Function SkipPrompt{
### This function is used to give a popup prompt to the user if they would like to skip a step that is already created ###
param($description,$name)
    $Choice = ShowBox "$description $name already exists.  Would you like to skip this step?" "Warning" "Warn" -YesNo
    if($Choice -eq "No"){          
        $Msg = "Script cancelled by user.  Hit OK to continue."
        if((ErrorChecker $Msg) -eq $false){Return $false}
    }else{
        DM "Skipped" "Magenta"
        Return $true
    }
}

Function Validate{
### This function performs validation checks after various steps in Main ###
param($testCMD)
    $ErrorActionPreference = "SilentyContinue"
    $timeout = 0
    $test = $null
    do{
        Start-Sleep -Seconds 1
        $test = Invoke-Expression $testCMD
        if($test -ne $null){
            DM "Success" "Green"
            $timeout = 10
        }
        $timeout++
    }while($timeout -lt 10)
    if($test -eq $null){
        Return $false
    }else{
        Return $true
    }
}

Function Get-FileName{
### This function creates the File window when browsing for files ###
param($extension, $desc)
	$OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
	$OpenFileDialog.InitialDirectory = $LabelSourcePath.Text
	$OpenFileDialog.Filter = "$desc ($extension)| $extension"
	$OpenFileDialog.ShowDialog() | Out-Null
	$OpenFileDialog.Filename
}

Function Pop-FileName{
### This function populates the associated text box with the trimmed file from Get-FileName ###
param($targFile, $targTxtBox)
    if($targFile -ne $null){
        $ParentDir = ($LabelSourcePath.Text) + "\"
        if($targFile.Contains($ParentDir)){
            $targTxtBox.Text = $targFile.Replace($ParentDir,"")
        }elseif($targFile.Contains($PkgFilesFolder)){
            $LabelSourcePath.Text = $PkgFilesFolder
            $targTxtBox.Text = $targFile.Replace(($PkgFilesFolder + "\"),"")
        }else{
            $OkHolder = ShowBox "File must be located under $PkgFilesFolder" "Error" "Error"
        }
    }
}

Function Reset-Form{
### This function resets the GUI to its natural state, except for the output log ###
    Reset-Cats
    Set-FormToPkg
    Set-FormToApp
    $CheckBoxSelectAll.Checked = $SelectAll
    $CheckBoxADGroup.Checked = $CreateAD
    $CheckBoxCollection.Checked = $CreateCollection
    $CheckBoxDeployment.Checked = $CreateDeployment
    Set-FormToOptions
    $TextBoxAppName.Text = ($PkgNameFormat.Replace("_",$PkgDelimiter))
    $RadioBtnApp.Checked = $true
    $RadioBtnPkg.Checked = $false
    $CheckBoxAddPCs.Enabled = $true
    $CheckBoxAddPCs.Checked = $false
    $TextBoxAddPCs.Text = ""
    $TextBoxAddPCs.Enabled = $false
    $RunButton.Enabled = $true
    $ResetButton.Enabled = $true
    $QuitButton.Enabled = $true
    $ProgressBar.Value = 0
    $StatusStripLabel.Text = "Ready"
    $StatusStrip.Update()
    $ErrorActionPreference = $eap
}

Function Set-FormToAll{
### This function enables/disables required parts of the GUI if user selects to create all Components ###
    $CheckBoxADGroup.Enabled = $false
    $CheckBoxADGroup.Checked = $true
    $CheckBoxCollection.Enabled = $false
    $CheckBoxCollection.Checked = $true
    $RadioBtnApp.Enabled = $false
    $RadioBtnApp.Checked = $true
    Set-FormToApp
    $RadioBtnPkg.Enabled = $false
    $CheckBoxDeployment.Enabled = $false
    $CheckBoxDeployment.Checked = $true
}

Function Set-FormToOptions{
### This function enables/disables required parts of the GUI if user selects to define Components ###
    if($CheckBoxSelectAll.Checked){Set-FormToAll}
    else{
        if($CheckBoxADGroup.Checked){
            $CheckBoxAddPCs.Enabled = $true
        }else{
            $CheckBoxAddPCs.Enabled = $false
            $TextBoxAddPCs.Enabled = $false
            $TextBoxAddPCs.Text = ""
        }
        if($CheckBoxCollection.Checked -and -not($RadioBtnManual.Checked)){
            $CheckBoxDeployment.Enabled = $true
            $CheckBoxDeployment.Checked = $CreateDeployment
        }else{
            $CheckBoxDeployment.Enabled = $false
            $CheckBoxDeployment.Checked = $false
        }
    }
}

Function Set-FormToPkg{
### This function enables/disables required parts of the GUI in relation to creating a Package ###
    Set-FormToNone
    $RadioBtnManual.Checked = $true
    $RadioBtnMSI.Enabled = $false
    $RadioBtnMSI.Checked = $false
    $RadioBtnAppV.Enabled = $false
    $RadioBtnAppV.Checked = $false
    $RadioBtnScript.Enabled = $false
    $RadioBtnScript.Checked = $false
    $ListViewAdmCategory.Enabled = $false
    $ListViewAdmCategory.CheckedItems |ForEach-Object {$_.Checked = $false}
    $NewAdmCatButton.Enabled = $false
    $TextBoxDesc.Enabled = $false
    $TextBoxDesc.Text = ""
    $ComboBoxCategory.Enabled = $false
    $ComboBoxCategory.SelectedIndex = 0
    $NewCatButton.Enabled = $false
    $TextBoxKeywords.Enabled = $false
    $TextBoxKeywords.Text = ""
    $TextBoxIcon.Enabled = $false
    $TextBoxIcon.Text = ""
    $BrowseButtonIcon.Enabled = $false
    $PictureBoxIcon.Image = $null
}

Function Set-FormToApp{
### This function enables/disables required parts of the GUI in relation to creating an Application ###
    $RadioBtnMSI.Enabled = $true
    $RadioBtnAppV.Enabled = $true
    $RadioBtnScript.Enabled = $true
    $ListViewAdmCategory.Enabled = $true
    $NewAdmCatButton.Enabled = $true
    $TextBoxDesc.Enabled = $true
    $ComboBoxCategory.Enabled = $true
    $NewCatButton.Enabled = $true
    $TextBoxKeywords.Enabled = $true
    $TextBoxIcon.Enabled = $true
    $BrowseButtonIcon.Enabled = $true
}

Function Set-FormToMSI{
### This function enables/disables required parts of the GUI in relation to creating an Application with a MSI ###
    Set-FormToNone
    Set-FormToOptions
    $CheckBoxTransform.Enabled = $true
    $TextBoxInstFile.Enabled = $true
    $TextBoxInstFile.Text = $TextBoxAppName.Text + ".msi"
    $BrowseBtnInstFile.Enabled = $true
    $LabelSourcePath.Text = Join-Path $PkgFilesFolder $TextBoxAppName.Text
    $CheckBoxx64.Enabled = $true
}

Function Set-FormToAppV{
### This function enables/disables required parts of the GUI in relation to creating an Application with an AppV ###
    Set-FormToNone
    Set-FormToOptions
    $TextBoxInstFile.Enabled = $true
    $TextBoxInstFile.Text = $TextBoxAppName.Text + ".appv"
    $BrowseBtnInstFile.Enabled = $true
    $LabelSourcePath.Text = Join-Path $PkgFilesFolder $TextBoxAppName.Text
}

Function Set-FormToScript{
### This function enables/disables required parts of the GUI in relation to creating an Application with a Script ###
    Set-FormToNone
    Set-FormToOptions
    $TextBoxInstFile.Enabled = $true
    $TextBoxInstFile.Text = $ScriptInstallCMD
    $BrowseBtnInstFile.Enabled = $true
    $TextBoxTransform.Enabled = $true
    $TextBoxTransform.Text = $ScriptUninstallCMD
    $BrowseButtonMST.Enabled = $true
    $LabelSourcePath.Text = Join-Path $PkgFilesFolder $TextBoxAppName.Text
    $TextBoxProdCode.Enabled = $true
    $TextBoxProdCode.Text = "{00000000-0000-0000-0000-000000000000}"
    $BrowseBtnDetectMSI.Enabled = $true
    $LabelNotImp.Text = "(Not Implemented)"
}

Function Set-FormToNone{
### This function enables/disables required parts of the GUI in relation to creating an Application without a Deployment Type ###
    $CheckBoxDeployment.Enabled = $false
    $CheckBoxDeployment.Checked = $false
    $CheckBoxTransform.Enabled = $false
    $CheckBoxTransform.Checked = $false
	$TextBoxInstFile.Enabled = $false
    $TextBoxInstFile.Text = ""
    $BrowseBtnInstFile.Enabled = $false
    $LabelSourcePath.Text = $PkgFilesFolder
    $TextBoxTransform.Enabled = $false
    $TextBoxTransform.Text = ""
    $BrowseButtonMST.Enabled = $false
    $CheckBoxx64.Enabled = $false
    $CheckBoxx64.Checked = $false
    $TextBoxMSIx64.Enabled = $false
    $TextBoxMSIx64.Text = ""
    $BrowseButtonMSIx64.Enabled = $false
    $TextBoxTransformx64.Enabled = $false
    $TextBoxTransformx64.Text = ""
    $BrowseButtonMSTx64.Enabled = $false
    $TextBoxProdCode.Enabled = $false
    $TextBoxProdCode.Text = ""
    $BrowseBtnDetectMSI.Enabled = $false
    $ComboBoxComparator.Enabled = $false
    $TextBoxProdVersion.Enabled = $false
    $TextBoxProdVersion.Text = ""
    $LabelNotImp.Text = ""
}

Function Reset-Cats{
### This function refreshes the Catagory dropdown ###
    Set-Location $Sitecode
    $ListViewAdmCategory.Items.Clear()
    Get-CMCategory -CategoryType AppCategories | Sort LocalizedCategoryInstanceName | %{
        $LI = New-Object system.Windows.Forms.ListViewItem
        $LI.Name = $_.LocalizedCategoryInstanceName
		$LI.Text = $_.LocalizedCategoryInstanceName
        $ListViewAdmCategory.Items.add($LI) | Out-Null
    }
    $ComboBoxCategory.Items.Clear()
    $ComboBoxCategory.Items.Add("") | Out-Null
    Get-CMCategory -CategoryType CatalogCategories | Sort LocalizedCategoryInstanceName | %{$ComboBoxCategory.Items.Add($_.LocalizedCategoryInstanceName) | Out-Null}
    $ComboBoxCategory.SelectedIndex = 0
    Set-Location $LocalDrive
}

Function New-Cat{
### This function creates a new Category in SCCM when user clicks the New button ###
param($CatType)
    $NewCat = [Microsoft.VisualBasic.Interaction]::InputBox("Enter a Category name to create", "New Category", "")
    if($NewCat -ne "" -and $NewCat -ne $null){
        Set-Location $Sitecode
        $Error.Clear()
        New-CMCategory -CategoryType $CatType -Name $NewCat | Out-Null
        if($Error[0] -ne $null){
            DM "Error creating Category: $NewCat" "Red"
            $OkHolder = ShowBox $Error[0].Exception "Error" "Error"
            $NewCat = $null
        }else{
            DM "Category created"
        }
        Set-Location $LocalDrive
    }
    Return $NewCat
}

#region################ Main Form (UI) block #####################################################
Function MainForm{
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[void] [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.VisualBasic")

Import-Module ActiveDirectory -ErrorAction SilentlyContinue
Import-Module (Join-Path $(Split-Path $env:SMS_ADMIN_UI_PATH) ConfigurationManager.psd1)

$Form = New-Object System.Windows.Forms.Form 
$Form.Text = "SCCM AddApp Tool v$scriptVersion"
$Form.Size = New-Object System.Drawing.Size(725,710) 
$Form.StartPosition = "CenterScreen"
$Form.FormBorderStyle = "FixedDialog"
$Form.MaximizeBox = $False
$Form.KeyPreview = $True
$Form.Add_KeyDown({if ($_.KeyCode -eq "Escape") {$Form.Close()}})

$MainMenu = New-Object System.Windows.Forms.MenuStrip
$MainMenu.BackColor = [System.Drawing.Color]::LightSteelBlue
$FileMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$FileMenu.Text = "&File"
$miQuit = New-Object System.Windows.Forms.ToolStripMenuItem
$miQuit.Text = "&Quit"
$miQuit.Add_Click({$Form.Close()})
$HelpMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$HelpMenu.Text = "&Help"
$miAbout = New-Object System.Windows.Forms.ToolStripMenuItem
$miAbout.Text = "&About"
$miAbout.Add_Click({[Windows.Forms.MessageBox]::Show($about, "About SCCM AddApp Tool", [Windows.Forms.MessageBoxButtons]::Ok)})
[void]$MainMenu.Items.Add($FileMenu)
[void]$FileMenu.DropDownItems.Add($miQuit)
[void]$MainMenu.Items.Add($HelpMenu)
[void]$HelpMenu.DropDownItems.Add($miAbout)
$Form.Controls.Add($MainMenu)

$LabelAppName = New-Object System.Windows.Forms.Label
$LabelAppName.Location = New-Object System.Drawing.Size(10,30) 
$LabelAppName.Size = New-Object System.Drawing.Size(260,20) 
$LabelAppName.Text = "Package name:"
$Form.Controls.Add($LabelAppName)

$TextBoxAppName = New-Object System.Windows.Forms.TextBox 
$TextBoxAppName.Location = New-Object System.Drawing.Size(10,50) 
$TextBoxAppName.Size = New-Object System.Drawing.Size(260,20)
$Form.Controls.Add($TextBoxAppName)

$GroupBoxTaskOptions = New-Object System.Windows.Forms.GroupBox
$GroupBoxTaskOptions.Location = New-Object System.Drawing.Size(10,80)
$GroupBoxTaskOptions.Size = New-Object System.Drawing.Size(120,120)
$GroupBoxTaskOptions.Text = "Create:"
$Form.Controls.Add($GroupBoxTaskOptions)
$BoxFont = $GroupBoxTaskOptions.Font.Name
$BoxFontSize = $GroupBoxTaskOptions.Font.Size - 1

$CheckBoxSelectAll = New-Object System.Windows.Forms.CheckBox
$CheckBoxSelectAll.Location = New-Object System.Drawing.Size(10,15)
$CheckBoxSelectAll.AutoSize = $True
$CheckBoxSelectAll.Font = New-Object System.Drawing.Font($BoxFont,$BoxFontSize)
$CheckBoxSelectAll.Text = "Select All"
$CheckBoxSelectAll.add_Click({
    if($CheckBoxSelectAll.Checked){
        Set-FormToAll
    }else{
        $CheckBoxADGroup.Enabled = $true
        $CheckBoxADGroup.Checked = $false
        $CheckBoxCollection.Enabled = $true
        $CheckBoxCollection.Checked = $false
        $RadioBtnApp.Enabled = $true
        $RadioBtnPkg.Enabled = $true
        $CheckBoxDeployment.Checked = $false
    }
})
$GroupBoxTaskOptions.Controls.Add($CheckBoxSelectAll)

$CheckBoxADGroup = New-Object System.Windows.Forms.CheckBox
$CheckBoxADGroup.Location = New-Object System.Drawing.Size(20,33)
$CheckBoxADGroup.AutoSize = $True
$CheckBoxADGroup.Font = New-Object System.Drawing.Font($BoxFont,$BoxFontSize)
$CheckBoxADGroup.Text = "AD Group"
$CheckBoxADGroup.add_Click({Set-FormToOptions})
$GroupBoxTaskOptions.Controls.Add($CheckBoxADGroup)

$CheckBoxCollection = New-Object System.Windows.Forms.CheckBox
$CheckBoxCollection.Location = New-Object System.Drawing.Size(20,49)
$CheckBoxCollection.AutoSize = $True
$CheckBoxCollection.Font = New-Object System.Drawing.Font($BoxFont,$BoxFontSize)
$CheckBoxCollection.Text = "Collection"
$CheckBoxCollection.add_Click({Set-FormToOptions})
$GroupBoxTaskOptions.Controls.Add($CheckBoxCollection)

$RadioBtnApp = New-Object System.Windows.Forms.RadioButton
$RadioBtnApp.Location = new-object System.Drawing.Point(20,65)
$RadioBtnApp.AutoSize = $True
$RadioBtnApp.Font = New-Object System.Drawing.Font($BoxFont,$BoxFontSize)
$RadioBtnApp.Text = "Application"
$RadioBtnApp.add_Click({Set-FormToApp})
$GroupBoxTaskOptions.Controls.Add($RadioBtnApp)

$RadioBtnPkg = New-Object System.Windows.Forms.RadioButton
$RadioBtnPkg.Location = new-object System.Drawing.Point(20,81)
$RadioBtnPkg.AutoSize = $True
$RadioBtnPkg.Font = New-Object System.Drawing.Font($BoxFont,$BoxFontSize)
$RadioBtnPkg.Text = "Package"
$RadioBtnPkg.add_Click({
    $OkHolder = ShowBox "This tool was designed primarily for App Model.`nAlthough it will still create a standardized Package, most of the details in SCCM will be empty."
    Set-FormToPkg
})
$GroupBoxTaskOptions.Controls.Add($RadioBtnPkg)

$CheckBoxDeployment = New-Object System.Windows.Forms.CheckBox
$CheckBoxDeployment.Location = New-Object System.Drawing.Size(20,97)
$CheckBoxDeployment.AutoSize = $True
$CheckBoxDeployment.Font = New-Object System.Drawing.Font($BoxFont,$BoxFontSize)
$CheckBoxDeployment.Text = "Deployment"
$CheckBoxDeployment.add_Click({})
$GroupBoxTaskOptions.Controls.Add($CheckBoxDeployment)

$GroupBoxDepType = New-Object System.Windows.Forms.GroupBox
$GroupBoxDepType.Location = New-Object System.Drawing.Size(150,80)
$GroupBoxDepType.Size = New-Object System.Drawing.Size(120,120)
$GroupBoxDepType.Text = "Deployment Type:"
$Form.Controls.Add($GroupBoxDepType)

$RadioBtnManual = New-Object System.Windows.Forms.RadioButton
$RadioBtnManual.Location = New-Object System.Drawing.Size(20,15)
$RadioBtnManual.AutoSize = $True
$RadioBtnManual.Text = "Manual"
$RadioBtnManual.add_Click({Set-FormToNone})
$GroupBoxDepType.Controls.Add($RadioBtnManual)

$RadioBtnMSI = New-Object System.Windows.Forms.RadioButton
$RadioBtnMSI.Location = New-Object System.Drawing.Size(20,35)
$RadioBtnMSI.AutoSize = $True
$RadioBtnMSI.Text = "MSI Installer"
$RadioBtnMSI.add_Click({Set-FormToMSI})
$GroupBoxDepType.Controls.Add($RadioBtnMSI)

$CheckBoxTransform = New-Object System.Windows.Forms.CheckBox
$CheckBoxTransform.Location = New-Object System.Drawing.Size(20,55)
$CheckBoxTransform.AutoSize = $True
$CheckBoxTransform.Text = "Transform"
$CheckBoxTransform.add_Click({
    if($CheckBoxTransform.Checked){
        $TextBoxTransform.Enabled = $true
        $TextBoxTransform.Text = $TextBoxAppName.Text + ".mst"
        $BrowseButtonMST.Enabled = $true
        if($CheckBoxx64.Checked){
            $TextBoxTransformx64.Enabled = $true
            $TextBoxTransform.Text = "x86\" + $TextBoxAppName.Text + ".mst"
            $TextBoxTransformx64.Text = "x64\" + $TextBoxAppName.Text + ".mst"
            $BrowseButtonMSTx64.Enabled = $true
        }
	}else{
		$TextBoxTransform.Enabled = $false
        $TextBoxTransform.Text = ""
        $BrowseButtonMST.Enabled = $false
        if($CheckBoxx64.Checked){
            $TextBoxTransformx64.Enabled = $false
            $TextBoxTransformx64.Text = ""
            $BrowseButtonMSTx64.Enabled = $false
        }
	}
})
$GroupBoxDepType.Controls.Add($CheckBoxTransform)

$RadioBtnAppV = New-Object System.Windows.Forms.RadioButton
$RadioBtnAppV.Location = New-Object System.Drawing.Size(20,75)
$RadioBtnAppV.AutoSize = $True
$RadioBtnAppV.Text = "App-V 5"
$RadioBtnAppV.add_Click({Set-FormToAppV})
$GroupBoxDepType.Controls.Add($RadioBtnAppV)

$RadioBtnScript = New-Object System.Windows.Forms.RadioButton
$RadioBtnScript.Location = New-Object System.Drawing.Size(20,95)
$RadioBtnScript.AutoSize = $True
$RadioBtnScript.Text = "Script"
$RadioBtnScript.add_Click({Set-FormToScript})
$GroupBoxDepType.Controls.Add($RadioBtnScript)

$OutputBox = New-Object System.Windows.Forms.RichTextBox 
$OutputBox.Location = New-Object System.Drawing.Size(290,30) 
$OutputBox.Size = New-Object System.Drawing.Size(410,170)
$OutputBox.Font = New-Object System.Drawing.Font("Lucida Console",8.25)
$OutputBox.Multiline = $true
$OutputBox.ReadOnly = $true
$OutputBox.ScrollBars = "Vertical"
$OutputBox.Text = ""
$Form.Controls.Add($OutputBox)

$ClearButton = New-Object System.Windows.Forms.Button
$ClearButton.Location = New-Object System.Drawing.Size(625,203)
$ClearButton.AutoSize = $True
$ClearButton.Text = "Clear Log"
$ClearButton.Add_Click({$OutputBox.Text = "`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n"})
$Form.Controls.Add($ClearButton)

$LabelSource = New-Object System.Windows.Forms.Label
$LabelSource.Location = New-Object System.Drawing.Size(10,210) 
$LabelSource.AutoSize = $True
$LabelSource.Text = "Source:"
$Form.Controls.Add($LabelSource)

$LabelSourcePath = New-Object System.Windows.Forms.Label
$LabelSourcePath.Location = New-Object System.Drawing.Size(10,230) 
$LabelSourcePath.AutoSize = $True
$Form.Controls.Add($LabelSourcePath)

$TextBoxInstFile = New-Object System.Windows.Forms.TextBox 
$TextBoxInstFile.Location = New-Object System.Drawing.Size(10,250) 
$TextBoxInstFile.Size = New-Object System.Drawing.Size(260,20)
$Form.Controls.Add($TextBoxInstFile)

$BrowseBtnInstFile = New-Object System.Windows.Forms.Button
$BrowseBtnInstFile.Location = New-Object System.Drawing.Size(275,248)
$BrowseBtnInstFile.AutoSize = $True
$BrowseBtnInstFile.Text = "Browse"
$BrowseBtnInstFile.Add_Click({
    $InstallFile = $null
    if($RadioBtnMSI.Checked){
        $InstallFile = Get-FileName "*.msi" "Windows Installer Package"
    }elseif($RadioBtnAppV.Checked){
        $InstallFile = Get-FileName "*.appv" "Microsoft Application Virtualization 5.x package"
    }elseif($RadioBtnScript.Checked){
        $InstallFile = Get-FileName "*.exe" "Executable File"
    }
    Pop-FileName $InstallFile $TextBoxInstFile
})
$Form.Controls.Add($BrowseBtnInstFile)

$TextBoxTransform = New-Object System.Windows.Forms.TextBox 
$TextBoxTransform.Location = New-Object System.Drawing.Size(10,275) 
$TextBoxTransform.Size = New-Object System.Drawing.Size(260,20)
$Form.Controls.Add($TextBoxTransform)

$BrowseButtonMST = New-Object System.Windows.Forms.Button
$BrowseButtonMST.Location = New-Object System.Drawing.Size(275,273)
$BrowseButtonMST.AutoSize = $True
$BrowseButtonMST.Text = "Browse"
$BrowseButtonMST.Add_Click({
    $InstallFile = $null
    if($RadioBtnMSI.Checked){
        $InstallFile = Get-FileName "*.mst" "MST File"
    }elseif($RadioBtnScript.Checked){
        $InstallFile = Get-FileName "*.exe" "Executable File"
    }
    Pop-FileName $InstallFile $TextBoxTransform
})
$Form.Controls.Add($BrowseButtonMST)

$CheckBoxx64 = New-Object System.Windows.Forms.CheckBox
$CheckBoxx64.Location = New-Object System.Drawing.Size(10,300)
$CheckBoxx64.AutoSize = $True
$CheckBoxx64.Text = "Create 2nd Deployment Type for x64"
$CheckBoxx64.add_Click({
    if($CheckBoxx64.Checked){
        $TextBoxMSIx64.Enabled = $true
        $TextBoxInstFile.Text = "x86\" + $TextBoxAppName.Text + ".msi"
        $TextBoxMSIx64.Text = "x64\" + $TextBoxAppName.Text + ".msi"
        $BrowseButtonMSIx64.Enabled = $true
        if($CheckBoxTransform.Checked){
            $TextBoxTransformx64.Enabled = $true
            $TextBoxTransform.Text = "x86\" + $TextBoxAppName.Text + ".mst"
            $TextBoxTransformx64.Text = "x64\" + $TextBoxAppName.Text + ".mst"
            $BrowseButtonMSTx64.Enabled = $true
        }
	}else{
		$TextBoxMSIx64.Enabled = $false
        $TextBoxMSIx64.Text = ""
        $BrowseButtonMSIx64.Enabled = $false
        $TextBoxInstFile.Text = $TextBoxAppName.Text + ".msi"
        $TextBoxTransformx64.Enabled = $false
        $TextBoxTransformx64.Text = ""
        $BrowseButtonMSTx64.Enabled = $false
        if($CheckBoxTransform.Checked){
            $TextBoxTransform.Text = $TextBoxAppName.Text + ".mst"
        }
	}
})
$Form.Controls.Add($CheckBoxx64)

$TextBoxMSIx64 = New-Object System.Windows.Forms.TextBox 
$TextBoxMSIx64.Location = New-Object System.Drawing.Size(10,320) 
$TextBoxMSIx64.Size = New-Object System.Drawing.Size(260,20)
$Form.Controls.Add($TextBoxMSIx64)

$BrowseButtonMSIx64 = New-Object System.Windows.Forms.Button
$BrowseButtonMSIx64.Location = New-Object System.Drawing.Size(275,318)
$BrowseButtonMSIx64.AutoSize = $True
$BrowseButtonMSIx64.Text = "Browse"
$BrowseButtonMSIx64.Add_Click({Pop-FileName (Get-FileName "*.msi" "Windows Installer Package") $TextBoxMSIx64})
$Form.Controls.Add($BrowseButtonMSIx64)

$TextBoxTransformx64 = New-Object System.Windows.Forms.TextBox 
$TextBoxTransformx64.Location = New-Object System.Drawing.Size(10,345) 
$TextBoxTransformx64.Size = New-Object System.Drawing.Size(260,20)
$Form.Controls.Add($TextBoxTransformx64)

$BrowseButtonMSTx64 = New-Object System.Windows.Forms.Button
$BrowseButtonMSTx64.Location = New-Object System.Drawing.Size(275,343)
$BrowseButtonMSTx64.AutoSize = $True
$BrowseButtonMSTx64.Text = "Browse"
$BrowseButtonMSTx64.Add_Click({Pop-FileName (Get-FileName "*.mst" "MST File") $TextBoxTransformx64})
$Form.Controls.Add($BrowseButtonMSTx64)

$GroupBoxDetection = New-Object System.Windows.Forms.GroupBox
$GroupBoxDetection.Location = New-Object System.Drawing.Size(360,250)
$GroupBoxDetection.Size = New-Object System.Drawing.Size(340,100)
$GroupBoxDetection.Text = "Detection Method (Windows Installer):"
$Form.Controls.Add($GroupBoxDetection)

$LabelProdCode = New-Object System.Windows.Forms.Label
$LabelProdCode.Location = New-Object System.Drawing.Size(10,20) 
$LabelProdCode.AutoSize = $True 
$LabelProdCode.Text = "Product Code:"
$GroupBoxDetection.Controls.Add($LabelProdCode)

$TextBoxProdCode = New-Object System.Windows.Forms.TextBox 
$TextBoxProdCode.Location = New-Object System.Drawing.Size(10,40) 
$TextBoxProdCode.Size = New-Object System.Drawing.Size(240,20)
$GroupBoxDetection.Controls.Add($TextBoxProdCode)

$BrowseBtnDetectMSI = New-Object System.Windows.Forms.Button
$BrowseBtnDetectMSI.Location = New-Object System.Drawing.Size(255,38)
$BrowseBtnDetectMSI.AutoSize = $True
$BrowseBtnDetectMSI.Text = "Browse"
$BrowseBtnDetectMSI.Add_Click({
    $MSIProps = Get-MSIProps (Get-FileName "*.msi" "Windows Installer Package")
    $TextBoxProdCode.Text = $MSIProps.ProductCode
    $TextBoxProdVersion.Text = $MSIProps.ProductVersion
})
$GroupBoxDetection.Controls.Add($BrowseBtnDetectMSI)

$ComboBoxComparator = New-Object System.Windows.Forms.ComboBox
$ComboBoxComparator.Location = New-Object System.Drawing.Point(25,70)
$ComboBoxComparator.Size = New-Object System.Drawing.Size(100, 20)
@("IsEquals","NotEquals","GreaterEquals","GreaterThan","LessEquals","LessThan") | %{$ComboBoxComparator.Items.add("$_") | Out-Null}
$ComboBoxComparator.SelectedIndex = 2
$GroupBoxDetection.Controls.Add($ComboBoxComparator)

$TextBoxProdVersion = New-Object System.Windows.Forms.TextBox 
$TextBoxProdVersion.Location = New-Object System.Drawing.Size(130,70) 
$TextBoxProdVersion.Size = New-Object System.Drawing.Size(80,20)
$GroupBoxDetection.Controls.Add($TextBoxProdVersion)

$LabelNotImp = New-Object System.Windows.Forms.Label
$LabelNotImp.Location = New-Object System.Drawing.Size(215,72) 
$LabelNotImp.AutoSize = $True
$LabelNotImp.Forecolor = 'Orange'
$GroupBoxDetection.Controls.Add($LabelNotImp)

$ListViewAdmCategory = New-Object System.Windows.Forms.ListView
$ListViewAdmCategory.Location = New-Object System.Drawing.Point(10,385)
$ListViewAdmCategory.Size = New-Object System.Drawing.Size(165,100)
$ListViewAdmCategory.View = 'Details'
$ListViewAdmCategory.CheckBoxes = $true
$LVcolAdmCategory = $ListViewAdmCategory.Columns.add('SCCM Admin Categories')
$LVcolAdmCategory.Width = 144
$Form.Controls.Add($ListViewAdmCategory)

$NewAdmCatButton = New-Object System.Windows.Forms.Button
$NewAdmCatButton.Location = New-Object System.Drawing.Size(10,490)
$NewAdmCatButton.AutoSize = $True
$NewAdmCatButton.Text = "New"
$NewAdmCatButton.Add_Click({
    $NewCategory = New-Cat "AppCategories"
    if($NewCategory -ne "" -and $NewCategory -ne $null){
        $LI = New-Object system.Windows.Forms.ListViewItem
        $LI.Name = $NewCategory
		$LI.Text = $NewCategory
        $ListViewAdmCategory.Items.add($LI) | Out-Null
    }
})
$Form.Controls.Add($NewAdmCatButton)

$GroupBoxAppCatalog = New-Object System.Windows.Forms.GroupBox
$GroupBoxAppCatalog.Location = New-Object System.Drawing.Size(190,375)
$GroupBoxAppCatalog.Size = New-Object System.Drawing.Size(510,170)
$GroupBoxAppCatalog.Text = "Application Catalog:"
$Form.Controls.Add($GroupBoxAppCatalog)

$LabelDesc = New-Object System.Windows.Forms.Label
$LabelDesc.Location = New-Object System.Drawing.Size(10,20) 
$LabelDesc.AutoSize = $True
$LabelDesc.Text = "Description:"
$GroupBoxAppCatalog.Controls.Add($LabelDesc)

$TextBoxDesc = New-Object System.Windows.Forms.RichTextBox 
$TextBoxDesc.Location = New-Object System.Drawing.Size(10,40) 
$TextBoxDesc.Size = New-Object System.Drawing.Size(490,40)
$TextBoxDesc.Multiline = $true
$TextBoxDesc.ScrollBars = "Vertical"
$GroupBoxAppCatalog.Controls.Add($TextBoxDesc)

$LabelCategory = New-Object System.Windows.Forms.Label
$LabelCategory.Location = New-Object System.Drawing.Size(10,90) 
$LabelCategory.AutoSize = $True 
$LabelCategory.Text = "Category:"
$GroupBoxAppCatalog.Controls.Add($LabelCategory)

$ComboBoxCategory = New-Object System.Windows.Forms.ComboBox
$ComboBoxCategory.Location = New-Object System.Drawing.Point(80,88)
$ComboBoxCategory.Size = New-Object System.Drawing.Size(180, 20)
$GroupBoxAppCatalog.Controls.Add($ComboBoxCategory)

$NewCatButton = New-Object System.Windows.Forms.Button
$NewCatButton.Location = New-Object System.Drawing.Size(265,86)
$NewCatButton.AutoSize = $True
$NewCatButton.Text = "New"
$NewCatButton.Add_Click({
    $NewCategory = New-Cat "CatalogCategories"
    if($NewCategory -ne "" -and $NewCategory -ne $null){
        $ComboBoxCategory.Items.add("$NewCategory") | Out-Null
    }
})
$GroupBoxAppCatalog.Controls.Add($NewCatButton)

$LabelKeywords = New-Object System.Windows.Forms.Label
$LabelKeywords.Location = New-Object System.Drawing.Size(10,115) 
$LabelKeywords.AutoSize = $True 
$LabelKeywords.Text = "Keywords:"
$GroupBoxAppCatalog.Controls.Add($LabelKeywords)

$TextBoxKeywords = New-Object System.Windows.Forms.TextBox 
$TextBoxKeywords.Location = New-Object System.Drawing.Size(80,113) 
$TextBoxKeywords.Size = New-Object System.Drawing.Size(260,20)
$GroupBoxAppCatalog.Controls.Add($TextBoxKeywords)

$LabelIcon = New-Object System.Windows.Forms.Label
$LabelIcon.Location = New-Object System.Drawing.Size(10,140) 
$LabelIcon.AutoSize = $True 
$LabelIcon.Text = "Icon File:"
$GroupBoxAppCatalog.Controls.Add($LabelIcon)

$TextBoxIcon = New-Object System.Windows.Forms.TextBox 
$TextBoxIcon.Location = New-Object System.Drawing.Size(80,138) 
$TextBoxIcon.Size = New-Object System.Drawing.Size(340,20)
$GroupBoxAppCatalog.Controls.Add($TextBoxIcon)

$BrowseButtonIcon = New-Object System.Windows.Forms.Button
$BrowseButtonIcon.Location = New-Object System.Drawing.Size(425,136)
$BrowseButtonIcon.AutoSize = $True
$BrowseButtonIcon.Text = "Browse"
$BrowseButtonIcon.Add_Click({
    $IconFile = Get-FileName "*.exe;*.jpeg;*.jpg;*.ico;*.png" "Image and Icon Files"
    if($IconFile -ne $null){
        $TextBoxIcon.Text = $IconFile
        if($IconFile.ToLower().EndsWith(".exe")){
            $IconEXE = Get-Item $IconFile
            if($IconFile.StartsWith("\\")){#cannot extract from network path, so copy to local TEMP
                Copy-Item $IconFile -Destination $env:TEMP -Force
                $IconEXE = Get-Item ($env:TEMP+"\"+$IconEXE.Name)
            }
            $NewIcon = $env:TEMP + "\" + $IconEXE.BaseName + ".png"
            [System.Drawing.Icon]::ExtractAssociatedIcon($IconEXE.FullName).ToBitmap().Save($NewIcon)
            DM "Icon extracted."
            $TextBoxIcon.Text = $NewIcon
            $PictureBoxIcon.Image = [System.Drawing.Image]::FromFile($NewIcon)
            if($IconFile.StartsWith("\\") -and (Test-Path ($env:TEMP+"\"+$IconEXE.Name))){
                Remove-Item ($env:TEMP+"\"+$IconEXE.Name) | Out-Null
            }
        }elseif($IconFile.ToLower().EndsWith(".ico")){
            $PictureBoxIcon.Image = New-Object System.Drawing.Icon($IconFile)
        }else{
            $PictureBoxIcon.Image = [System.Drawing.Image]::FromFile($IconFile)
        }
    }
})
$GroupBoxAppCatalog.Controls.Add($BrowseButtonIcon)

$PictureBoxIcon = New-Object Windows.Forms.PictureBox
$PictureBoxIcon.Location = New-Object System.Drawing.Size(415,90)
$PictureBoxIcon.Size = New-Object System.Drawing.Size(30,30)
$PictureBoxIcon.SizeMode = "StretchImage"
$GroupBoxAppCatalog.Controls.Add($PictureBoxIcon)

$CheckBoxAddPCs = New-Object System.Windows.Forms.CheckBox
$CheckBoxAddPCs.Location = New-Object System.Drawing.Size(10,560)
$CheckBoxAddPCs.AutoSize = $True
$CheckBoxAddPCs.Text = "Add machine(s) to deployment group:"
$CheckBoxAddPCs.add_Click({
    if($CheckBoxAddPCs.Checked){
        $TextBoxAddPCs.Enabled = $true
        $TextBoxAddPCs.Text = $TestMachines.($env:USERNAME)
	}else{
        $TextBoxAddPCs.Text = ""
        $TextBoxAddPCs.Enabled = $false
    }
})
$Form.Controls.Add($CheckBoxAddPCs)

$TextBoxAddPCs = New-Object System.Windows.Forms.TextBox 
$TextBoxAddPCs.Location = New-Object System.Drawing.Size(230,559) 
$TextBoxAddPCs.Size = New-Object System.Drawing.Size(330,20)
$Form.Controls.Add($TextBoxAddPCs)

$ProgressBar = New-Object System.Windows.Forms.ProgressBar
$ProgressBar.Location = New-Object System.Drawing.Size(10,590)
$ProgressBar.Size = New-Object System.Drawing.Size(690,20)
$ProgressBar.Minimum = 0
$ProgressBar.Maximum = 100
$Form.Controls.Add($ProgressBar)

$RunButton = New-Object System.Windows.Forms.Button
$RunButton.Location = New-Object System.Drawing.Size(210,620)
$RunButton.Size = New-Object System.Drawing.Size(130,23)
$RunButton.Text = "Create"
$RunButton.Add_Click({
	Set-Vars
    if(Check-Input){
        $RunButton.Enabled = $false
        $ResetButton.Enabled = $false
        $QuitButton.Enabled = $false
        $StatusStripLabel.Text = "Running as $env:USERNAME"
        $StatusStrip.Update()
        Main
    }
})
$Form.Controls.Add($RunButton)

$ResetButton = New-Object System.Windows.Forms.Button
$ResetButton.Location = New-Object System.Drawing.Size(350,620)
$ResetButton.Size = New-Object System.Drawing.Size(80,23)
$ResetButton.Text = "Reset Form"
$ResetButton.Add_Click({Reset-Form})
$Form.Controls.Add($ResetButton)

$QuitButton = New-Object System.Windows.Forms.Button
$QuitButton.Location = New-Object System.Drawing.Size(440,620)
$QuitButton.Size = New-Object System.Drawing.Size(75,23)
$QuitButton.Text = "Quit"
$QuitButton.Add_Click({$Form.Close()})
$Form.Controls.Add($QuitButton)

$StatusStrip = New-Object System.Windows.Forms.StatusStrip
$StatusStrip.BackColor = [System.Drawing.Color]::LightSteelBlue
$StatusStripLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$StatusStripLabel.Text = "Ready"
[void]$StatusStrip.Items.add($StatusStripLabel)
$Form.Controls.Add($StatusStrip)

if(Import-Settings){Reset-Form}else{Return}
$Form.Add_Shown({$Form.Activate()})
[void] $Form.ShowDialog()
}
#endregion########################################################################################

### All starts here
if((Check-Prereqs) -eq $false){Return}
#launch GUI
MainForm
