﻿param([switch]$Dbug,[switch]$Chk4m)

### Global Variables ###

#if this is running from a mapped drive, replace the drive letter with the true root
$ScriptPath = $PSScriptRoot
if(-not($ScriptPath.StartsWith("\\"))){
    $MappedRoot = (Get-PSDrive ($PSScriptRoot.Split(":")[0])).DisplayRoot
    if($MappedRoot -ne $null){$ScriptPath = Join-Path $MappedRoot $PSScriptRoot.Split(":")[1]}
}

$PkgNameFormat = "Manufacturer_Product_Version"
$scriptName = "MCM AddApp Tool"
$scriptVersion = "2.15.3"

### About
$about = "****************************************************************`n"
$about += "  ScriptName:   $scriptName`n"
$about += "  ScriptPath:   $PSCommandPath`n"
$about += "  ScriptVersion:  $scriptVersion`n"
$about += "  ScriptAuthor:   Joel Chettle`n"
$about += "  Description:    Creates groups in Active Directory and applications in ConfigMgr, including the collections and deployments if capable, per configurations defined in settings.`n"
$about += "****************************************************************`n"
$about += "  Notes:    This tool is meant to automate common conditions. More features may be added over time. But by no means is it fully inclusive to all scenarios.`n"
$about += "****************************************************************`n"
if(Test-Path "$ScriptPath\LICENSE.txt"){$about += (Get-Content "$ScriptPath\LICENSE.txt") -join "`n"}

Function Main{
### This function performs the steps to create the Application in AD and MCM when user clicks "Create" button on the GUI ###
    ### Set Variables
    ## From GUI
	$PackageName = $TextBoxAppName.Text
    $isManual = $RadioBtnManual.Checked
    $isMSI = $RadioBtnMSI.Checked
    $isAppX = $RadioBtnAppX.Checked
    $isScript = $RadioBtnScript.Checked
    $SourcePath = $LabelSourcePath.Text
    $InstFileName = $TextBoxInstFile.Text
    $isTransform = $CheckBoxTransform.Checked
    $MSTName = $TextBoxTransform.Text
    $DetectionMeth = $ComboBoxDetection.SelectedItem
    $ProdCode = $TextBoxProdCode.Text
    $DetectExist = $RadioBtnDetectExist.Checked
    $DetectComp = $ComboBoxComparator.SelectedItem
    $ProdVersion = $TextBoxProdVersion.Text
    $Detect32on64 = $CheckBoxDetect32on64.Checked
    $TwoClauses = $CheckBox2ndDetect.Checked
    $2ndDetectionMeth = $ComboBox2ndDetection.SelectedItem
    $2ndProdCode = $TextBox2ndProdCode.Text
    $2ndDetectExist = $RadioBtn2ndDetectExist.Checked
    $2ndDetectComp = $ComboBox2ndComparator.SelectedItem
    $2ndProdVersion = $TextBox2ndProdVersion.Text
    $2ndDetect32on64 = $CheckBox2ndDetect32on64.Checked
    $AppAdmCat = ($ListViewAdmCategory.CheckedItems |ForEach-Object {$_.name})
    $AppDesc = $TextBoxDesc.Text
    $LocalizedAppName = $TextBoxLocalAppName.Text
    $AppIcon = $TextBoxIcon.Text
    $DoStepAD = $CheckBoxADGroup.Checked
    $DoStepCollection = $CheckBoxCollection.Checked
    $DoStepDeployment = $CheckBoxDeployment.Checked
    $UInteraction = $CheckBoxInteraction.Checked
    $RebootBehavior = $ComboboxRebootB.SelectedItem
    $ReqDiskSpace = $CheckBoxDiskSpace.Checked
    $DiskSpaceMB = $TextBoxDiskSpace.Text
    $AddPCs = $CheckBoxAddPCs.Checked
    $PCNames = $TextBoxAddPCs.Text
    if(-not(Check-Input)){return}
    ## Refined
    $Date = (Get-Date).ToShortDateString()
    switch($Comments){
		'Date'{$Comment = $Date}
		'UserID'{$Comment = $env:USERNAME}
        'Date+UserID'{$Comment = $Date + " - " + $env:USERNAME}
		default{$Comment = ""}
	}
    $FriendlyName =  $PackageName.Replace($PkgDelimiter," ")
    if($CreateUninstall){$actions = "Install","Uninstall"}
    else{$actions = "Install"}
    $Manufacturer = $PackageName.Split($PkgDelimiter)[0]
    $Version = $PackageName.Substring($PackageName.IndexOf($PkgDelimiter)+1)
    $Version = $Version.Substring($Version.IndexOf($PkgDelimiter)+1)
    #adjust total of the progress bar depending on steps required
    $TotalSteps = 3 #at minimum, tool creates/moves App + cleans history
    if($DoStepAD){ #create AD group(s)
        $TotalSteps = $TotalSteps + 1
        if($CreateUninstall){$TotalSteps = $TotalSteps + 1}
        if($AddPCs){$TotalSteps = $TotalSteps + 1} #adding machines to AD group
    }
    if($DoStepCollection){ #create/move collection(s)
        $TotalSteps = $TotalSteps + 2
        if($CreateUninstall){$TotalSteps = $TotalSteps + 2}
    }
    if(-not($isManual)){$TotalSteps = $TotalSteps + 2} #creating deployment type + distribute content
    if($ReqDiskSpace){$TotalSteps = $TotalSteps + 1} #adding requirement to deptype
    if($DoStepDeployment){ #create deployment(s)
        $TotalSteps = $TotalSteps + 1
        if($CreateUninstall){$TotalSteps = $TotalSteps + 1}
    }
    $CurrentStep = 0

    #Begin...
    $RunButton.Enabled = $false
    $ResetButton.Enabled = $false
    $QuitButton.Enabled = $false
    $StatusStripLabel.Text = "Running"
    $StatusStrip.Update()

    DM "======================================================"
    DM " $FriendlyName"
    DM (" " + (Get-Date))
    DM "======================================================"

    $eap = $ErrorActionPreference
    $ErrorActionPreference = "SilentyContinue"
#region################ Active Directory block ###################################################
    if($DoStepAD){
        foreach($action in $actions){
            $GroupName = "$PackageName-$action"
            DM "Creating $action AD group..." -NNL
            #check if already exists.  YesNo box to continue.
            $Skip = $null
            $test = Get-ADGroup -LDAPFilter "(name=$GroupName)" -SearchBase "$ADPath" -ErrorAction SilentlyContinue
            if($test -ne $null){
                $Skip = SkipPrompt "Active Directory group" $GroupName
                if($Skip -eq $false){Return}
            }
            #create
            if(-not($Skip)){
                $Error.Clear()
                New-ADGroup $GroupName -Path $ADPath -GroupScope $ADGroupScope -Description "$action App: $FriendlyName"
                if((ErrorChecker) -eq $false){Return}
                #validate
                if((Validate "Get-ADGroup -LDAPFilter `"(name=$GroupName)`" -SearchBase `"$ADPath`"") -eq $false){if((ErrorChecker "Failed to create Active Directory group.") -eq $false){Return}}
            }
            $CurrentStep++
            $ProgressBar.Value = $CurrentStep/$TotalSteps * 100

            #add machines
            if($AddPCs -and $action -eq "Install"){
                DM "Adding machines to AD group..."
                $PCNames = $PCNames.Replace(" ","").Replace(",",";").Replace("`n",";")
                foreach($targetPC in ($PCNames.Split(";"))){
                    if($targetPC.contains("\")){
                        $targPCDomain = (Get-ADDomain ($targetPC.split("\")[0])).DNSRoot
                        $targetPC = $targetPC.split("\")[1]
                    }else{
                        $targPCDomain = (Get-ADDomain $ADDomain).DNSRoot
                    }
                    $ADtarget = $null
                    $ADtarget = Get-ADComputer $targetPC -Server $targPCDomain -ErrorAction SilentlyContinue
                    if($ADtarget -eq $null){
                        DM "$targetPC not found in AD. Skipping." "Orange"
	                }else{
                        $Error.Clear()
                        Add-ADGroupMember (Get-ADGroup -LDAPFilter "(name=$GroupName)" -SearchBase "$ADPath") $ADtarget
                        if($Error[0] -ne $null){
                            DM "Error adding $targetPC to AD group. Continuing..." "Red"
                        }
                    }
                }
                $CurrentStep++
                $ProgressBar.Value = $CurrentStep/$TotalSteps * 100
            }
        }
    }
#endregion########################################################################################
#region################ MCM Collection block ####################################################
    Set-Location $Sitecode
    if($DoStepCollection){
        $CollectionFolder = ".\$CollectionFolder"
        if(-not(Test-Path $CollectionFolder)){
            DM "Creating Collection folder..."
            New-Item $CollectionFolder -ItemType directory
            $timeout = 0
            do{Start-Sleep -Seconds 1;$timeout++}while(-not(Test-Path $CollectionFolder) -and $timeout -lt 20)
        }
        foreach($action in $actions){
            $GroupName = "$PackageName-$action"
            DM "Creating $action Collection..." -NNL
            #check if already exists.  YesNo box to continue.
            $Skip = $null
            $test = Get-CMDeviceCollection -Name $GroupName
            if($test -ne $null){
                $Skip = SkipPrompt "Device Collection" $GroupName
                if($Skip -eq $false){Return}
            }
            #create
            if(-not($Skip)){
                $Error.Clear()
                if($RefreshInterval -ne "Manual"){
                    if($RefreshInterval -eq "Days"){$StartTime = [DateTime]"$Date 12:00 AM"}
                    else{$StartTime = Get-Date}
                    $Schedule = New-CMSchedule -RecurCount $RefreshIntCount -RecurInterval $RefreshInterval -Start $StartTime
                    $Collection = New-CMDeviceCollection -Name $GroupName -LimitingCollectionName $LimitingCollection -Comment $Comment -RefreshSchedule $Schedule
                }else{
                    $Collection = New-CMDeviceCollection -Name $GroupName -LimitingCollectionName $LimitingCollection -Comment $Comment -RefreshType $RefreshInterval
                }
                if((ErrorChecker) -eq $false){Return}
                if($DoStepAD){
                    Add-CMDeviceCollectionQueryMembershipRule -Collection $Collection -QueryExpression "select * from SMS_R_System where SMS_R_System.SecurityGroupName = '$ADDomain\\$GroupName'" -RuleName $PackageName
                }
                #validate
                if((Validate "Get-CMDeviceCollection -Name $GroupName") -eq $false){if((ErrorChecker "Failed to create Device Collection.") -eq $false){Return}}
                $CurrentStep++
                $ProgressBar.Value = $CurrentStep/$TotalSteps * 100
                
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
        }
    }
#endregion########################################################################################
#region################ MCM Application block ###################################################
    $ApplicationPath = ".\Application\$ApplicationFolder"
    DM "Creating Application..." -NNL
    
    #check if already exists.  YesNo box to continue.
    $Skip = $null
    $test = Get-CMApplication -Name $PackageName
    if($test -ne $null){
        $Skip = SkipPrompt "Application" $PackageName
        if($Skip -eq $false){Return}
    }

    #create
    if(-not($Skip)){
        $Error.Clear()
        $Application = New-CMApplication -Name $PackageName -Description $Comment -ReleaseDate $Date -AutoInstall $AllowTaskSeqInstall -LocalizedApplicationName $LocalizedAppName -Publisher $Manufacturer -SoftwareVersion $Version
        Set-CMApplication -Name $PackageName -DistributionPointSetting $PrestageDP
        if($AppAdmCat -ne "" -and $AppAdmCat -ne $null){
            if($AppAdmCat -is [array]){
                $AppAdmCatObj = Get-CMCategory -CategoryType AppCategories | ?{$AppAdmCat.contains($_.LocalizedCategoryInstanceName)}
            }else{
                $AppAdmCatObj = Get-CMCategory -CategoryType AppCategories -Name $AppAdmCat
            }
            Set-CMApplication -Name $PackageName -AddAppCategory $AppAdmCatObj
        }
        if($AppDesc -ne "" -and $AppDesc -ne $null){
            Set-CMApplication -Name $PackageName -LocalizedApplicationDescription $AppDesc
        }
        if($AppIcon -ne "" -and $AppIcon -ne $null){
            Set-CMApplication -Name $PackageName -IconLocationFile $AppIcon
        }
        if((ErrorChecker) -eq $false){Return}
        #validate
        if((Validate "Get-CMApplication -Name $PackageName") -eq $false){if((ErrorChecker "Failed to create Application.") -eq $false){Return}}
        $CurrentStep++
        $ProgressBar.Value = $CurrentStep/$TotalSteps * 100

        if(-not(Test-Path $ApplicationPath)){
            DM "Creating folder..."
            New-Item $ApplicationPath -ItemType directory
            $timeout = 0
            do{Start-Sleep -Seconds 1;$timeout++}while(-not(Test-Path $ApplicationPath) -and $timeout -lt 20)
        }
        DM "Moving Application..."
        $Error.Clear()
        Move-CMObject -InputObject $Application -FolderPath $ApplicationPath
        if((ErrorChecker) -eq $false){DM "Failed to move Application. Look for it in root folder." "Orange"}
        $CurrentStep++
        $ProgressBar.Value = $CurrentStep/$TotalSteps * 100
    }else{
        $CurrentStep = $CurrentStep + 2
        $ProgressBar.Value = $CurrentStep/$TotalSteps * 100
    }
#endregion########################################################################################
#region################ MCM Deployment Type block ###############################################
    if(-not($isManual)){
        DM "Creating Deployment Type..." -NNL
        #check if already exists.  YesNo box to continue.
        $Skip = $null
        $test = Get-CMDeploymentType -ApplicationName $PackageName -DeploymentTypeName $PackageName
        if($test -ne $null){
            $Skip = SkipPrompt "Deployment Type" $PackageName
            if($Skip -eq $false){Return}
        }
        #create
        if(-not($Skip)){
            $InstFullPath = Join-Path $SourcePath $InstFileName
            if($isMSI){
                $Log = "/{0} {1}\{2}_MSI_Install.log" -f $LogOption,$LogPath,$PackageName
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
                $Error.Clear()
                if($UInteraction){Add-CMMSiDeploymentType -ApplicationName $PackageName -DeploymentTypeName $PackageName -ContentLocation $InstFullPath -Force -Comment $Comment -InstallCommand $InstCMD -UninstallCommand $UninstallCMD -MaximumRuntimeMins $maxDeployTime -SourceUpdateProductCode $ProdID -InstallationBehaviorType $InstallBehavior -RebootBehavior $RebootBehavior -RequireUserInteraction}
                else{Add-CMMSiDeploymentType -ApplicationName $PackageName -DeploymentTypeName $PackageName -ContentLocation $InstFullPath -Force -Comment $Comment -InstallCommand $InstCMD -UninstallCommand $UninstallCMD -MaximumRuntimeMins $maxDeployTime -SourceUpdateProductCode $ProdID -InstallationBehaviorType $InstallBehavior -RebootBehavior $RebootBehavior}
            }elseif($isAppX){
                $Error.Clear()
                Add-CMWindowsAppxDeploymentType -ApplicationName $PackageName -DeploymentTypeName $PackageName -ContentLocation $InstFullPath -Force -Comment $Comment
            }elseif($isScript){
                #build a Detection Clause
                $1stDetectClause = Build-DetectionClause $DetectionMeth $ProdCode $DetectExist $DetectComp $ProdVersion $Detect32on64
                if($TwoClauses){
                    $2ndDetectClause = Build-DetectionClause $2ndDetectionMeth $2ndProdCode $2ndDetectExist $2ndDetectComp $2ndProdVersion $2ndDetect32on64
                    $DetectClause = $1stDetectClause,$2ndDetectClause
                }else{$DetectClause = $1stDetectClause}

                $Error.Clear()
                if($UInteraction){Add-CMScriptDeploymentType -ApplicationName $PackageName -DeploymentTypeName $PackageName -ContentLocation $SourcePath -Force -Comment $Comment -InstallCommand $InstFileName -UninstallCommand $MSTName -AddDetectionClause $DetectClause -MaximumRuntimeMins $maxDeployTime -InstallationBehaviorType $InstallBehavior -RebootBehavior $RebootBehavior -RequireUserInteraction}
                else{Add-CMScriptDeploymentType -ApplicationName $PackageName -DeploymentTypeName $PackageName -ContentLocation $SourcePath -Force -Comment $Comment -InstallCommand $InstFileName -UninstallCommand $MSTName -AddDetectionClause $DetectClause -MaximumRuntimeMins $maxDeployTime -InstallationBehaviorType $InstallBehavior -RebootBehavior $RebootBehavior}
            }
            if((ErrorChecker) -eq $false){Return}
            #validate
            $timeout = 0
            do{
                Start-Sleep -Seconds 1
                $test = Get-CMDeploymentType -ApplicationName $PackageName -DeploymentTypeName $PackageName
                if($test -ne $null){
                    DM "Success" "Green"
                    $timeout = 10
                }
                $timeout++
            }while($timeout -lt 10)
            if($test -eq $null){if((ErrorChecker "Failed to create Deployment Type.") -eq $false){Return}}
            #set Requirement
            if($ReqDiskSpace){
                DM "Adding Requirement..."
                $DSRule = Get-CMGlobalCondition -Name "Disk space" | New-CMRequirementRuleFreeDiskSpaceValue -PartitionOption System -RuleOperator GreaterThan -Value1 $DiskSpaceMB
                $Error.Clear()
                if($isMSI){Set-CMMSiDeploymentType -ApplicationName $PackageName -DeploymentTypeName $PackageName -AddRequirement $DSRule}
                elseif($isAppX){Set-CMWindowsAppxDeploymentType -ApplicationName $PackageName -DeploymentTypeName $PackageName -AddRequirement $DSRule}
                elseif($isScript){Set-CMScriptDeploymentType -ApplicationName $PackageName -DeploymentTypeName $PackageName -AddRequirement $DSRule}
                if((ErrorChecker) -eq $false){Return}
                $CurrentStep++
                $ProgressBar.Value = $CurrentStep/$TotalSteps * 100
            }
        }
        $CurrentStep++
        $ProgressBar.Value = $CurrentStep/$TotalSteps * 100

        DM "Distributing Content..."
        $Error.Clear()
        Start-CMContentDistribution -ApplicationName $PackageName -DistributionPointGroupName $DPGroup
        if((ErrorChecker) -eq $false){Return}
        $CurrentStep++
        $ProgressBar.Value = $CurrentStep/$TotalSteps * 100
    }else{
        DM "Since Manual was selected you must create the Deployment." "Orange"
    }
#endregion########################################################################################
#region################ MCM Deployment block ####################################################
    if($DoStepDeployment){
        foreach($action in $actions){
            $GroupName = "$PackageName-$action"
            DM "Creating $action Deployment..."
            #for some reason it uses local time for Available and UTC for Deadline. so to get to match, have to add hour difference to Available
            $UTChourDiff = (New-TimeSpan -Start (Get-Date) -End (Get-Date).ToUniversalTime()).TotalHours
            $Error.Clear()
            if($InstallPurpose -eq "Available" -and $action -eq "Install"){
                New-CMApplicationDeployment -Name $PackageName -CollectionName $GroupName -Comment $Comment -AvailableDateTime (Get-Date).AddHours($UTChourDiff) -DeployPurpose Available -UserNotification $UserNotification
            }else{
                New-CMApplicationDeployment -Name $PackageName -CollectionName $GroupName -Comment $Comment -AvailableDateTime (Get-Date).AddHours($UTChourDiff) -DeadlineDateTime (Get-Date) -DeployAction $action -DeployPurpose Required -UserNotification $UserNotification -SendWakeUpPacket $SendWakeup
            }
            if((ErrorChecker) -eq $false){Return}
            $CurrentStep++
            $ProgressBar.Value = $CurrentStep/$TotalSteps * 100
        }
        if($PkgrTestCollection -ne "" -and $PkgrTestCollection -ne $null){
            New-CMApplicationDeployment -Name $PackageName -CollectionName $PkgrTestCollection -Comment $Comment -AvailableDateTime (Get-Date).AddHours($UTChourDiff) -DeployPurpose Available -UserNotification $UserNotification
        }
    }
#endregion########################################################################################
#region################ Application Cleanup block ################################################
    DM "Cleaning Application Revision History..."
    #remove all revisions except most current
    $Revisions = Get-CMApplicationRevisionHistory -Name $PackageName
    if($Revisions.Count -gt 1){
        for($Rev=1; $Rev -lt $Revisions.Count; $Rev++){
            Remove-CMApplicationRevisionHistory -Name $PackageName -Revision $Rev -Force
        }
    }
    $CurrentStep++
    $ProgressBar.Value = $CurrentStep/$TotalSteps * 100
#endregion########################################################################################

    Reset-Form
    DM "Completed"
    DM "======================================================"
}

Function Build-DetectionClause{
## This function builds a detection clause based on input ###
param($method,$CodeOrPath,$dExist,$dComp,$dVersion,$d32on64)
    if($method -ne "MSI"){
        $dPath = Split-Path $CodeOrPath
        $dItem = Split-Path $CodeOrPath -Leaf
    }
    switch($method){
        "MSI"{
            if($dExist){$dClause = New-CMDetectionClauseWindowsInstaller -ProductCode $CodeOrPath -Existence}
            else{$dClause = New-CMDetectionClauseWindowsInstaller -ProductCode $CodeOrPath -Value -PropertyType ProductVersion -ExpressionOperator $dComp -ExpectedValue $dVersion}
        }
        "File"{
            if($dExist){$dClauseCMD = "New-CMDetectionClauseFile -Path `"$dPath`" -FileName `"$dItem`" -Existence"}
            else{$dClauseCMD = "New-CMDetectionClauseFile -Path `"$dPath`" -FileName `"$dItem`" -Value -PropertyType Version -ExpressionOperator $dComp -ExpectedValue $dVersion"}
            if(-not($d32on64)){$dClauseCMD += " -Is64Bit"}
            $dClause = Invoke-Expression $dClauseCMD
        }
        "Registry"{
            $Hive = 'LocalMachine'
            if($dPath.StartsWith("HKLM:\") -or $dPath.StartsWith("HKEY_LOCAL_MACHINE")){
                $dPath = $dPath.Replace("HKLM:\","").Replace("HKEY_LOCAL_MACHINE","")
            }elseif($dPath.StartsWith("HKCU:\") -or $dPath.StartsWith("HKEY_CURRENT_USER")){
                $Hive = 'CurrentUser'
                $dPath = $dPath.Replace("HKCU:\","").Replace("HKEY_CURRENT_USER","")
            }elseif($dPath.StartsWith("HKEY_CLASSES_ROOT")){
                $Hive = 'ClassesRoot'
                $dPath = $dPath.Replace("HKEY_CLASSES_ROOT","")
            }elseif($dPath.StartsWith("HKEY_USERS")){
                $Hive = 'Users'
                $dPath = $dPath.Replace("HKEY_USERS","")
            }elseif($dPath.StartsWith("HKEY_CURRENT_CONFIG")){
                $Hive = 'CurrentConfig'
                $dPath = $dPath.Replace("HKEY_CURRENT_CONFIG","")
            }
            if($dExist){$dClauseCMD = "New-CMDetectionClauseRegistryKeyValue -Hive $Hive -KeyName `"$dPath`" -ValueName `"$dItem`" -PropertyType String -Existence"}
            else{$dClauseCMD = "New-CMDetectionClauseRegistryKeyValue -Hive $Hive -KeyName `"$dPath`" -ValueName `"$dItem`" -Value -PropertyType Version -ExpressionOperator $dComp -ExpectedValue $dVersion"}
            if(-not($d32on64)){$dClauseCMD += " -Is64Bit"}
            $dClause = Invoke-Expression $dClauseCMD
        }
    }
    return $dClause
}
Function Get-MSIProps{
## This function gets the Product Code and Version from a given MSI.  Some credit for this code from https://winadminnotes.wordpress.com/2010/04/05/accessing-msi-file-as-a-database/
param($MSIFileName)
    $StatusStripLabel.Text = "Loading MSI"
    $StatusStrip.Update()
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
    $StatusStripLabel.Text = "Ready"
    $StatusStrip.Update()
    Return $temp
}
Function Import-Settings{
## This function grabs the values from the settings XML entered by the user and stores them in Variables ###
    if(-not(Test-Path $SettingsXML)){Return $false}
    [xml]$Settings = Get-Content $SettingsXML
    [System.Collections.ArrayList]$AllowNulls = @("ScriptInstallCMD","ScriptUninstallCMD","TestMachines","PkgrTestCollection","RefreshIntCount")
    [System.Collections.ArrayList]$BooleanVals = @("SelectAll","CreateAD","CreateCollection","CreateDeployment","AllowTaskSeqInstall","SendWakeup","CreateUninstall")
    foreach($XMLSet in ($Settings.Settings.ChildNodes).Name){
        $Value = ($Settings.Settings.$XMLSet).Trim()
        if(($Value -eq "" -or $Value -eq $null) -and -not($AllowNulls.Contains($XMLSet))){
            ShowBox "$XMLSet is not valid. Please enter a value in settings XML.`n$SettingsXML" "Error" "Error"
            Return $false
        }elseif($Value -eq $null -and $AllowNulls.Contains($XMLSet)){
            Set-Variable -Name $XMLSet -Value "" -Scope Global
        }elseif($BooleanVals.Contains($XMLSet)){
            Set-Variable -Name $XMLSet -Value (Convert-ToBoolean $Value) -Scope Global
        }else{
            Set-Variable -Name $XMLSet -Value $Value -Scope Global
        }
    }
    if(-not($sitecode.Contains(":"))){Set-Variable -Name sitecode -Value ($sitecode + ":") -Scope Global}
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
Function Check-InArray{
## This function reduces code in Check-Input, testing value against array
param($testVar,$validArray)
    $testValue = (Get-Variable $testVar).Value
    if(-not($validArray.split(",").contains($testValue))){
        ShowBox "$testVar not valid in settings XML. Valid values are $validArray." "Error" "Error"
        Return $false
    }
    Return $true
}
Function Check-Input{
### This function validates user input ###
    #From GUI
    if($PackageName -eq "" -or $PackageName -eq $null -or $PackageName.Split($PkgDelimiter).Count -lt 3){
        ShowBox ("Package name not valid. Use format: {0}" -f $PkgNameFormat.Replace("_",$PkgDelimiter)) "Error" "Error"
        Return $false
    }
    #remove valid special characters and check the rest
    $TestPkgName = $PackageName
    @("-","_",".","(",")",$PkgDelimiter) | %{$TestPkgName = $TestPkgName.Replace($_,"")}
    if($TestPkgName -notmatch '^[0-9a-zA-Z]+$'){
        $badChar = [System.Text.RegularExpressions.Regex]::Replace($TestPkgName,"[0-9a-zA-Z]","")
        ShowBox "Package name contains a space or non-alphanumeric character: $badChar" "Error" "Error"
        Return $false
    }
    $maxlength=64
    if($PackageName.Length -gt $maxlength){
        ShowBox ("Package name is too long: {0}. Max is {1} characters." -f $PackageName.Length,$maxlength) "Error" "Error"
        Return $false
    }
    if(-not($isManual) -and -not($isScript) -and -not(Test-Path (Join-Path $SourcePath $InstFileName))){
        ShowBox "File not valid. Could not locate: $SourcePath\$InstFileName" "Error" "Error"
        Return $false
    }
    if($isTransform -and -not(Test-Path (Join-Path $SourcePath $MSTName))){
        ShowBox "File not valid. Could not locate: $SourcePath\$MSTName" "Error" "Error"
        Return $false
    }
    if($LocalizedAppName.Replace(" ","") -eq "" -or $LocalizedAppName -eq $null){
        ShowBox "Software Center Application Name not valid." "Error" "Error"
        Return $false
    }
    if($AppIcon -ne "" -and -not(Test-Path $AppIcon)){
        ShowBox "Icon not valid. Could not locate: $AppIcon" "Error" "Error"
        Return $false
    }
    if($isScript){
        if($InstFileName -eq "" -or $InstFileName -eq $null){
            ShowBox "Install Command not valid." "Error" "Error"
            Return $false
        }
        if($DoStepDeployment -and $CreateUninstall -and ($MSTName -eq "" -or $MSTName -eq $null)){
            ShowBox "Uninstall Command not valid." "Error" "Error"
            Return $false
        }
        if($ProdCode -eq "" -or $ProdCode -eq $null){
            ShowBox "Detection Method $DetectionMeth not valid." "Error" "Error"
            Return $false
        }
        if($DetectionMeth -eq "MSI" -and $ProdCode -notmatch '^[0-9a-fA-F{}-]+$'){
            ShowBox "Product code not valid." "Error" "Error"
            Return $false
        }
        if(-not($DetectExist) -and ($ProdVersion -eq "" -or $ProdVersion -eq $null)){
            ShowBox "Detection Method Version not valid." "Error" "Error"
            Return $false
        }
        if($TwoClauses){
            if($2ndProdCode -eq "" -or $2ndProdCode -eq $null){
                ShowBox "Detection Method $2ndDetectionMeth (Clause 2) not valid." "Error" "Error"
                Return $false
            }
            if($2ndDetectionMeth -eq "MSI" -and $2ndProdCode -notmatch '^[0-9a-fA-F{}-]+$'){
                ShowBox "Product code (Clause 2) not valid." "Error" "Error"
                Return $false
            }
            if(-not($2ndDetectExist) -and ($2ndProdVersion -eq "" -or $2ndProdVersion -eq $null)){
                ShowBox "Detection Method Version (Clause 2) not valid." "Error" "Error"
                Return $false
            }
        }
    }
    $TestINT = Try{[int]$DiskSpaceMB}Catch{0}
    if($ReqDiskSpace -and $TestINT -le 0){
        ShowBox "Disk Space not valid." "Error" "Error"
        Return $false
    }
    if($AddPCs -and ($PCNames -eq "" -or $PCNames -eq $null)){
        ShowBox "Machine names not valid." "Error" "Error"
        Return $false
    }
    if($DoStepAD){
        if(-not(Get-Module -ListAvailable | ?{$_.Name -eq "ActiveDirectory"})){
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            if(-not(Get-Module -ListAvailable | ?{$_.Name -eq "ActiveDirectory"})){
                ShowBox "Administrative Tools is required." "Error" "Error"
                Return $false
            }
        }
    }
    #From XML
    if($DoStepAD){
        if(-not(Check-InArray "ADGroupScope" "DomainLocal,Global,Universal")){Return $false}
    }
    if(-not($sitecode.Contains(":"))){
        Set-Variable -Name sitecode -Value ($sitecode + ":") -Scope Global
    }
    if(-not($CollectionFolder.ToUpper().StartsWith("DEVICECOLLECTION\"))){
        ShowBox "CollectionFolder not valid in settings XML. Valid values must be under DeviceCollection\." "Error" "Error"
        Return $false
    }
    if(-not(Check-InArray "RefreshInterval" "Minutes,Hours,Days,Manual")){Return $false}
    if($RefreshInterval -ne "Manual"){
        $TestINT = Try{[int]$RefreshIntCount}Catch{0}
        if($TestINT -le 0){
            ShowBox "RefreshIntCount not valid in settings XML. Must be a numeric value greater than 0." "Error" "Error"
            Return $false
        }
        if(($RefreshInterval -eq "Minutes" -and $TestINT -gt 59) -or ($RefreshInterval -eq "Hours" -and $TestINT -gt 23) -or ($RefreshInterval -eq "Days" -and $TestINT -gt 31)){
            ShowBox "RefreshIntCount not valid in settings XML. Must be a numeric with maximum value per interval: Minutes-59, Hours-23, Days-31." "Error" "Error"
            Return $false
        }
    }
    if(-not(Check-InArray "PrestageDP" "AutoDownload,DeltaCopy,NoDownload")){Return $false}
    if(-not(Check-InArray "InstallBehavior" "InstallForUser,InstallForSystem,InstallForSystemIfResourceIsDeviceOtherwiseInstallForUser")){Return $false}
    if(-not(Check-InArray "InstallPurpose" "Available,Required")){Return $false}
    $TestINT = Try{[int]$maxDeployTime}Catch{0}
    if($TestINT -lt 15 -or $TestINT -gt 720){
        ShowBox "maxDeployTime not valid in settings XML. Must be a numeric value between 15 and 720." "Error" "Error"
        Return $false
    }
    if(-not(Check-InArray "UserNotification" "DisplayAll,DisplaySoftwareCenterOnly,HideAll")){Return $false}
    if($PkgDelimiter -match '^[0-9a-zA-Z]+$'){
        ShowBox "Package delimiter not valid in settings XML. It must be a non-alphanumeric character." "Error" "Error"
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
        ShowBox "Package delimiter not valid in settings XML. It cannot contain a space or any of the following characters: /\:|*?<>`"." "Error" "Error"
        Return $false
    }
    if($LogOption.StartsWith("/")){
        Set-Variable -Name LogOption -Value ($LogOption.TrimStart("/")) -Scope Global
    }
    if(-not($LogOption.ToUpper().StartsWith("L"))){
        ShowBox "LogOption not valid in settings XML. Valid values start with 'L'." "Error" "Error"
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
        "Question"{$icon = [Windows.Forms.MessageBoxIcon]::Question}
		default{$icon = [Windows.Forms.MessageBoxIcon]::Information}
	}
    if($YesNo){
        $UserChoice = [Windows.Forms.MessageBox]::Show($msg, $title, [Windows.Forms.MessageBoxButtons]::YesNo, $icon)
        Return $UserChoice
    }else{
	    $OkHolder = [Windows.Forms.MessageBox]::Show($msg, $title, [Windows.Forms.MessageBoxButtons]::Ok, $icon)
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
param($customError="",[switch]$NoMain)
    if($Error[0] -ne $null -or $customError -ne ""){
        if($customError -ne ""){
            $ErrorMsg = $customError
        }else{
            $ErrorMsg = $Error[0].Exception
        }
        ShowBox $ErrorMsg "Error" "Error"
        if(-not($NoMain)){
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
            Set-Location $env:SystemDrive
        }
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
	$OutNull = $OpenFileDialog.ShowDialog()
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
            ShowBox "File must be located under $PkgFilesFolder" "Error" "Error"
        }
    }
}
Function Reset-Form{
### This function resets the GUI to its natural state, except for the output log ###
    $StatusStripLabel.Text = "Loading"
    $StatusStrip.Update()
    Reset-Cats
    Set-FormToNone
    $TextBoxAppName.Text = ($PkgNameFormat.Replace("_",$PkgDelimiter))
    $TextBoxLocalAppName.Text = ($TextBoxAppName.Text).Split($PkgDelimiter)[1]
    $CheckBoxSelectAll.Checked = $SelectAll
    $CheckBoxADGroup.Checked = $CreateAD
    $CheckBoxCollection.Checked = $CreateCollection
    $CheckBoxDeployment.Checked = $CreateDeployment
    $RadioBtnManual.Checked = $true
    $RadioBtnMSI.Checked = $false
    $RadioBtnAppX.Checked = $false
    $RadioBtnScript.Checked = $false 
    $TextBoxDesc.Text = ""
    $PictureBoxIcon.Image = $null
    if($TextBoxIcon.Text -ne "" -and $TextBoxIcon.Text -ne $null -and (Get-Item $TextBoxIcon.Text -ErrorAction SilentlyContinue).DirectoryName.ToUpper() -eq ($env:TEMP).ToUpper()){
        $OutNull = Remove-Item $TextBoxIcon.Text -Force
    }
    $TextBoxIcon.Text = ""
    $ListViewAdmCategory.CheckedItems |ForEach-Object {$_.Checked = $false}
    Set-FormToOptions
    if(-not($Chk4m)){$RunButton.Enabled = $true}
    $ResetButton.Enabled = $true
    $QuitButton.Enabled = $true
    $ProgressBar.Value = 0
    $StatusStripLabel.Text = "Ready"
    $StatusStrip.Update()
    $ErrorActionPreference = $eap
}
Function ResetAndDisable-TextBox{
param($textbox)
    $textbox.Enabled = $false
    $textbox.Text = ""
    $textbox.BackColor = [System.Drawing.Color]::Empty
}
Function ResetAndDisable-CheckBox{
param($checkbox)
    $checkbox.Enabled = $false
    $checkbox.Checked = $false
}
Function Set-FormToOptions{
### This function enables/disables required parts of the GUI if user selects to define Components ###
    if($CheckBoxSelectAll.Checked){
        $CheckBoxADGroup.Enabled = $false
        $CheckBoxADGroup.Checked = $true
        $CheckBoxCollection.Enabled = $false
        $CheckBoxCollection.Checked = $true
        $CheckBoxDeployment.Enabled = $false
        if(-not($RadioBtnManual.Checked)){$CheckBoxDeployment.Checked = $true}
    }
    else{
        $CheckBoxADGroup.Enabled = $true
        $CheckBoxCollection.Enabled = $true
        if($CheckBoxCollection.Checked -and -not($RadioBtnManual.Checked)){
            $CheckBoxDeployment.Enabled = $true
            $CheckBoxDeployment.Checked = $CreateDeployment
        }else{ResetAndDisable-CheckBox $CheckBoxDeployment}
    }
    if($CheckBoxADGroup.Checked){
        $CheckBoxAddPCs.Enabled = $true
    }else{
        ResetAndDisable-CheckBox $CheckBoxAddPCs
        ResetAndDisable-TextBox $TextBoxAddPCs
    }
}
Function Set-FormToDTOptions{
### This function enables/disables required parts of the GUI in relation to Deployment Type selection ###
    Set-FormToNone
    Set-FormToOptions
    $TextBoxInstFile.Enabled = $true
    $BrowseBtnInstFile.Enabled = $true
    $LabelSourcePath.Text = Join-Path $PkgFilesFolder $TextBoxAppName.Text
    $CheckBoxDiskSpace.Enabled = $true
    if($RadioBtnMSI.Checked){
        $CheckBoxTransform.Enabled = $true
        $TextBoxInstFile.Text = $TextBoxAppName.Text + ".msi"
        $CheckBoxInteraction.Enabled = $true
        $ComboboxRebootB.Enabled = $true
        $ComboboxRebootB.SelectedIndex = 0
    }elseif($RadioBtnAppX.Checked){
        $TextBoxInstFile.Text = $TextBoxAppName.Text + ".msix"
    }elseif($RadioBtnScript.Checked){
        $TextBoxInstFile.Text = $ScriptInstallCMD
        $TextBoxTransform.Enabled = $true
        $TextBoxTransform.Text = $ScriptUninstallCMD
        $BrowseButtonMST.Enabled = $true
        $ComboBoxDetection.Enabled = $true
        $ComboBoxDetection.SelectedIndex = 0
        $TextBoxProdCode.Enabled = $true
        Set-FormToDetectionOption $ComboBoxDetection $TextBoxProdCode $BrowseBtnDetectMSI $CheckBoxDetect32on64
        $RadioBtnDetectExist.Enabled = $true
        $RadioBtnDetectCompare.Enabled = $true
        $CheckBox2ndDetect.Enabled = $true
        $ComboBox2ndDetection.SelectedIndex = 0
        Set-FormToDetectionOption $ComboBox2ndDetection $TextBox2ndProdCode $BrowseBtn2ndDetectMSI $CheckBox2ndDetect32on64
        $CheckBoxInteraction.Enabled = $true
        $ComboboxRebootB.Enabled = $true
        $ComboboxRebootB.SelectedIndex = 0
    }
}
Function Set-FormToNone{
### This function enables/disables required parts of the GUI in relation to creating an Application without a Deployment Type ###
    ResetAndDisable-CheckBox $CheckBoxDeployment
    ResetAndDisable-CheckBox $CheckBoxTransform
    ResetAndDisable-TextBox $TextBoxInstFile
    $BrowseBtnInstFile.Enabled = $false
    $LabelSourcePath.Text = $PkgFilesFolder
    ResetAndDisable-TextBox $TextBoxTransform
    $BrowseButtonMST.Enabled = $false
    $ComboBoxDetection.Enabled = $false
    ResetAndDisable-TextBox $TextBoxProdCode
    $BrowseBtnDetectMSI.Enabled = $false
    $RadioBtnDetectExist.Enabled = $false
    $RadioBtnDetectExist.Checked = $true
    $RadioBtnDetectCompare.Enabled = $false
    $ComboBoxComparator.Enabled = $false
    ResetAndDisable-TextBox $TextBoxProdVersion
    ResetAndDisable-CheckBox $CheckBoxDetect32on64
    $TextBox2ndProdCode.Text = ""
    $RadioBtn2ndDetectExist.Checked = $true
    $ComboBox2ndComparator.Enabled = $false
    ResetAndDisable-TextBox $TextBox2ndProdVersion
    $CheckBox2ndDetect32on64.Checked = $false
    $CheckBox2ndDetect.Checked = $false
    Set-FormToDetectClause1
    $ButtonClause2.Enabled = $false
    $ButtonClause1.BackColor = $Form.BackColor
    $CheckBox2ndDetect.Enabled = $false
    ResetAndDisable-CheckBox $CheckBoxInteraction
    $ComboboxRebootB.Enabled = $false
    ResetAndDisable-CheckBox $CheckBoxDiskSpace
    ResetAndDisable-TextBox $TextBoxDiskSpace
}
Function Set-FormToDetectionOption{
### This function enables/disables required parts of the GUI in relation to the selected Detection Method ###
param($CBDetection,$TBDetect,$BtBrowse,$CB32on64)
    switch($CBDetection.SelectedItem){
        'MSI'{
            $TBDetect.Text = "{00000000-0000-0000-0000-000000000000}"
            $BtBrowse.Enabled = $true
            ResetAndDisable-CheckBox $CB32on64
        }
        'File'{
            $TBDetect.Text = '%ProgramFiles%\'
            $BtBrowse.Enabled = $true
            $CB32on64.Enabled = $true
        }
        'Registry'{
            $TBDetect.Text = "HKLM:\"
            $BtBrowse.Enabled = $false
            $CB32on64.Enabled = $true
        }
    }
}
Function Set-FormToBrowsedDetection{
### This function sets fields when user Browses to a MSI or File for detection ###
param($CBDetection,$TBDetect,$TBVersion,$CB32on64)
    switch($CBDetection.SelectedItem){
        "MSI"{
            $MSIProps = Get-MSIProps (Get-FileName "*.msi" "Windows Installer Package")
            $TBDetect.Text = $MSIProps.ProductCode
            $TBVersion.Text = $MSIProps.ProductVersion
        }
        "File"{
            $DetectFile = Get-FileName "*.*" "All files"
            $TBVersion.Text = (Get-Item $DetectFile).VersionInfo.FileVersionRaw -join '.'
            if($DetectFile.Contains(${env:ProgramFiles(x86)})){
                $DetectFile = $DetectFile.Replace(${env:ProgramFiles(x86)},'%ProgramFiles%')
                $CB32on64.Checked = $true
            }
            $TBDetect.Text = $DetectFile.Replace($env:ProgramFiles,'%ProgramFiles%')
        }
    }
}
Function Set-FormToDetectClause1{
### This function enables/disables required parts of the GUI in relation to 1 detection clause ###
    $GroupBox2ndDetection.Visible = $false
    $GroupBoxDetection.Visible = $true
    $ButtonClause1.Enabled = $false
    $ButtonClause1.BackColor = $MainMenu.BackColor
    $ButtonClause2.Enabled = $true
    $ButtonClause2.BackColor = $Form.BackColor
}
Function Set-RequiredField{
### This function highlights required Text fields ###
    if($this.Enabled -and (($this.Text).Replace(" ","") -eq "" -or $this.Text -eq $null)){$this.BackColor = [System.Drawing.Color]::Pink}
    else{$this.BackColor = [System.Drawing.Color]::Empty}
}
Function Reset-Cats{
### This function refreshes the Catagory list ###
    if($Chk4m){return}
    Set-Location $Sitecode
    $ListViewAdmCategory.Items.Clear()
    Get-CMCategory -CategoryType AppCategories | Sort LocalizedCategoryInstanceName | %{
        $LI = New-Object system.Windows.Forms.ListViewItem
        $LI.Name = $_.LocalizedCategoryInstanceName
		$LI.Text = $_.LocalizedCategoryInstanceName
        $OutNull = $ListViewAdmCategory.Items.add($LI)
    }
    Set-Location $env:SystemDrive
}
Function New-Cat{
### This function creates a new Category in MCM when user clicks the New button ###
param($CatType)
    $NewCat = [Microsoft.VisualBasic.Interaction]::InputBox("Enter a Category name to create", "New Category", "")
    if($NewCat -ne "" -and $NewCat -ne $null){
        Set-Location $Sitecode
        $Error.Clear()
        $OutNull = New-CMCategory -CategoryType $CatType -Name $NewCat
        if($Error[0] -ne $null){
            DM "Error creating Category: $NewCat" "Red"
            ShowBox $Error[0].Exception "Error" "Error"
            $NewCat = $null
        }else{
            DM "Category created"
        }
        Set-Location $env:SystemDrive
    }
    Return $NewCat
}
Function Add-FormObj{
### This function reduces excessive code by dynamically creating Form objects along with various definitions ###
param($fComponent, $fObj, $ParentObj, $x, $y, $xSize, $Txt=$null, $TTipTxt=$null, $Forecolor=$null, $Select=$null, [switch]$DisableMouseWheel, $Checked=$false, [switch]$CheckRight, $Font=$null, $ySize=20, [switch]$Required, [switch]$MenuItem)
    if($fObj -eq $null){$DynamicObj = New-Object System.Windows.Forms.$fComponent}
    else{$DynamicObj = $fObj}

    if($Txt){
        if($fComponent -eq 'ComboBox'){
            $Txt | %{$OutNull = $DynamicObj.Items.add($_)}
            if($Select){
                for($i=0;$i-le $DynamicObj.Items.Count-1;$i++){
                    if($DynamicObj.Items[$i] -eq $Select){$DynamicObj.SelectedIndex = $i}
                }
            }
        }else{$DynamicObj.Text = $Txt}
    }
    if($Forecolor){$DynamicObj.Forecolor = $Forecolor}
    switch($Font){
        'Small'{$DynamicObj.Font = New-Object System.Drawing.Font($DynamicObj.Font.Name,($DynamicObj.Font.Size - 1))}
        'Bold'{$DynamicObj.Font = New-Object System.Drawing.Font($DynamicObj.Font.Name,$DynamicObj.Font.Size,[System.Drawing.FontStyle]::Bold)}
        default{}
    }
    if($DisableMouseWheel){$DynamicObj.Add_Mousewheel({$_.Handled = $true})}

    if($fComponent -eq "ToolStripMenuItem"){
        if($TTipTxt){$DynamicObj.ToolTipText = $TTipTxt}
        if($MenuItem){[void]$ParentObj.Items.Add($DynamicObj)}
        else{[void]$ParentObj.DropDownItems.Add($DynamicObj)}
    }else{
        $DynamicObj.Location = New-Object System.Drawing.Size($x,$y)
        if($xSize -eq 0){$DynamicObj.AutoSize = $True}
        else{$DynamicObj.Size = New-Object System.Drawing.Size($xSize,$ySize)}

        if($TTipTxt){
            $SetTooltip = New-Object System.Windows.Forms.ToolTip
            $SetTooltip.SetToolTip($DynamicObj,$TTipTxt)
        }
        switch -Wildcard ($fComponent){
            'CheckBox'{
                $DynamicObj.Checked = $Checked
                if($CheckRight){$DynamicObj.CheckAlign = "TopRight"}
            }
            'ComboBox'{$DynamicObj.DropDownStyle = 'DropDownList'}
            '*TextBox'{if($Required){$DynamicObj.Add_TextChanged({Set-RequiredField})}}
        }
        $ParentObj.Controls.Add($DynamicObj)
    }
}
Function Test-WriteAccess{
### This function tests whether user has Write access to a directory ###
param($TestPath)
    $Error.Clear()
    $OutNull = New-Item -Path "$TestPath\check" -ItemType File
    if($Error[0] -ne $null){
        Return $false
    }else{
        Remove-Item -Path "$TestPath\check"
        Return $true
    }
}
Function Load-Prereqs{
### This function loads modules and sets the working directory for the XML ###
    ### Load Forms
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [void] [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.VisualBasic")

    #look for configman module in default location, or assume its loaded in path
    if(-not($Chk4m)){
        $ConfigManMod = Join-Path $(Split-Path $env:SMS_ADMIN_UI_PATH) ConfigurationManager.psd1
        If(Test-Path $ConfigManMod){Import-Module $ConfigManMod}
        Else{
            $Error.Clear()
            Import-Module ConfigurationManager
            if((ErrorChecker -NoMain) -eq $false){Return}
        }
    }

    #check Settings  
    $WorkingPath = $ScriptPath
    if(-not(Test-Path "$WorkingPath\Settings.xml")){
        if(-not(Test-WriteAccess $WorkingPath)){
            $WorkingPath = "$env:APPDATA\MCMAddAppTool"
            if(-not(Test-Path $WorkingPath)){$OutNull = New-Item $WorkingPath -ItemType directory}
        }
    }
    $SettingsXML = "$WorkingPath\Settings.xml"
    if(-not(Test-Path $SettingsXML)){
        ShowBox "Required settings could not be found or accessed.`nThis must be set before continuing." "First Run?"
        SettingsForm
    }
    Return $SettingsXML
}

#region################ Main Form (UI) block #####################################################
Function MainForm{
#Declare Form Objects
$Form = New-Object System.Windows.Forms.Form

$MainMenu = New-Object System.Windows.Forms.MenuStrip
$FileMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$miRunning = New-Object System.Windows.Forms.ToolStripMenuItem
$miRunAs = New-Object System.Windows.Forms.ToolStripMenuItem
$miQuit = New-Object System.Windows.Forms.ToolStripMenuItem
$EditMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$miSettings = New-Object System.Windows.Forms.ToolStripMenuItem
$HelpMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$miAbout = New-Object System.Windows.Forms.ToolStripMenuItem

$TextBoxAppName = New-Object System.Windows.Forms.TextBox

$GroupBoxTaskOptions = New-Object System.Windows.Forms.GroupBox
$CheckBoxSelectAll = New-Object System.Windows.Forms.CheckBox
$CheckBoxADGroup = New-Object System.Windows.Forms.CheckBox
$CheckBoxCollection = New-Object System.Windows.Forms.CheckBox
$CheckBoxDeployment = New-Object System.Windows.Forms.CheckBox

$GroupBoxDepType = New-Object System.Windows.Forms.GroupBox
$RadioBtnManual = New-Object System.Windows.Forms.RadioButton
$RadioBtnMSI = New-Object System.Windows.Forms.RadioButton
$CheckBoxTransform = New-Object System.Windows.Forms.CheckBox
$RadioBtnAppX = New-Object System.Windows.Forms.RadioButton
$RadioBtnScript = New-Object System.Windows.Forms.RadioButton

$OutputBox = New-Object System.Windows.Forms.RichTextBox
$ClearButton = New-Object System.Windows.Forms.Button

$LabelSourcePath = New-Object System.Windows.Forms.Label
$TextBoxInstFile = New-Object System.Windows.Forms.TextBox
$BrowseBtnInstFile = New-Object System.Windows.Forms.Button
$TextBoxTransform = New-Object System.Windows.Forms.TextBox
$BrowseButtonMST = New-Object System.Windows.Forms.Button

$GroupBoxSoftCenter = New-Object System.Windows.Forms.GroupBox
$TextBoxLocalAppName = New-Object System.Windows.Forms.TextBox
$TextBoxDesc = New-Object System.Windows.Forms.RichTextBox
$TextBoxIcon = New-Object System.Windows.Forms.TextBox
$BrowseButtonIcon = New-Object System.Windows.Forms.Button
$PictureBoxIcon = New-Object Windows.Forms.PictureBox

$GroupBoxDetection = New-Object System.Windows.Forms.GroupBox
$ComboBoxDetection = New-Object System.Windows.Forms.ComboBox
$TextBoxProdCode = New-Object System.Windows.Forms.TextBox 
$BrowseBtnDetectMSI = New-Object System.Windows.Forms.Button
$RadioBtnDetectExist = New-Object System.Windows.Forms.RadioButton
$RadioBtnDetectCompare = New-Object System.Windows.Forms.RadioButton
$ComboBoxComparator = New-Object System.Windows.Forms.ComboBox
$TextBoxProdVersion = New-Object System.Windows.Forms.TextBox
$CheckBoxDetect32on64 = New-Object System.Windows.Forms.CheckBox

$GroupBox2ndDetection = New-Object System.Windows.Forms.GroupBox
$ComboBox2ndDetection = New-Object System.Windows.Forms.ComboBox
$TextBox2ndProdCode = New-Object System.Windows.Forms.TextBox 
$BrowseBtn2ndDetectMSI = New-Object System.Windows.Forms.Button
$RadioBtn2ndDetectExist = New-Object System.Windows.Forms.RadioButton
$RadioBtn2ndDetectCompare = New-Object System.Windows.Forms.RadioButton
$ComboBox2ndComparator = New-Object System.Windows.Forms.ComboBox
$TextBox2ndProdVersion = New-Object System.Windows.Forms.TextBox
$CheckBox2ndDetect32on64 = New-Object System.Windows.Forms.CheckBox

$CheckBox2ndDetect = New-Object System.Windows.Forms.CheckBox
$ButtonClause1 = New-Object System.Windows.Forms.Button
$ButtonClause2 = New-Object System.Windows.Forms.Button

$GroupBoxUserExp = New-Object System.Windows.Forms.GroupBox
$CheckBoxInteraction = New-Object System.Windows.Forms.CheckBox
$ComboboxRebootB = New-Object System.Windows.Forms.ComboBox

$GroupBoxRequirement = New-Object System.Windows.Forms.GroupBox
$CheckBoxDiskSpace = New-Object System.Windows.Forms.CheckBox
$TextBoxDiskSpace = New-Object System.Windows.Forms.TextBox 

$ListViewAdmCategory = New-Object System.Windows.Forms.ListView
$NewAdmCatButton = New-Object System.Windows.Forms.Button

$CheckBoxAddPCs = New-Object System.Windows.Forms.CheckBox
$TextBoxAddPCs = New-Object System.Windows.Forms.RichTextBox

$ProgressBar = New-Object System.Windows.Forms.ProgressBar
$RunButton = New-Object System.Windows.Forms.Button
$ResetButton = New-Object System.Windows.Forms.Button
$QuitButton = New-Object System.Windows.Forms.Button

$StatusStrip = New-Object System.Windows.Forms.StatusStrip
$StatusStripLabel = New-Object System.Windows.Forms.ToolStripStatusLabel

#Define Form Objects
$Form.Text = $scriptName
$Form.Size = New-Object System.Drawing.Size(725,665) 
$Form.StartPosition = "CenterScreen"
$Form.FormBorderStyle = "FixedDialog"
$Form.MaximizeBox = $False
$Form.KeyPreview = $True
$Form.Add_KeyDown({if ($_.KeyCode -eq "Escape") {$Form.Close()}})
if(Test-Path "$ScriptPath\AppIcon.ico"){$Form.Icon = New-Object System.Drawing.Icon("$ScriptPath\AppIcon.ico")}
$Form.Add_Load({Get-Process | ?{ $_.MainWindowTitle -eq "Loading"} | Stop-Process -Force})

$MainMenu.BackColor = [System.Drawing.Color]::LightSteelBlue
$miRunning.Enabled = $false
$miRunAs.Add_Click({
    if((ShowBox "This will close the current window and relaunch with a RunAs dialog.`nContinue?" "Confirm" "Question" -YesNo) -eq "Yes"){
        $Form.Close()
        $Error.Clear()
        if($Dbug){Start-Process powershell.exe -Verb RunAs -WorkingDirectory $ScriptPath -ArgumentList ('-NoProfile -File "{0}" -Dbug' -f ($PSCommandPath))}
        else{Start-Process powershell.exe -Verb RunAs -WorkingDirectory $ScriptPath -ArgumentList ('-NoProfile -WindowStyle hidden -File "{0}" -Dbug' -f ($PSCommandPath))}
        ErrorChecker -NoMain
    }
})
$miQuit.Add_Click({$Form.Close()})
$miSettings.Add_Click({
    SettingsForm
    Import-Settings
    Reset-Form
})
$miAbout.Add_Click({ShowBox $about "About" "Information"})

$TextBoxAppName.add_TextChanged({
    Set-RequiredField
    if(-not($RadioBtnManual.Checked)){$LabelSourcePath.Text = Join-Path $PkgFilesFolder $TextBoxAppName.Text}
    $TextBoxLocalAppName.Text = ($TextBoxAppName.Text).Split($PkgDelimiter)[1]
})

$CheckBoxSelectAll.add_Click({Set-FormToOptions})
$CheckBoxADGroup.add_Click({Set-FormToOptions})
$CheckBoxCollection.add_Click({Set-FormToOptions})

$RadioBtnManual.add_Click({Set-FormToNone})
$RadioBtnMSI.add_Click({Set-FormToDTOptions})
$CheckBoxTransform.add_Click({
    if($CheckBoxTransform.Checked){
        $TextBoxTransform.Enabled = $true
        $TextBoxTransform.Text = $TextBoxAppName.Text + ".mst"
        $BrowseButtonMST.Enabled = $true
	}else{
        ResetAndDisable-TextBox $TextBoxTransform
        $BrowseButtonMST.Enabled = $false
	}
})
$RadioBtnAppX.add_Click({Set-FormToDTOptions})
$RadioBtnScript.add_Click({Set-FormToDTOptions})
 
$OutputBox.Font = New-Object System.Drawing.Font("Lucida Console",8.25)
$OutputBox.Multiline = $true
$OutputBox.ReadOnly = $true
$OutputBox.ScrollBars = "Vertical"
$ClearButton.Add_Click({$OutputBox.Text = "`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n`r`n"})

$BrowseBtnInstFile.Add_Click({
    $InstallFile = $null
    if($RadioBtnMSI.Checked){
        $InstallFile = Get-FileName "*.msi" "Windows Installer Package"
    }elseif($RadioBtnAppX.Checked){
        $InstallFile = Get-FileName "*.appx;*.appxbundle;*.msix;*.msixbundle" "Windows App Package"
    }elseif($RadioBtnScript.Checked){
        $InstallFile = Get-FileName "*.exe" "Executable File"
    }
    Pop-FileName $InstallFile $TextBoxInstFile
})
$BrowseButtonMST.Add_Click({
    $InstallFile = $null
    if($RadioBtnMSI.Checked){
        $InstallFile = Get-FileName "*.mst" "MST File"
    }elseif($RadioBtnScript.Checked){
        $InstallFile = Get-FileName "*.exe" "Executable File"
    }
    Pop-FileName $InstallFile $TextBoxTransform
})

$ComboBoxDetection.add_SelectedIndexChanged({Set-FormToDetectionOption $ComboBoxDetection $TextBoxProdCode $BrowseBtnDetectMSI $CheckBoxDetect32on64})
$BrowseBtnDetectMSI.Add_Click({Set-FormToBrowsedDetection $ComboBoxDetection $TextBoxProdCode $TextBoxProdVersion $CheckBoxDetect32on64})
$RadioBtnDetectExist.add_Click({
if($RadioBtnDetectExist.Checked){
    $ComboBoxComparator.Enabled = $false
    $TextBoxProdVersion.Enabled = $false
}
})
$RadioBtnDetectCompare.add_Click({
if($RadioBtnDetectCompare.Checked){
    $ComboBoxComparator.Enabled = $true
    $TextBoxProdVersion.Enabled = $true
}
})
$CheckBox2ndDetect.add_Click({
    Set-FormToDetectClause1
    $ButtonClause2.Enabled = $CheckBox2ndDetect.Checked
    if(-not($CheckBox2ndDetect.Checked)){$ButtonClause1.BackColor = $Form.BackColor}
})
$ButtonClause1.add_Click({Set-FormToDetectClause1})
$ButtonClause2.add_Click({
    $GroupBoxDetection.Visible = $false
    $GroupBox2ndDetection.Visible = $true
    $ButtonClause1.Enabled = $true
    $ButtonClause1.BackColor = $Form.BackColor
    $ButtonClause2.Enabled = $false
    $ButtonClause2.BackColor = $MainMenu.BackColor
})
$ComboBox2ndDetection.add_SelectedIndexChanged({Set-FormToDetectionOption $ComboBox2ndDetection $TextBox2ndProdCode $BrowseBtn2ndDetectMSI $CheckBox2ndDetect32on64})
$BrowseBtn2ndDetectMSI.Add_Click({Set-FormToBrowsedDetection $ComboBox2ndDetection $TextBox2ndProdCode $TextBox2ndProdVersion $CheckBox2ndDetect32on64})
$RadioBtn2ndDetectExist.add_Click({
if($RadioBtn2ndDetectExist.Checked){
    $ComboBox2ndComparator.Enabled = $false
    $TextBox2ndProdVersion.Enabled = $false
}
})
$RadioBtn2ndDetectCompare.add_Click({
if($RadioBtn2ndDetectCompare.Checked){
    $ComboBox2ndComparator.Enabled = $true
    $TextBox2ndProdVersion.Enabled = $true
}
})

$TextBoxDesc.Multiline = $true
$TextBoxDesc.ScrollBars = "Vertical"

$BrowseButtonIcon.Add_Click({
    $IconFile = Get-FileName "*.exe;*.jpeg;*.jpg;*.ico;*.png" "Image and Icon Files"
    if($IconFile -ne $null){
        $StatusStripLabel.Text = "Loading icon"
        $StatusStrip.Update()
        $TextBoxIcon.Text = $IconFile
        if($IconFile.ToLower().EndsWith(".exe")){
            $IconEXE = Get-Item $IconFile
            if($IconFile.StartsWith("\\")){#cannot extract from UNC path, so map drive
                $NewDrive = [char](68..90 | ?{((Get-PSDrive).Name -notContains [char]$_)} | random)
                New-PSDrive -Name $NewDrive -PSProvider "FileSystem" -Root (Split-Path $IconFile) -Persist
                $IconEXE = Get-Item ($NewDrive+":\"+$IconEXE.Name)
            }
            #extract image to Temp
            $NewIcon = $env:TEMP + "\" + $IconEXE.BaseName + ".png"
            [System.Drawing.Icon]::ExtractAssociatedIcon($IconEXE.FullName).ToBitmap().Save($NewIcon)
            DM "Icon extracted."
            $TextBoxIcon.Text = $NewIcon
            $BitMap = New-Object System.Drawing.Bitmap($NewIcon)
            #Picturebox will lock the file if it is used for the graphic. So create a clone.
            $BitMapClone = New-Object System.Drawing.Bitmap($BitMap)
            $PictureBoxIcon.Image = $BitMapClone
            $BitMap.Dispose()
            Get-PSDrive -Name $NewDrive | Remove-PSDrive
        }elseif($IconFile.ToLower().EndsWith(".ico")){
            $PictureBoxIcon.Image = New-Object System.Drawing.Icon($IconFile)
        }else{
            $PictureBoxIcon.Image = [System.Drawing.Image]::FromFile($IconFile)
        }
        $StatusStripLabel.Text = "Ready"
        $StatusStrip.Update()
    }
})
$PictureBoxIcon.SizeMode = "StretchImage"

$CheckBoxDiskSpace.add_Click({
    if($CheckBoxDiskSpace.Checked){$TextBoxDiskSpace.Enabled = $true}
    else{ResetAndDisable-TextBox $TextBoxDiskSpace}
})
$TextBoxDiskSpace.TextAlign = "Right"

$ListViewAdmCategory.View = 'Details'
$ListViewAdmCategory.CheckBoxes = $true
$LVcolAdmCategory = $ListViewAdmCategory.Columns.add('MCM Admin Categories')
$LVcolAdmCategory.Width = 144
$NewAdmCatButton.Add_Click({
    $NewCategory = New-Cat "AppCategories"
    if($NewCategory -ne "" -and $NewCategory -ne $null){Reset-Cats}
})

$CheckBoxAddPCs.add_Click({
    if($CheckBoxAddPCs.Checked){
        $TextBoxAddPCs.Enabled = $true
        $TextBoxAddPCs.Text = $TestMachines.Replace(",","`n").Replace(";","`n")
	}else{ResetAndDisable-TextBox $TextBoxAddPCs}
})
$TextBoxAddPCs.Multiline = $true
$TextBoxAddPCs.ScrollBars = "Vertical"

$ProgressBar.Minimum = 0
$ProgressBar.Maximum = 100

$RunButton.Add_Click({
	Import-Settings
    Main
})
$ResetButton.Add_Click({Reset-Form})
$QuitButton.Add_Click({$Form.Close()})

if($Chk4m){
    $NewAdmCatButton.Enabled = $false
    $RunButton.Enabled = $false
}

$StatusStrip.BackColor = [System.Drawing.Color]::LightSteelBlue
$StatusStripLabel.Text = "Ready"

#Add Form Objects
Add-FormObj 'ToolStripMenuItem' $FileMenu $MainMenu -Txt "&File" -MenuItem
Add-FormObj 'ToolStripMenuItem' $miRunning $FileMenu -Txt "&UR:$env:USERNAME"
Add-FormObj 'ToolStripMenuItem' $miRunAs $FileMenu -Txt "&Run As..."
Add-FormObj 'ToolStripMenuItem' $miQuit $FileMenu -Txt "&Quit"
Add-FormObj 'ToolStripMenuItem' $EditMenu $MainMenu -Txt "&Edit" -MenuItem
Add-FormObj 'ToolStripMenuItem' $miSettings $EditMenu -Txt "&Settings"
Add-FormObj 'ToolStripMenuItem' $HelpMenu $MainMenu -Txt "&Help" -MenuItem
Add-FormObj 'ToolStripMenuItem' $miAbout $HelpMenu -Txt "&About"
$Form.Controls.Add($MainMenu)

Add-FormObj 'Label' $null $Form 10 30 0 "Package name:" 
Add-FormObj 'Textbox' $TextBoxAppName $Form 10 50 260

Add-FormObj 'GroupBox' $GroupBoxTaskOptions $Form 10 80 120 "Create:" -ySize 120
Add-FormObj 'CheckBox' $CheckBoxSelectAll $GroupBoxTaskOptions 10 20 0 "Select All"
Add-FormObj 'CheckBox' $CheckBoxADGroup $GroupBoxTaskOptions 20 40 0 "AD Group"
Add-FormObj 'CheckBox' $CheckBoxCollection $GroupBoxTaskOptions 20 60 0 "Collection"
Add-FormObj 'CheckBox' $CheckBoxDeployment $GroupBoxTaskOptions 20 80 0 "Deployment"

Add-FormObj 'GroupBox' $GroupBoxDepType $Form 150 80 120 "Deployment Type:" -ySize 120
Add-FormObj 'RadioButton' $RadioBtnManual $GroupBoxDepType 20 15 0 "Manual"
Add-FormObj 'RadioButton' $RadioBtnMSI $GroupBoxDepType 20 35 0 "MSI Installer"
Add-FormObj 'CheckBox' $CheckBoxTransform $GroupBoxDepType 30 55 0 "Transform"
Add-FormObj 'RadioButton' $RadioBtnAppX $GroupBoxDepType 20 75 0 "AppX/MSIX"
Add-FormObj 'RadioButton' $RadioBtnScript $GroupBoxDepType 20 95 0 "Script"

Add-FormObj 'RichTextBox' $OutputBox $Form 290 30 410 "" -ySize 170
Add-FormObj 'Button' $ClearButton $Form 625 203 0 "Clear Log"

Add-FormObj 'Label' $null $Form 10 210 0 "Source:"
Add-FormObj 'Label' $LabelSourcePath $Form 10 230 0
Add-FormObj 'Textbox' $TextBoxInstFile $Form 10 250 260 -TTipTxt "For MSI or AppX, this is the relevant msi/appx/msix file`nFor Script, this is the Install command" -Required
Add-FormObj 'Button' $BrowseBtnInstFile $Form 275 248 0 "Browse"
Add-FormObj 'Textbox' $TextBoxTransform $Form 10 275 260 -TTipTxt "For MSI with Transform, this is the mst file`nFor Script, this is the Uninstall command" -Required
Add-FormObj 'Button' $BrowseButtonMST $Form 275 273 0 "Browse"

Add-FormObj 'GroupBox' $GroupBoxSoftCenter $Form 360 250 340 "Software Center:" -ySize 150
Add-FormObj 'Textbox' $TextBoxLocalAppName $GroupBoxSoftCenter 10 20 220 -TTipTxt "Localized Application Name" -Required
Add-FormObj 'Label' $null $GroupBoxSoftCenter 10 45 0 "Description:"
Add-FormObj 'RichTextBox' $TextBoxDesc $GroupBoxSoftCenter 10 65 320 -ySize 45
Add-FormObj 'Label' $null $GroupBoxSoftCenter 10 120 0 "Icon:"
Add-FormObj 'Textbox' $TextBoxIcon $GroupBoxSoftCenter 45 118 205 -TTipTxt "Path to ico or exe file`nDoes not support dlls at this time"
Add-FormObj 'Button' $BrowseButtonIcon $GroupBoxSoftCenter 255 116 0 "Browse"
Add-FormObj 'PictureBox' $PictureBoxIcon $GroupBoxSoftCenter 275 15 40 -ySize 40

Add-FormObj 'GroupBox' $GroupBoxDetection $Form 10 310 340 "Detection Method:" -ySize 125
Add-FormObj 'ComboBox' $ComboBoxDetection $GroupBoxDetection 10 20 70 ('MSI','File','Registry')
Add-FormObj 'Textbox' $TextBoxProdCode $GroupBoxDetection 10 45 240 -TTipTxt "For MSI, this is the Product code`nFor File or Registry, this is the relevant path" -Required
Add-FormObj 'Button' $BrowseBtnDetectMSI $GroupBoxDetection 255 43 0 "Browse"
Add-FormObj 'RadioButton' $RadioBtnDetectExist $GroupBoxDetection 10 75 0 "Exists" "For Registry, assumes property as a String"
Add-FormObj 'RadioButton' $RadioBtnDetectCompare $GroupBoxDetection 70 75 0 " " "Version"
Add-FormObj 'ComboBox' $ComboBoxComparator $GroupBoxDetection 95 75 100 ('IsEquals','NotEquals','GreaterEquals','GreaterThan','LessEquals','LessThan') -Select 'GreaterEquals'
Add-FormObj 'Textbox' $TextBoxProdVersion $GroupBoxDetection 200 75 90 -Required
Add-FormObj 'CheckBox' $CheckBoxDetect32on64 $GroupBoxDetection 10 100 0 "associate with a 32-bit application on 64-bit systems"
Add-FormObj 'GroupBox' $GroupBox2ndDetection $Form 10 310 340 "Detection Method:" -ySize 125
Add-FormObj 'ComboBox' $ComboBox2ndDetection $GroupBox2ndDetection 10 20 70 ('MSI','File','Registry')
Add-FormObj 'Textbox' $TextBox2ndProdCode $GroupBox2ndDetection 10 45 240 -Required
Add-FormObj 'Button' $BrowseBtn2ndDetectMSI $GroupBox2ndDetection 255 43 0 "Browse"
Add-FormObj 'RadioButton' $RadioBtn2ndDetectExist $GroupBox2ndDetection 10 75 0 "Exists"
Add-FormObj 'RadioButton' $RadioBtn2ndDetectCompare $GroupBox2ndDetection 70 75 0 " "
Add-FormObj 'ComboBox' $ComboBox2ndComparator $GroupBox2ndDetection 95 75 100 ('IsEquals','NotEquals','GreaterEquals','GreaterThan','LessEquals','LessThan') -Select 'GreaterEquals'
Add-FormObj 'Textbox' $TextBox2ndProdVersion $GroupBox2ndDetection 200 75 90 -Required
Add-FormObj 'CheckBox' $CheckBox2ndDetect32on64 $GroupBox2ndDetection 10 100 0 "associate with a 32-bit application on 64-bit systems"
Add-FormObj 'CheckBox' $CheckBox2ndDetect $Form 20 440 0 "AND" "Create a 2nd Detection Clause joined by AND`n(OR condition is not yet implemented)`nUse Clause buttons to switch between"
Add-FormObj 'Label' $null $Form 250 440 0 "Clause" -Font 'Small'
Add-FormObj 'Button' $ButtonClause1 $Form 290 437 20 "1"
Add-FormObj 'Button' $ButtonClause2 $Form 315 437 20 "2"

Add-FormObj 'GroupBox' $GroupBoxUserExp $Form 360 410 340 "User Experience" -ySize 70
Add-FormObj 'CheckBox' $CheckBoxInteraction $GroupBoxUserExp 20 20 0 "Allow users to view and interact with the installation"
Add-FormObj 'Label' $null $GroupBoxUserExp 20 45 0 "Reboot Behavior:"
Add-FormObj 'ComboBox' $ComboboxRebootB $GroupBoxUserExp 120 43 120 ('BasedOnExitCode','NoAction','ForceReboot','ProgramReboot')

Add-FormObj 'GroupBox' $GroupBoxRequirement $Form 360 490 340 "Requirement:" -ySize 45
Add-FormObj 'CheckBox' $CheckBoxDiskSpace $GroupBoxRequirement 20 20 0 "Disk Space                           MB" "Set Free Space requirement for System Drive (in MB)`nPotentially useful for large applications"
Add-FormObj 'Textbox' $TextBoxDiskSpace $GroupBoxRequirement 115 18 50 -Required
$TextBoxDiskSpace.BringToFront()

Add-FormObj 'ListView' $ListViewAdmCategory $Form 10 470 165 -ySize 75
Add-FormObj 'Button' $NewAdmCatButton $Form 10 550 0 "New"

Add-FormObj 'CheckBox' $CheckBoxAddPCs $Form 185 470 0 "Add device(s) to AD group:" "Select to add machines to the newly created AD group"
Add-FormObj 'RichTextBox' $TextBoxAddPCs $Form 185 490 165 -TTipTxt "Enter machine name(s)`nMultiple machines can be separated by new lines`nOr on the same line with comma (,) or semicolons (;)`nSpecify domain if needed in format: Domain\Machine" -ySize 70 -Required

Add-FormObj 'Button' $RunButton $Form 360 550 130 "Create" -ySize 23
Add-FormObj 'Button' $ResetButton $Form 500 550 80 "Reset Form" -ySize 23
Add-FormObj 'Button' $QuitButton $Form 590 550 75 "Quit" -ySize 23

Add-FormObj 'ProgressBar' $ProgressBar $Form 10 580 690

[void]$StatusStrip.Items.add($StatusStripLabel)
$Form.Controls.Add($StatusStrip)

#Show Form
if(Import-Settings){Reset-Form}else{Return}
$Form.Add_Shown({$Form.Activate()})
[System.Windows.Forms.Application]::Run($Form)
}
#endregion########################################################################################

#region################ Settings Form block ######################################################
Function SettingsForm{
if(-not(Import-Settings)){
#first run - set defaults
    $SelectAll = $true
    $ADPath = 'OU=,DC=,DC=,DC='
    $ADGroupScope = 'DomainLocal'
    $CollectionFolder = 'DeviceCollection\'
    $RefreshInterval = 'Hours'
    $RefreshIntCount = 1
    $AllowTaskSeqInstall = $true
    $PrestageDP = 'AutoDownload'
    $InstallBehavior = 'InstallForSystem'
    $maxDeployTime = 120
    $InstallPurpose = 'Required'
    $SendWakeup = $true
    $UserNotification = 'DisplaySoftwareCenterOnly'
    $Comments = 'Date+UserID'
    $CreateUninstall = $false
    $PkgDelimiter = '_'
    $MSIargs = 'REBOOT=ReallySuppress ALLUSERS=1 /qn'
    $UninstallArgs = 'REBOOT=ReallySuppress /qn'
    $LogOption = 'l*v'
    $ScriptInstallCMD = 'Deploy-Application.exe'
    $ScriptUninstallCMD = 'Deploy-Application.exe -DeploymentType "Uninstall"'
}

#Declare Form Objects
$SettingsForm = New-Object System.Windows.Forms.Form 

$SetGroupBoxCreateComponents = New-Object System.Windows.Forms.GroupBox
$SetCheckBoxSelectAll = New-Object System.Windows.Forms.CheckBox
$SetCheckBoxCreateAD = New-Object System.Windows.Forms.CheckBox
$SetCheckBoxCreateCollection = New-Object System.Windows.Forms.CheckBox
$SetCheckBoxCreateDeployment = New-Object System.Windows.Forms.CheckBox

$SetGroupBoxADoptions = New-Object System.Windows.Forms.GroupBox
$SetTextBoxADDomain = New-Object System.Windows.Forms.TextBox
$SetTextBoxADPath = New-Object System.Windows.Forms.TextBox
$SetComboBoxADGroupScope = New-Object System.Windows.Forms.ComboBox
$SetTextBoxTestMachines = New-Object System.Windows.Forms.TextBox

$SetGroupBoxMCMoptions = New-Object System.Windows.Forms.GroupBox
$SetTextBoxSitecode = New-Object System.Windows.Forms.TextBox
$SetComboBoxComments = New-Object System.Windows.Forms.ComboBox
$SetTextBoxLimitingCollection = New-Object System.Windows.Forms.TextBox
$SetTextBoxCollectionFolder = New-Object System.Windows.Forms.TextBox
$SetComboBoxRefreshInterval = New-Object System.Windows.Forms.ComboBox
$SetComboBoxRefreshIntCount = New-Object System.Windows.Forms.ComboBox
$SetTextBoxApplicationFolder = New-Object System.Windows.Forms.TextBox
$SetCheckBoxAllowTaskSeqInstall = New-Object System.Windows.Forms.CheckBox
$SetComboBoxPrestageDP = New-Object System.Windows.Forms.ComboBox
$SetTextBoxDPGroup = New-Object System.Windows.Forms.TextBox
$SetComboBoxInstallBehavior = New-Object System.Windows.Forms.ComboBox
$SetTextBoxmaxDeployTime = New-Object System.Windows.Forms.TextBox
$SetTrackBarmaxDeployTime = New-Object System.Windows.Forms.TrackBar
$SetComboBoxInstPurpose = New-Object System.Windows.Forms.ComboBox
$SetCheckBoxSendWakeup = New-Object System.Windows.Forms.CheckBox
$SetComboBoxUserNotification = New-Object System.Windows.Forms.ComboBox
$SetTextBoxPkgrTestCollection = New-Object System.Windows.Forms.TextBox
$SetCheckBoxUninstall = New-Object System.Windows.Forms.CheckBox

$SetGroupBoxPKGoptions = New-Object System.Windows.Forms.GroupBox
$SetTextBoxPkgDelimiter = New-Object System.Windows.Forms.TextBox
$SetLabelPkgDelimiterShown = New-Object System.Windows.Forms.Label
$SetTextBoxPkgFilesFolder = New-Object System.Windows.Forms.TextBox
$SetTextBoxMSIargs = New-Object System.Windows.Forms.TextBox
$SetTextBoxUninstallArgs = New-Object System.Windows.Forms.TextBox
$SetTextBoxLogOption = New-Object System.Windows.Forms.TextBox
$SetTextBoxLogPath = New-Object System.Windows.Forms.TextBox
$SetTextBoxScriptInstallCMD = New-Object System.Windows.Forms.TextBox
$SetTextBoxScriptUninstallCMD = New-Object System.Windows.Forms.TextBox

$SetSaveButton = New-Object System.Windows.Forms.Button
$SetLabelSaved = New-Object System.Windows.Forms.Label
$SetCloseButton = New-Object System.Windows.Forms.Button

#Define Form Objects
$SettingsForm.Text = "$scriptName Settings"
$Screen = [System.Windows.Forms.Screen]::PrimaryScreen 
$SettingsForm.Size = New-Object System.Drawing.Size(400,(($Screen.Bounds.Height)*.7)) 
$SettingsForm.StartPosition = "CenterScreen"
$SettingsForm.FormBorderStyle = "FixedDialog"
$SettingsForm.AutoScroll = $True
$SettingsForm.MaximizeBox = $False
$SettingsForm.KeyPreview = $True
$SettingsForm.Add_KeyDown({if ($_.KeyCode -eq "Escape") {$SettingsForm.Close()}})
if(Test-Path "$ScriptPath\AppIcon.ico"){$SettingsForm.Icon = New-Object System.Drawing.Icon("$ScriptPath\AppIcon.ico")}

$SetCheckBoxSelectAll.add_Click({
    if($SetCheckBoxSelectAll.Checked){
        $SetCheckBoxCreateAD.Enabled = $false
        $SetCheckBoxCreateAD.Checked = $true
        $SetCheckBoxCreateCollection.Enabled = $false
        $SetCheckBoxCreateCollection.Checked = $true
        $SetCheckBoxCreateDeployment.Enabled = $false
        $SetCheckBoxCreateDeployment.Checked = $true
    }else{
        $SetCheckBoxCreateAD.Enabled = $true
        $SetCheckBoxCreateAD.Checked = $false
        $SetCheckBoxCreateCollection.Enabled = $true
        $SetCheckBoxCreateCollection.Checked = $false
        $SetCheckBoxCreateDeployment.Enabled = $true
        $SetCheckBoxCreateDeployment.Checked = $false
    }
})
$SetCheckBoxCreateDeployment.add_Click({
    if($SetCheckBoxCreateDeployment.Checked){$SetCheckBoxCreateCollection.Checked = $true}
})

$SetComboBoxRefreshInterval.add_SelectedIndexChanged({
    $SetComboBoxRefreshIntCount.Items.Clear()
    switch($SetComboBoxRefreshInterval.SelectedItem){
        'Minutes'{$MaxInt = 59}
        'Hours'{$MaxInt = 23}
        'Days'{$MaxInt = 31}
        'Manual'{$MaxInt = 0
            $OutNull = $SetComboBoxRefreshIntCount.Items.add($MaxInt)
        }
    }
    for($i=1;$i-le $MaxInt;$i++){$OutNull = $SetComboBoxRefreshIntCount.Items.add($i)}
    $SetComboBoxRefreshIntCount.SelectedIndex = 0
})
$SetComboBoxRefreshIntCount.Add_Mousewheel({if(-not($SetComboBoxRefreshIntCount.DroppedDown)){$_.Handled = $true}})

$minmaxDeployTime = 15
$maxmaxDeployTime = 720
$SetTrackBarmaxDeployTime.SetRange($minmaxDeployTime, $maxmaxDeployTime) 
$SetTextBoxmaxDeployTime.add_Leave({
    if([int]($SetTextBoxmaxDeployTime.Text) -lt $minmaxDeployTime){
        $SetTextBoxmaxDeployTime.Text = $minmaxDeployTime
    }elseif([int]($SetTextBoxmaxDeployTime.Text) -gt $maxmaxDeployTime){
        $SetTextBoxmaxDeployTime.Text = $maxmaxDeployTime
    }
})
$SetTextBoxmaxDeployTime.add_TextChanged({
    if([int]($SetTextBoxmaxDeployTime.Text) -ge $minmaxDeployTime -and [int]($SetTextBoxmaxDeployTime.Text) -le $maxmaxDeployTime){$SetTrackBarmaxDeployTime.Value = $SetTextBoxmaxDeployTime.Text}
})

$SetTrackBarmaxDeployTime.AutoSize = $False
$SetTrackBarmaxDeployTime.Orientation = “Horizontal”
$SetTrackBarmaxDeployTime.TickFrequency = 15
$SetTrackBarmaxDeployTime.LargeChange = 15
$SetTrackBarmaxDeployTime.SmallChange = 5
$SetTrackBarmaxDeployTime.TickStyle = “TopLeft”
$SetTrackBarmaxDeployTime.Value = $maxDeployTime
$SetTrackBarmaxDeployTime.add_ValueChanged({$SetTextBoxmaxDeployTime.Text = $SetTrackBarmaxDeployTime.Value})

$SetComboBoxInstPurpose.add_SelectedIndexChanged({
    if($SetComboBoxInstPurpose.SelectedItem -eq 'Available'){$SetCheckBoxSendWakeup.Enabled = $false}else{$SetCheckBoxSendWakeup.Enabled = $true}
})

$SetTextBoxPkgDelimiter.MaxLength = 1
$SetTextBoxPkgDelimiter.TextAlign = "Center"
$SetTextBoxPkgDelimiter.add_TextChanged({$SetLabelPkgDelimiterShown.Text = $PkgNameFormat.Replace("_",$SetTextBoxPkgDelimiter.Text)})

$SetSaveButton.Add_Click({
    $SetLabelSaved.Text = ""
    $Error.Clear()
    $xmlObjectsettings = New-Object System.Xml.XmlWriterSettings
    $xmlObjectsettings.Indent = $true
    $xmlObjectsettings.IndentChars = " "
    $XmlObjectWriter = [System.XML.XmlWriter]::Create($SettingsXML, $xmlObjectsettings)
    $XmlObjectWriter.WriteStartDocument()
    $XmlObjectWriter.WriteStartElement(“Settings“)
    $XmlObjectWriter.WriteComment(“Create Component options”)
    $XmlObjectWriter.WriteElementString(“SelectAll”,$SetCheckBoxSelectAll.Checked)
    $XmlObjectWriter.WriteElementString(“CreateAD”,$SetCheckBoxCreateAD.Checked)
    $XmlObjectWriter.WriteElementString(“CreateCollection”,$SetCheckBoxCreateCollection.Checked)
    $XmlObjectWriter.WriteElementString(“CreateDeployment”,$SetCheckBoxCreateDeployment.Checked)
    $XmlObjectWriter.WriteComment(“Active Directory options”)
    $XmlObjectWriter.WriteElementString(“ADDomain”,$SetTextBoxADDomain.Text)
    $XmlObjectWriter.WriteElementString(“ADPath”,$SetTextBoxADPath.Text)
    $XmlObjectWriter.WriteElementString(“ADGroupScope”,$SetComboBoxADGroupScope.SelectedItem)
    $XmlObjectWriter.WriteElementString(“TestMachines”,$SetTextBoxTestMachines.Text)
    $XmlObjectWriter.WriteComment(“ConfigMgr options”)
    $XmlObjectWriter.WriteElementString(“Sitecode”,$SetTextBoxSitecode.Text)
    $XmlObjectWriter.WriteElementString(“Comments”,$SetComboBoxComments.SelectedItem)
    $XmlObjectWriter.WriteComment(“Collection”)
    $XmlObjectWriter.WriteElementString(“LimitingCollection”,$SetTextBoxLimitingCollection.Text)
    $XmlObjectWriter.WriteElementString(“CollectionFolder”,$SetTextBoxCollectionFolder.Text)
    $XmlObjectWriter.WriteElementString(“RefreshInterval”,$SetComboBoxRefreshInterval.SelectedItem)
    $XmlObjectWriter.WriteElementString(“RefreshIntCount”,$SetComboBoxRefreshIntCount.SelectedItem)
    $XmlObjectWriter.WriteComment(“Application”)
    $XmlObjectWriter.WriteElementString(“ApplicationFolder”,$SetTextBoxApplicationFolder.Text)
    $XmlObjectWriter.WriteElementString(“AllowTaskSeqInstall”,$SetCheckBoxAllowTaskSeqInstall.Checked)
    $XmlObjectWriter.WriteElementString(“PrestageDP”,$SetComboBoxPrestageDP.SelectedItem)
    $XmlObjectWriter.WriteComment(“Deployment”)
    $XmlObjectWriter.WriteElementString(“DPGroup”,$SetTextBoxDPGroup.Text)
    $XmlObjectWriter.WriteElementString(“InstallBehavior”,$SetComboBoxInstallBehavior.SelectedItem)
    $XmlObjectWriter.WriteElementString(“maxDeployTime”,$SetTextBoxmaxDeployTime.Text)
    $XmlObjectWriter.WriteElementString(“InstallPurpose”,$SetComboBoxInstPurpose.SelectedItem)
    $XmlObjectWriter.WriteElementString(“SendWakeup”,$SetCheckBoxSendWakeup.Checked)
    $XmlObjectWriter.WriteElementString(“UserNotification”,$SetComboBoxUserNotification.SelectedItem)
    $XmlObjectWriter.WriteElementString(“PkgrTestCollection”,$SetTextBoxPkgrTestCollection.Text)
    $XmlObjectWriter.WriteElementString(“CreateUninstall”,$SetCheckBoxUninstall.Checked)
    $XmlObjectWriter.WriteComment(“Installer options”)
    $XmlObjectWriter.WriteElementString(“PkgDelimiter”,$SetTextBoxPkgDelimiter.Text)
    $XmlObjectWriter.WriteElementString(“PkgFilesFolder”,$SetTextBoxPkgFilesFolder.Text)
    $XmlObjectWriter.WriteElementString(“MSIargs”,$SetTextBoxMSIargs.Text)
    $XmlObjectWriter.WriteElementString(“UninstallArgs”,$SetTextBoxUninstallArgs.Text)
    $XmlObjectWriter.WriteElementString(“LogOption”,$SetTextBoxLogOption.Text)
    $XmlObjectWriter.WriteElementString(“LogPath”,$SetTextBoxLogPath.Text)
    $XmlObjectWriter.WriteElementString(“ScriptInstallCMD”,$SetTextBoxScriptInstallCMD.Text)
    $XmlObjectWriter.WriteElementString(“ScriptUninstallCMD”,$SetTextBoxScriptUninstallCMD.Text)
    $XmlObjectWriter.WriteEndElement()
    $XmlObjectWriter.WriteEndDocument()
    $XmlObjectWriter.Flush()
    $XmlObjectWriter.Close()
    
    if(-not(Test-Path $SettingsXML) -or $Error[0] -ne $null){
        ShowBox "Unable to create Settings file.`nMake sure you have write access to $SettingsXML" "Error" "Error"
        $SetLabelSaved.Forecolor = 'Red'
        $SetLabelSaved.Text = "Error!"
    }else{
        $SetLabelSaved.Forecolor = 'Green'
        $SetLabelSaved.Text = "Saved!"
    }
})

$SetCloseButton.Add_Click({$SettingsForm.Close()})

#Add Form Objects
Add-FormObj 'Label' $null $SettingsForm 10 10 0 "*Optional. If not desired, leave blank." -Forecolor 'Gray'

Add-FormObj 'GroupBox' $SetGroupBoxCreateComponents $SettingsForm 10 30 350 "Create Components (default):" -ySize 95
Add-FormObj 'CheckBox' $SetCheckBoxSelectAll $SetGroupBoxCreateComponents 10 20 0 "Select All" "Create all components (Active Directory group, Collection, Application, and Deployment)" -Checked $SelectAll -Font 'Small'
Add-FormObj 'CheckBox' $SetCheckBoxCreateAD $SetGroupBoxCreateComponents 20 38 0 "AD Group" "Create an Active Directory group for the package" -Checked $CreateAD -Font 'Small'
Add-FormObj 'CheckBox' $SetCheckBoxCreateCollection $SetGroupBoxCreateComponents 20 54 0 "Collection" "Create a device Collection`nIf AD group is enabled this will also create a query rule linking the two" -Checked $CreateCollection -Font 'Small'
Add-FormObj 'CheckBox' $SetCheckBoxCreateDeployment $SetGroupBoxCreateComponents 20 70 0 "Deployment" "Create a Deployment to the Collection`nCollection must be enabled" -Checked $CreateDeployment -Font 'Small'
if($SetCheckBoxSelectAll.Checked){
    $SetCheckBoxCreateAD.Enabled = $false
    $SetCheckBoxCreateCollection.Enabled = $false
    $SetCheckBoxCreateDeployment.Enabled = $false
}

Add-FormObj 'GroupBox' $SetGroupBoxADoptions $SettingsForm 10 140 350 "Active Directory options:" -ySize 125
Add-FormObj 'Label' $null $SetGroupBoxADoptions 10 20 0 "Domain:" 
Add-FormObj 'Textbox' $SetTextBoxADDomain $SetGroupBoxADoptions 240 18 100 $ADDomain "Active Directory domain where the Distribution groups will be created" -Required
Add-FormObj 'Label' $null $SetGroupBoxADoptions 10 45 0 "OU:"
Add-FormObj 'Textbox' $SetTextBoxADPath $SetGroupBoxADoptions 160 43 180 $ADPath "The full path to the OU where the groups will be created. In format:`nOU=,OU=,DC=,DC=,DC=" -Required
Add-FormObj 'Label' $null $SetGroupBoxADoptions 10 70 0 "Group Scope:"
Add-FormObj 'ComboBox' $SetComboBoxADGroupScope $SetGroupBoxADoptions 240 68 100 ('DomainLocal','Global','Universal') "The Security type defined for the AD group" -Select $ADGroupScope -DisableMouseWheel
Add-FormObj 'Label' $null $SetGroupBoxADoptions 10 95 0 "Test Machines*:" -Forecolor 'Gray'
Add-FormObj 'Textbox' $SetTextBoxTestMachines $SetGroupBoxADoptions 160 93 180 $TestMachines "Machine names to add to the AD group`nSeparate by , or ;`nSpecify domain if needed in format: Domain\Machine"

Add-FormObj 'GroupBox' $SetGroupBoxMCMoptions $SettingsForm 10 280 350 "ConfigMgr options:" -ySize 450
Add-FormObj 'Label' $null $SetGroupBoxMCMoptions 10 20 0 "Sitecode:"
Add-FormObj 'Textbox' $SetTextBoxSitecode $SetGroupBoxMCMoptions 300 18 40 $Sitecode "Site code" -Required
Add-FormObj 'Label' $null $SetGroupBoxMCMoptions 10 45 0 "Comments:"
Add-FormObj 'ComboBox' $SetComboBoxComments $SetGroupBoxMCMoptions 240 43 100 ('Date','UserID','Date+UserID','None') "Add User/Date comments to Collection, Application, and Deployment" -Select $Comments -DisableMouseWheel
Add-FormObj 'Label' $null $SetGroupBoxMCMoptions 10 70 0 "Limiting Collection:"
Add-FormObj 'Textbox' $SetTextBoxLimitingCollection $SetGroupBoxMCMoptions 160 68 180 $LimitingCollection "The Limiting Collection to be used for the Device Collections" -Required
Add-FormObj 'Label' $null $SetGroupBoxMCMoptions 10 95 0 "Collection Folder:"
Add-FormObj 'Textbox' $SetTextBoxCollectionFolder $SetGroupBoxMCMoptions 160 93 180 $CollectionFolder "The folder under Device Collections that the new Collections will be moved to`nTool will create folder if it doesn’t exist" -Required
Add-FormObj 'Label' $null $SetGroupBoxMCMoptions 10 120 0 "Refresh Interval:"
Add-FormObj 'ComboBox' $SetComboBoxRefreshInterval $SetGroupBoxMCMoptions 210 118 70 ('Minutes','Hours','Days','Manual') "The interval type used to refresh the Collection" -Select $RefreshInterval -DisableMouseWheel
Add-FormObj 'Label' $null $SetGroupBoxMCMoptions 285 120 0 ":"
switch($SetComboBoxRefreshInterval.SelectedItem){
    'Minutes'{$MaxInt = 59}
    'Hours'{$MaxInt = 23}
    'Days'{$MaxInt = 31}
    'Manual'{$MaxInt = 0
        $OutNull = $SetComboBoxRefreshIntCount.Items.add($MaxInt)
    }
}
for($i=1;$i-le $MaxInt;$i++){
	$OutNull = $SetComboBoxRefreshIntCount.Items.add($i)
    if($i -eq $RefreshIntCount){$SetComboBoxRefreshIntCount.SelectedIndex = $i-1}
}
Add-FormObj 'ComboBox' $SetComboBoxRefreshIntCount $SetGroupBoxMCMoptions 300 118 40 $null "The count used in conjunction with the Interval type"
Add-FormObj 'Label' $null $SetGroupBoxMCMoptions 10 145 0 "Application Folder:"
Add-FormObj 'Textbox' $SetTextBoxApplicationFolder $SetGroupBoxMCMoptions 160 143 180 $ApplicationFolder "The folder that new Applications or Packages will be moved to`nTool will create folder if it doesn’t exist" -Required
Add-FormObj 'CheckBox' $SetCheckBoxAllowTaskSeqInstall $SetGroupBoxMCMoptions 10 170 330 "Allow Task Sequence" "Application setting`nAllow this application to be installed from the Install Application task sequence action without being deployed" -Checked $AllowTaskSeqInstall -CheckRight
Add-FormObj 'Label' $null $SetGroupBoxMCMoptions 10 195 0 "Prestaged Distribution Point:"
Add-FormObj 'ComboBox' $SetComboBoxPrestageDP $SetGroupBoxMCMoptions 240 193 100 ('AutoDownload','DeltaCopy','NoDownload') "Application Distribution setting. Prestaged distribution point.`nAutomatically download content when the packages are assigned to distribution points,`nDownload only content changes to the distribution point,`nor Manually copy the content in this package to the distribution point" -Select $PrestageDP -DisableMouseWheel
Add-FormObj 'Label' $null $SetGroupBoxMCMoptions 10 220 0 "Distribution Group:"
Add-FormObj 'Textbox' $SetTextBoxDPGroup $SetGroupBoxMCMoptions 160 218 180 $DPGroup "The Distribution Group used to distribute content to`nMust use a pre-existing group and not an individual DP" -Required
Add-FormObj 'Label' $null $SetGroupBoxMCMoptions 10 245 0 "Install Behavior:"
Add-FormObj 'ComboBox' $SetComboBoxInstallBehavior $SetGroupBoxMCMoptions 160 243 180 ('InstallForUser','InstallForSystem','InstallForSystemIfResourceIsDeviceOtherwiseInstallForUser') "Application Deployment Type setting`nInstall Behavior" -Select $InstallBehavior -DisableMouseWheel
Add-FormObj 'Label' $null $SetGroupBoxMCMoptions 10 270 0 "Maximum run time (minutes):"
Add-FormObj 'TextBox' $SetTextBoxmaxDeployTime $SetGroupBoxMCMoptions 300 268 40 $maxDeployTime "Application Deployment Type setting`nMaximum allowed run time (minutes)" -Required
Add-FormObj 'TrackBar' $SetTrackBarmaxDeployTime $SetGroupBoxMCMoptions 10 290 330 -DisableMouseWheel -ySize 25
Add-FormObj 'Label' $null $SetGroupBoxMCMoptions 10 320 0 "Install Purpose:"
Add-FormObj 'ComboBox' $SetComboBoxInstPurpose $SetGroupBoxMCMoptions 240 318 100 ('Available','Required') "Application Deployment setting.`nAvailable`nRequired" -Select $InstallPurpose -DisableMouseWheel
Add-FormObj 'CheckBox' $SetCheckBoxSendWakeup $SetGroupBoxMCMoptions 10 345 330 "Send Wake-up" "Application Deployment setting`nSend wake-up packets" -Checked $SendWakeup -CheckRight
if($SetComboBoxInstPurpose.SelectedItem -eq 'Available'){$SetCheckBoxSendWakeup.Enabled = $false}
Add-FormObj 'Label' $null $SetGroupBoxMCMoptions 10 370 0 "User Notification:"
Add-FormObj 'ComboBox' $SetComboBoxUserNotification $SetGroupBoxMCMoptions 160 368 180 ('DisplayAll','DisplaySoftwareCenterOnly','HideAll') "Application Deployment setting. User notifications`nDisplay in Software Center and show all notifications,`nDisplay in Software Center and only show notifications for computer restarts,`nor Hide in Software Center and all notifications" -Select $UserNotification -DisableMouseWheel
Add-FormObj 'Label' $null $SetGroupBoxMCMoptions 10 395 0 "Test Collection*:" -Forecolor 'Gray'
Add-FormObj 'Textbox' $SetTextBoxPkgrTestCollection $SetGroupBoxMCMoptions 160 393 180 $PkgrTestCollection "Will create an additional Available deployment to this Collection`nThis is intended to be used for package testing"
Add-FormObj 'CheckBox' $SetCheckBoxUninstall $SetGroupBoxMCMoptions 10 420 330 "Uninstall Deployment" "Will also create Uninstall groups and deployment" -Checked $CreateUninstall -CheckRight

Add-FormObj 'GroupBox' $SetGroupBoxPKGoptions $SettingsForm 10 745 350 "Installer options:" -ySize 245
Add-FormObj 'Label' $null $SetGroupBoxPKGoptions 10 20 0 "Package Delimiter:"
Add-FormObj 'Textbox' $SetTextBoxPkgDelimiter $SetGroupBoxPKGoptions 320 18 20 $PkgDelimiter "A non-alphanumeric character to separate the Package name into Manufacturer Product and Version`nSome characters are not allowed such as / \ : | * ? < > `“ ." -Required
Add-FormObj 'Label' $SetLabelPkgDelimiterShown $SetGroupBoxPKGoptions 10 40 0 $PkgNameFormat.Replace("_",$SetTextBoxPkgDelimiter.Text) -Font 'Bold'
Add-FormObj 'Label' $null $SetGroupBoxPKGoptions 10 65 0 "Source Files Folder:"
Add-FormObj 'Textbox' $SetTextBoxPkgFilesFolder $SetGroupBoxPKGoptions 160 63 180 $PkgFilesFolder "The source folder that packages are stored under" -Required
Add-FormObj 'Label' $null $SetGroupBoxPKGoptions 10 90 0 "MSI Arguments:"
Add-FormObj 'Textbox' $SetTextBoxMSIargs $SetGroupBoxPKGoptions 160 88 180 $MSIargs "Arguments to pass in to msiexec.exe along with the install command`nThis is if using a MSI install type" -Required
Add-FormObj 'Label' $null $SetGroupBoxPKGoptions 10 115 0 "Uninstall Arguments:"
Add-FormObj 'Textbox' $SetTextBoxUninstallArgs $SetGroupBoxPKGoptions 160 113 180 $UninstallArgs "Arguments to pass in to msiexec.exe along with the uninstall command`nThis is if using a MSI install type" -Required
Add-FormObj 'Label' $null $SetGroupBoxPKGoptions 10 140 0 "Logging Option:"
Add-FormObj 'Textbox' $SetTextBoxLogOption $SetGroupBoxPKGoptions 300 138 40 $LogOption "The log level to use with msiexec`nThis is if using a MSI install type" -Required
Add-FormObj 'Label' $null $SetGroupBoxPKGoptions 10 165 0 "Log Folder:"
Add-FormObj 'Textbox' $SetTextBoxLogPath $SetGroupBoxPKGoptions 160 163 180 $LogPath "The log path to use with msiexec`nThis is if using a MSI install type" -Required
Add-FormObj 'Label' $null $SetGroupBoxPKGoptions 10 190 0 "Script Install Command*:" -Forecolor 'Gray'
Add-FormObj 'Textbox' $SetTextBoxScriptInstallCMD $SetGroupBoxPKGoptions 160 188 180 $ScriptInstallCMD "The install command for the Application if using a Script install type"
Add-FormObj 'Label' $null $SetGroupBoxPKGoptions 10 215 0 "Script Uninstall Command*:" -Forecolor 'Gray'
Add-FormObj 'Textbox' $SetTextBoxScriptUninstallCMD $SetGroupBoxPKGoptions 160 213 180 $ScriptUninstallCMD "The uninstall command for the Application if using a Script install type"

Add-FormObj 'Button' $SetSaveButton $SettingsForm 100 1005 80 "Save" -ySize 23
Add-FormObj 'Label' $SetLabelSaved $SettingsForm 115 1030 0 ""
if(-not(Test-WriteAccess (Split-Path -Path $SettingsXML -Parent))){
    $SetSaveButton.Enabled = $false
    $SetLabelSaved.Forecolor = 'Orange'
    $SetLabelSaved.Text = "Set by admin"
}
Add-FormObj 'Button' $SetCloseButton $SettingsForm 190 1005 75 "Close" -ySize 23

Add-FormObj 'Label' $null $SettingsForm 10 1055 0 "Closing this window will launch/refresh the main program.`nIt may take a few moments to load. Please be patient." -Forecolor 'Gray'

#Show Form
$SettingsForm.Add_Shown({$SettingsForm.Activate()})
[void] $SettingsForm.ShowDialog()
$SettingsForm.Dispose()
}
#endregion########################################################################################

### Start here
#Recall the script hidden
if(-not($Dbug)){
    Start-Process powershell.exe -ArgumentList ('-NoProfile -WindowStyle hidden -File "{0}" -Dbug' -f ($PSCommandPath))
}else{
    #Loading screen
    $Loading = {
    param($RunFrom)
        [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
        [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        [System.Windows.Forms.Application]::EnableVisualStyles()

        $LoadingForm = New-Object System.Windows.Forms.Form
        $AddAppIcon = New-Object Windows.Forms.PictureBox
        $LoadingBar = New-Object System.Windows.Forms.ProgressBar

        $LoadingForm.Text = "Loading"
        $LoadingForm.Size = New-Object System.Drawing.Size(220,260) 
        $LoadingForm.StartPosition = "CenterScreen"
        $LoadingForm.FormBorderStyle = "FixedDialog"
        $LoadingForm.MaximizeBox = $False

        $AddAppIcon.Location = New-Object System.Drawing.Size(0,0)
        $AddAppIcon.Size = New-Object System.Drawing.Size(210,210)
        $AddAppIcon.SizeMode = "StretchImage"
        $AddAppIcon.Image = [System.Drawing.Image]::FromFile("$RunFrom\AppIcon.ico")

        $LoadingBar.Location = New-Object System.Drawing.Size(0,210)
        $LoadingBar.Size = New-Object System.Drawing.Size(205,10)
        $LoadingBar.Style = "Marquee"

        $LoadingForm.Controls.Add($AddAppIcon)
        $LoadingForm.Controls.Add($LoadingBar)

        $LoadingForm.Add_Shown({$LoadingForm.Activate()})
        [void] $LoadingForm.ShowDialog()
        $LoadingForm.Dispose()
    }
    $OutNull = Start-Job -ScriptBlock $Loading -ArgumentList $ScriptPath -Name "AddAppLoading"
    #load settings/prereqs
    $SettingsXML = Load-Prereqs
    if(Test-Path $SettingsXML){
        #launch GUI
        MainForm
    }else{
        ShowBox "Settings file must exist in order to use this tool and one was not found.`nMake sure you have write access to $SettingsXML" "Error" "Error"
    }
    Get-Job -Name "AddAppLoading" -ErrorAction SilentlyContinue | Remove-Job -Force
}

<###################### TODO
-is it possible to navigate AD in the settings form?
-create AD group, collection, deployment after creating the App?
-add Test Collection to Install collection (include), rather than a 2nd deployment?
-set a default log path?
-first several params of Add-FormObj are positional; might be easier to read if specified
-OR detection method
-browse registry for detection?
-some old var names might need to rename; Transform/MST is also used now for Uninstall CMD; Prodcode is also used for Registry or Files
#>