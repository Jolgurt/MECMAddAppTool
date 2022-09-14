param([switch]$Dbug)

### Global Variables ###
# When compiled with PS2EXE the variable MyCommand contains no path
if ($MyInvocation.MyCommand.CommandType -eq "ExternalScript"){ # Powershell script
    $ThisScript = $MyInvocation.MyCommand.Definition
}else{ # PS2EXE compiled script
	$ThisScript = [Environment]::GetCommandLineArgs()[0]
}
$ScriptPath = Split-Path -Parent -Path $ThisScript
#if this is running from a mapped drive, replace the drive letter with the root
if(-not($ScriptPath.StartsWith("\\"))){
    $ThisScriptRoot = (Get-PSDrive ($ScriptPath.Split(":")[0])).DisplayRoot
    if($ThisScriptRoot.StartsWith("\\")){
        $ScriptPath = Join-Path $ThisScriptRoot $ScriptPath.Split(":")[1]
    }
}
$SettingsXML = "$ScriptPath\MECMAddAppSettings.xml"
$License = "$ScriptPath\LICENSE.txt"
$PkgNameFormat = "Manufacturer_Product_Version"
$scriptName = "MECM AddApp Tool"
$scriptVersion = "2.11.2"

### About
$about = "*************************************************************************`n"
$about += "  ScriptName:   $scriptName`n"
$about += "  ScriptPath:   $ThisScript`n"
$about += "  ScriptVersion:  $scriptVersion`n"
$about += "  Created by:      Joel Chettle`n"
$about += "  Description:    Creates software groups in Active Directory and`n" 
$about += " 	           applications/packages in MECM/SCCM, including`n"
$about += " 	           the collections and deployments if capable, per`n"
$about += " 	           configurations defined in settings.`n"
$about += "  Requirements: Must be ran under an account with privileges to AD`n"
$about += " 	           and MECM.`n"
$about += " 	           Must have Configuration Manager Console and`n"
$about += " 	           AdminTools (optional) installed.`n"
$about += "*************************************************************************`n"
$about += "  Notes:`n"
$about += "     1] The time it takes to load the form is due mainly to the import`n"
$about += "         of data from MECM.`n"
$about += "     2] This tool is meant to automate common conditions. More`n"
$about += "         features may be added over time. But by no means is it fully`n"
$about += "         inclusive to all scenarios.`n"
$about += "*************************************************************************`n`n"
if(Test-Path $License){$about += Get-Content $License}

Function Main{
### This function performs the steps to create the Application in AD and MECM when user clicks "Create" button on the GUI ###
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
#region################ MECM Collection block ####################################################
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
        $Error.Clear()
        if($RefreshInterval -ne "Manual"){
            $StartTime = [DateTime]"$Date 12:00 AM"
            $Schedule = New-CMSchedule -RecurCount $RefreshIntCount -RecurInterval $RefreshInterval -Start $StartTime
            $Collection = New-CMDeviceCollection -Name $CollectionName -LimitingCollectionName $LimitingCollection -Comment $Comment -RefreshSchedule $Schedule
        }else{
            $Collection = New-CMDeviceCollection -Name $CollectionName -LimitingCollectionName $LimitingCollection -Comment $Comment -RefreshType $RefreshInterval
        }
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
#region################ MECM Application block ###################################################
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
#region################ MECM Deployment block ####################################################
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
                    #build a Detection Clause
                    if($DetectionMeth -ne "MSI"){
                        $DetectPath = Split-Path $ProdCode
                        $DetectItem = Split-Path $ProdCode -Leaf
                    }
                    switch($DetectionMeth){
                        "MSI"{
                            if(-not($DetectExist)){$DetectClause = New-CMDetectionClauseWindowsInstaller -ProductCode $ProdCode -Value -PropertyType ProductVersion -ExpressionOperator $DetectComp -ExpectedValue $ProdVersion}
                        }
                        "File"{
                            if($DetectExist){
                                $DetectClauseCMD = "New-CMDetectionClauseFile -Path `"$DetectPath`" -FileName `"$DetectItem`" -Existence"
                            }else{
                                $DetectClauseCMD = "New-CMDetectionClauseFile -Path `"$DetectPath`" -FileName `"$DetectItem`" -Value -PropertyType Version -ExpressionOperator $DetectComp -ExpectedValue $ProdVersion"
                            }
                            if(-not($Detect32on64)){$DetectClauseCMD += " -Is64Bit"}
                            $DetectClause = Invoke-Expression $DetectClauseCMD
                        }
                        "Registry"{
                            $Hive = 'LocalMachine'
                            if($ProdCode.StartsWith("HKLM:\") -or $ProdCode.StartsWith("HKEY_LOCAL_MACHINE")){
                                $DetectPath = $DetectPath.Replace("HKLM:\","").Replace("HKEY_LOCAL_MACHINE","")
                            }elseif($ProdCode.StartsWith("HKCU:\") -or $ProdCode.StartsWith("HKEY_CURRENT_USER")){
                                $Hive = 'CurrentUser'
                                $DetectPath = $DetectPath.Replace("HKCU:\","").Replace("HKEY_CURRENT_USER","")
                            }elseif($ProdCode.StartsWith("HKEY_CLASSES_ROOT")){
                                $Hive = 'ClassesRoot'
                                $DetectPath = $DetectPath.Replace("HKEY_CLASSES_ROOT","")
                            }elseif($ProdCode.StartsWith("HKEY_USERS")){
                                $Hive = 'Users'
                                $DetectPath = $DetectPath.Replace("HKEY_USERS","")
                            }elseif($ProdCode.StartsWith("HKEY_CURRENT_CONFIG")){
                                $Hive = 'CurrentConfig'
                                $DetectPath = $DetectPath.Replace("HKEY_CURRENT_CONFIG","")
                            }
                            if($DetectExist){
                                $DetectClauseCMD = "New-CMDetectionClauseRegistryKeyValue -Hive $Hive -KeyName `"$DetectPath`" -ValueName `"$DetectItem`" -PropertyType String -Existence"
                            }else{
                                $DetectClauseCMD = "New-CMDetectionClauseRegistryKeyValue -Hive $Hive -KeyName `"$DetectPath`" -ValueName `"$DetectItem`" -Value -PropertyType Version -ExpressionOperator $DetectComp -ExpectedValue $ProdVersion"
                            }
                            if(-not($Detect32on64)){$DetectClauseCMD += " -Is64Bit"}
                            $DetectClause = Invoke-Expression $DetectClauseCMD
                        }
                    }
                    $Error.Clear()
                    #MSI Exist can go straight into creating the DT.  All others have a Detection Clause.
                    if($DetectionMeth -eq "MSI" -and $DetectExist){
                        Add-CMScriptDeploymentType -ApplicationName $BetaName -DeploymentTypeName $DeploymentType -ContentLocation $SourcePath -Force -Comment $Comment -InstallCommand $InstFileName -UninstallCommand $MSTName -ProductCode $ProdCode -MaximumRuntimeMins $maxDeployTime -InstallationBehaviorType $InstallBehavior
                    }else{
                        Add-CMScriptDeploymentType -ApplicationName $BetaName -DeploymentTypeName $DeploymentType -ContentLocation $SourcePath -Force -Comment $Comment -InstallCommand $InstFileName -UninstallCommand $MSTName -AddDetectionClause $DetectClause -MaximumRuntimeMins $maxDeployTime -InstallationBehaviorType $InstallBehavior
                    }
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
            if((Get-Item $AppIcon).DirectoryName.ToUpper() -eq ($env:TEMP).ToUpper()){
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
    if(-not($sitecode.Contains(":"))){Set-Variable -Name sitecode -Value ($sitecode + ":") -Scope Global}
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
    Set-Variable -Name DetectionMeth -Value $ComboBoxDetection.SelectedItem -Scope Global
    Set-Variable -Name ProdCode -Value $TextBoxProdCode.Text -Scope Global
    Set-Variable -Name DetectExist -Value $RadioBtnDetectExist.Checked -Scope Global
    Set-Variable -Name DetectComp -Value $ComboBoxComparator.SelectedItem -Scope Global
    Set-Variable -Name ProdVersion -Value $TextBoxProdVersion.Text -Scope Global
    Set-Variable -Name Detect32on64 -Value $CheckBoxDetect32on64.Checked -Scope Global
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
    if($isScript){
        if($ProdCode -eq "" -or $ProdCode -eq $null){
            $OkHolder = ShowBox "Detection Method $DetectionMeth not valid." "Error" "Error"
            Return $false
        }
        if($DetectionMeth -eq "MSI" -and $ProdCode -notmatch '^[0-9a-fA-F{}-]+$'){
            $OkHolder = ShowBox "Product code not valid." "Error" "Error"
            Return $false
        }
        if(-not($DetectExist) -and ($ProdVersion -eq "" -or $ProdVersion -eq $null)){
            $OkHolder = ShowBox "Detection Method Version not valid." "Error" "Error"
            Return $false
        }
    }
    if($AddPCs -and ($PCNames -eq "" -or $PCNames -eq $null)){
        $OkHolder = ShowBox "Machine names not valid." "Error" "Error"
        Return $false
    }
    if($DoStepAD){
        if(-not(Get-Module -ListAvailable | ?{$_.Name -eq "ActiveDirectory"})){
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            if(-not(Get-Module -ListAvailable | ?{$_.Name -eq "ActiveDirectory"})){
                $OkHolder = ShowBox "Administrative Tools is required." "Error" "Error"
                Return $false
            }
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
    if($RefreshInterval -ne "Minutes" -and $RefreshInterval -ne "Hours" -and $RefreshInterval -ne "Days" -and $RefreshInterval -ne "Manual"){
        $OkHolder = ShowBox "RefreshInterval not valid in settings XML. Valid values are Minutes, Hours, Days, Manual." "Error" "Error"
        Return $false
    }
    if($RefreshInterval -ne "Manual"){
        $testDeci = Try{[decimal]$RefreshIntCount}Catch{0}
        if($testDeci -le 0){
            $OkHolder = ShowBox "RefreshIntCount not valid in settings XML. Must be a numeric value greater than 0." "Error" "Error"
            Return $false
        }
        if(($RefreshInterval -eq "Minutes" -and $testDeci -gt 59) -or ($RefreshInterval -eq "Hours" -and $testDeci -gt 23) -or ($RefreshInterval -eq "Days" -and $testDeci -gt 31)){
            $OkHolder = ShowBox "RefreshIntCount not valid in settings XML. Must be a numeric with maximum value per interval: Minutes-59, Hours-23, Days-31." "Error" "Error"
            Return $false
        }
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
param($customError="",[switch]$NoMain)
    if($Error[0] -ne $null -or $customError -ne ""){
        if($customError -ne ""){
            $ErrorMsg = $customError
        }else{
            $ErrorMsg = $Error[0].Exception
        }
        $OkHolder = ShowBox $ErrorMsg "Error" "Error"
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
    $StatusStripLabel.Text = "Loading"
    $StatusStrip.Update()
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
    $ComboBoxDetection.Enabled = $true
    $ComboBoxDetection.SelectedIndex = 0
    $TextBoxProdCode.Enabled = $true
    $TextBoxProdCode.Text = "{00000000-0000-0000-0000-000000000000}"
    $BrowseBtnDetectMSI.Enabled = $true
    $TextBoxProdVersion.Text = ""
    $RadioBtnDetectExist.Enabled = $true
    $RadioBtnDetectCompare.Enabled = $true
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
    $ComboBoxDetection.Enabled = $false
    $TextBoxProdCode.Enabled = $false
    $TextBoxProdCode.Text = ""
    $BrowseBtnDetectMSI.Enabled = $false
    $RadioBtnDetectExist.Enabled = $false
    $RadioBtnDetectExist.Checked = $true
    $RadioBtnDetectCompare.Enabled = $false
    $ComboBoxComparator.Enabled = $false
    $TextBoxProdVersion.Enabled = $false
    $TextBoxProdVersion.Text = ""
    $CheckBoxDetect32on64.Checked = $false
    $CheckBoxDetect32on64.Enabled = $false
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
    Set-Location $env:SystemDrive
}

Function New-Cat{
### This function creates a new Category in MECM when user clicks the New button ###
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
        Set-Location $env:SystemDrive
    }
    Return $NewCat
}

Function Add-FormObj{
### This function reduces excessive code by dynamically creating (simple) Form objects ###
param($fComponent, $fObj, $ParentObj, $x, $y, $xSize, $Txt=$null)
    if($fObj -eq $null){$DynamicObj = New-Object System.Windows.Forms.$fComponent}
    else{$DynamicObj = $fObj}

    $DynamicObj.Location = New-Object System.Drawing.Size($x,$y)
    if($xSize -eq 0){$DynamicObj.AutoSize = $True}
    else{$DynamicObj.Size = New-Object System.Drawing.Size($xSize,20)}
    if($Txt){$DynamicObj.Text = $Txt}
    $ParentObj.Controls.Add($DynamicObj)
}

#region################ Main Form (UI) block #####################################################
Function MainForm{
[void] [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.VisualBasic")

Import-Module (Join-Path $(Split-Path $env:SMS_ADMIN_UI_PATH) ConfigurationManager.psd1)

$Form = New-Object System.Windows.Forms.Form 
$Form.Text = $scriptName
$Form.Size = New-Object System.Drawing.Size(725,710) 
$Form.StartPosition = "CenterScreen"
$Form.FormBorderStyle = "FixedDialog"
$Form.MaximizeBox = $False
$Form.KeyPreview = $True
$Form.Add_KeyDown({if ($_.KeyCode -eq "Escape") {$Form.Close()}})
$AddappIco = $ThisScript.replace('.ps1','.ico')
if(Test-Path $AddappIco){$Form.Icon = New-Object System.Drawing.Icon($AddappIco)}

$MainMenu = New-Object System.Windows.Forms.MenuStrip
$MainMenu.BackColor = [System.Drawing.Color]::LightSteelBlue
$FileMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$FileMenu.Text = "&File"
$miRunning = New-Object System.Windows.Forms.ToolStripMenuItem
$miRunning.Text = "&$env:USERNAME"
$miRunning.Enabled = $false
$miRunAs = New-Object System.Windows.Forms.ToolStripMenuItem
$miRunAs.Text = "&Run As..."
$miRunAs.Add_Click({
    if((ShowBox "This will close the current window and relaunch with a RunAs dialog.`nContinue?" "Confirm" "Question" -YesNo) -eq "Yes"){
        $Form.Close()
        $Error.Clear()
        if($Dbug){Start-Process powershell.exe -Verb RunAs -WorkingDirectory $ScriptPath -ArgumentList ('-NoProfile -File "{0}" -Dbug' -f ($ThisScript))}
        else{Start-Process powershell.exe -Verb RunAs -WorkingDirectory $ScriptPath -ArgumentList ('-NoProfile -WindowStyle hidden -File "{0}" -Dbug' -f ($ThisScript))}
        ErrorChecker -NoMain
    }
})
$miSettings = New-Object System.Windows.Forms.ToolStripMenuItem
$miSettings.Text = "&Settings"
$miSettings.Add_Click({
    SettingsForm
    Reset-Form
})
$miQuit = New-Object System.Windows.Forms.ToolStripMenuItem
$miQuit.Text = "&Quit"
$miQuit.Add_Click({$Form.Close()})
$HelpMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$HelpMenu.Text = "&Help"
$miAbout = New-Object System.Windows.Forms.ToolStripMenuItem
$miAbout.Text = "&About"
$miAbout.Add_Click({$OkHolder = ShowBox $about "About" "Information"})
[void]$MainMenu.Items.Add($FileMenu)
[void]$FileMenu.DropDownItems.Add($miRunning)
[void]$FileMenu.DropDownItems.Add($miRunAs)
[void]$FileMenu.DropDownItems.Add($miSettings)
[void]$FileMenu.DropDownItems.Add($miQuit)
[void]$MainMenu.Items.Add($HelpMenu)
[void]$HelpMenu.DropDownItems.Add($miAbout)
$Form.Controls.Add($MainMenu)

Add-FormObj 'Label' $null $Form 10 30 0 "Package name:"
$TextBoxAppName = New-Object System.Windows.Forms.TextBox 
Add-FormObj 'Textbox' $TextBoxAppName $Form 10 50 260

$GroupBoxTaskOptions = New-Object System.Windows.Forms.GroupBox
$GroupBoxTaskOptions.Location = New-Object System.Drawing.Size(10,80)
$GroupBoxTaskOptions.Size = New-Object System.Drawing.Size(120,120)
$GroupBoxTaskOptions.Text = "Create:"
$Form.Controls.Add($GroupBoxTaskOptions)
$BoxFont = $GroupBoxTaskOptions.Font.Name
$BoxFontSize = $GroupBoxTaskOptions.Font.Size - 1

$CheckBoxSelectAll = New-Object System.Windows.Forms.CheckBox
$CheckBoxSelectAll.Font = New-Object System.Drawing.Font($BoxFont,$BoxFontSize)
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
Add-FormObj 'CheckBox' $CheckBoxSelectAll $GroupBoxTaskOptions 10 15 0 "Select All"

$CheckBoxADGroup = New-Object System.Windows.Forms.CheckBox
$CheckBoxADGroup.Font = New-Object System.Drawing.Font($BoxFont,$BoxFontSize)
$CheckBoxADGroup.add_Click({Set-FormToOptions})
Add-FormObj 'CheckBox' $CheckBoxADGroup $GroupBoxTaskOptions 20 33 0 "AD Group"

$CheckBoxCollection = New-Object System.Windows.Forms.CheckBox
$CheckBoxCollection.Font = New-Object System.Drawing.Font($BoxFont,$BoxFontSize)
$CheckBoxCollection.add_Click({Set-FormToOptions})
Add-FormObj 'CheckBox' $CheckBoxCollection $GroupBoxTaskOptions 20 49 0 "Collection"

$RadioBtnApp = New-Object System.Windows.Forms.RadioButton
$RadioBtnApp.Font = New-Object System.Drawing.Font($BoxFont,$BoxFontSize)
$RadioBtnApp.add_Click({Set-FormToApp})
Add-FormObj 'RadioButton' $RadioBtnApp $GroupBoxTaskOptions 20 65 0 "Application"

$RadioBtnPkg = New-Object System.Windows.Forms.RadioButton
$RadioBtnPkg.Font = New-Object System.Drawing.Font($BoxFont,$BoxFontSize)
$RadioBtnPkg.add_Click({
    $OkHolder = ShowBox "This tool was designed primarily for App Model.`nAlthough it will still create a standardized Package, most of the details in MECM will be empty."
    Set-FormToPkg
})
Add-FormObj 'RadioButton' $RadioBtnPkg $GroupBoxTaskOptions 20 81 0 "Package"

$CheckBoxDeployment = New-Object System.Windows.Forms.CheckBox
$CheckBoxDeployment.Font = New-Object System.Drawing.Font($BoxFont,$BoxFontSize)
Add-FormObj 'CheckBox' $CheckBoxDeployment $GroupBoxTaskOptions 20 97 0 "Deployment"

$GroupBoxDepType = New-Object System.Windows.Forms.GroupBox
$GroupBoxDepType.Location = New-Object System.Drawing.Size(150,80)
$GroupBoxDepType.Size = New-Object System.Drawing.Size(120,120)
$GroupBoxDepType.Text = "Deployment Type:"
$Form.Controls.Add($GroupBoxDepType)

$RadioBtnManual = New-Object System.Windows.Forms.RadioButton
$RadioBtnManual.add_Click({Set-FormToNone})
Add-FormObj 'RadioButton' $RadioBtnManual $GroupBoxDepType 20 15 0 "Manual"

$RadioBtnMSI = New-Object System.Windows.Forms.RadioButton
$RadioBtnMSI.add_Click({Set-FormToMSI})
Add-FormObj 'RadioButton' $RadioBtnMSI $GroupBoxDepType 20 35 0 "MSI Installer"

$CheckBoxTransform = New-Object System.Windows.Forms.CheckBox
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
Add-FormObj 'CheckBox' $CheckBoxTransform $GroupBoxDepType 20 55 0 "Transform"

$RadioBtnAppV = New-Object System.Windows.Forms.RadioButton
$RadioBtnAppV.add_Click({Set-FormToAppV})
Add-FormObj 'RadioButton' $RadioBtnAppV $GroupBoxDepType 20 75 0 "App-V 5"

$RadioBtnScript = New-Object System.Windows.Forms.RadioButton
$RadioBtnScript.add_Click({Set-FormToScript})
Add-FormObj 'RadioButton' $RadioBtnScript $GroupBoxDepType 20 95 0 "Script"

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

Add-FormObj 'Label' $null $Form 10 210 0 "Source:"
$LabelSourcePath = New-Object System.Windows.Forms.Label
Add-FormObj 'Label' $LabelSourcePath $Form 10 230 0

$TextBoxInstFile = New-Object System.Windows.Forms.TextBox 
Add-FormObj 'Textbox' $TextBoxInstFile $Form 10 250 260

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
Add-FormObj 'Textbox' $TextBoxTransform $Form 10 275 260

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
$CheckBoxx64.add_Click({
    if($CheckBoxx64.Checked){
        $OkHolder = ShowBox "This will create 2 Deployment Types within the same Application. But Operating System Requirements must be set manually."
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
Add-FormObj 'CheckBox' $CheckBoxx64 $Form 10 300 0 "Create 2nd Deployment Type for x64"

$TextBoxMSIx64 = New-Object System.Windows.Forms.TextBox 
Add-FormObj 'Textbox' $TextBoxMSIx64 $Form 10 320 260

$BrowseButtonMSIx64 = New-Object System.Windows.Forms.Button
$BrowseButtonMSIx64.Location = New-Object System.Drawing.Size(275,318)
$BrowseButtonMSIx64.AutoSize = $True
$BrowseButtonMSIx64.Text = "Browse"
$BrowseButtonMSIx64.Add_Click({Pop-FileName (Get-FileName "*.msi" "Windows Installer Package") $TextBoxMSIx64})
$Form.Controls.Add($BrowseButtonMSIx64)

$TextBoxTransformx64 = New-Object System.Windows.Forms.TextBox 
Add-FormObj 'Textbox' $TextBoxTransformx64 $Form 10 345 260

$BrowseButtonMSTx64 = New-Object System.Windows.Forms.Button
$BrowseButtonMSTx64.Location = New-Object System.Drawing.Size(275,343)
$BrowseButtonMSTx64.AutoSize = $True
$BrowseButtonMSTx64.Text = "Browse"
$BrowseButtonMSTx64.Add_Click({Pop-FileName (Get-FileName "*.mst" "MST File") $TextBoxTransformx64})
$Form.Controls.Add($BrowseButtonMSTx64)

$GroupBoxDetection = New-Object System.Windows.Forms.GroupBox
$GroupBoxDetection.Location = New-Object System.Drawing.Size(360,250)
$GroupBoxDetection.Size = New-Object System.Drawing.Size(340,125)
$GroupBoxDetection.Text = "Detection Method:"
$Form.Controls.Add($GroupBoxDetection)

$ComboBoxDetection = New-Object System.Windows.Forms.ComboBox
"MSI","File","Registry" | %{$ComboBoxDetection.Items.add("$_") | Out-Null}
$ComboBoxDetection.DropDownStyle = 'DropDownList'
$ComboBoxDetection.add_SelectedIndexChanged({
    switch($ComboBoxDetection.SelectedItem){
        'MSI'{
            $TextBoxProdCode.Text = "{00000000-0000-0000-0000-000000000000}"
            $BrowseBtnDetectMSI.Enabled = $true
            $CheckBoxDetect32on64.Checked = $false
            $CheckBoxDetect32on64.Enabled = $false
        }
        'File'{
            $TextBoxProdCode.Text = ""
            $BrowseBtnDetectMSI.Enabled = $true
            $CheckBoxDetect32on64.Enabled = $true
        }
        'Registry'{
            if(-not($ConfirmOnce)){Set-Variable -Name ConfirmOnce -Value (ShowBox "Currently this tool will set property to String if Exists, otherwise will use Version. Modify if needed in MECM.") -Scope Global}
            $TextBoxProdCode.Text = "HKLM:\"
            $BrowseBtnDetectMSI.Enabled = $false
            $CheckBoxDetect32on64.Enabled = $true
        }
    }
})
Add-FormObj 'ComboBox' $ComboBoxDetection $GroupBoxDetection 10 20 70

$TextBoxProdCode = New-Object System.Windows.Forms.TextBox 
Add-FormObj 'Textbox' $TextBoxProdCode $GroupBoxDetection 10 45 240

$BrowseBtnDetectMSI = New-Object System.Windows.Forms.Button
$BrowseBtnDetectMSI.Location = New-Object System.Drawing.Size(255,43)
$BrowseBtnDetectMSI.AutoSize = $True
$BrowseBtnDetectMSI.Text = "Browse"
$BrowseBtnDetectMSI.Add_Click({
    switch($ComboBoxDetection.SelectedItem){
        "MSI"{
            $MSIProps = Get-MSIProps (Get-FileName "*.msi" "Windows Installer Package")
            $TextBoxProdCode.Text = $MSIProps.ProductCode
            $TextBoxProdVersion.Text = $MSIProps.ProductVersion
        }
        "File"{
            $TextBoxProdCode.Text = Get-FileName "*.*" "All files"
        }
    }
})
$GroupBoxDetection.Controls.Add($BrowseBtnDetectMSI)

$RadioBtnDetectExist = New-Object System.Windows.Forms.RadioButton
$RadioBtnDetectExist.add_Click({
if($RadioBtnDetectExist.Checked){
    $ComboBoxComparator.Enabled = $false
    $TextBoxProdVersion.Enabled = $false
}
})
Add-FormObj 'RadioButton' $RadioBtnDetectExist $GroupBoxDetection 10 75 0 "Exists"

$RadioBtnDetectCompare = New-Object System.Windows.Forms.RadioButton
$RadioBtnDetectCompare.add_Click({
if($RadioBtnDetectCompare.Checked){
    $ComboBoxComparator.Enabled = $true
    $TextBoxProdVersion.Enabled = $true
}
})
Add-FormObj 'RadioButton' $RadioBtnDetectCompare $GroupBoxDetection 70 75 0 " "

$ComboBoxComparator = New-Object System.Windows.Forms.ComboBox
"IsEquals","NotEquals","GreaterEquals","GreaterThan","LessEquals","LessThan" | %{$ComboBoxComparator.Items.add("$_") | Out-Null}
$ComboBoxComparator.SelectedIndex = 2
Add-FormObj 'ComboBox' $ComboBoxComparator $GroupBoxDetection 95 75 100

$TextBoxProdVersion = New-Object System.Windows.Forms.TextBox
Add-FormObj 'Textbox' $TextBoxProdVersion $GroupBoxDetection 200 75 90

$CheckBoxDetect32on64 = New-Object System.Windows.Forms.CheckBox
Add-FormObj 'CheckBox' $CheckBoxDetect32on64 $GroupBoxDetection 10 100 0 "associate with a 32-bit application on 64-bit systems"

$ListViewAdmCategory = New-Object System.Windows.Forms.ListView
$ListViewAdmCategory.Location = New-Object System.Drawing.Point(10,385)
$ListViewAdmCategory.Size = New-Object System.Drawing.Size(165,100)
$ListViewAdmCategory.View = 'Details'
$ListViewAdmCategory.CheckBoxes = $true
$LVcolAdmCategory = $ListViewAdmCategory.Columns.add('MECM Admin Categories')
$LVcolAdmCategory.Width = 144
$Form.Controls.Add($ListViewAdmCategory)

$NewAdmCatButton = New-Object System.Windows.Forms.Button
$NewAdmCatButton.Location = New-Object System.Drawing.Size(10,490)
$NewAdmCatButton.AutoSize = $True
$NewAdmCatButton.Text = "New"
$NewAdmCatButton.Add_Click({
    $NewCategory = New-Cat "AppCategories"
    if($NewCategory -ne "" -and $NewCategory -ne $null){Reset-Cats}
})
$Form.Controls.Add($NewAdmCatButton)

$GroupBoxAppCatalog = New-Object System.Windows.Forms.GroupBox
$GroupBoxAppCatalog.Location = New-Object System.Drawing.Size(190,375)
$GroupBoxAppCatalog.Size = New-Object System.Drawing.Size(510,170)
$GroupBoxAppCatalog.Text = "Application Catalog:"
$Form.Controls.Add($GroupBoxAppCatalog)

Add-FormObj 'Label' $null $GroupBoxAppCatalog 10 20 0 "Description:"
$TextBoxDesc = New-Object System.Windows.Forms.RichTextBox 
$TextBoxDesc.Location = New-Object System.Drawing.Size(10,40) 
$TextBoxDesc.Size = New-Object System.Drawing.Size(490,40)
$TextBoxDesc.Multiline = $true
$TextBoxDesc.ScrollBars = "Vertical"
$GroupBoxAppCatalog.Controls.Add($TextBoxDesc)

Add-FormObj 'Label' $null $GroupBoxAppCatalog 10 90 0 "Category:"
$ComboBoxCategory = New-Object System.Windows.Forms.ComboBox
Add-FormObj 'ComboBox' $ComboBoxCategory $GroupBoxAppCatalog 80 88 180

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

Add-FormObj 'Label' $null $GroupBoxAppCatalog 10 115 0 "Keywords:"
$TextBoxKeywords = New-Object System.Windows.Forms.TextBox 
Add-FormObj 'Textbox' $TextBoxKeywords $GroupBoxAppCatalog 80 113 260

Add-FormObj 'Label' $null $GroupBoxAppCatalog 10 140 0 "Icon File:"
$TextBoxIcon = New-Object System.Windows.Forms.TextBox 
Add-FormObj 'Textbox' $TextBoxIcon $GroupBoxAppCatalog 80 138 340

$BrowseButtonIcon = New-Object System.Windows.Forms.Button
$BrowseButtonIcon.Location = New-Object System.Drawing.Size(425,136)
$BrowseButtonIcon.AutoSize = $True
$BrowseButtonIcon.Text = "Browse"
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
            $PictureBoxIcon.Image = [System.Drawing.Image]::FromFile($NewIcon)
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
$GroupBoxAppCatalog.Controls.Add($BrowseButtonIcon)

$PictureBoxIcon = New-Object Windows.Forms.PictureBox
$PictureBoxIcon.Location = New-Object System.Drawing.Size(415,90)
$PictureBoxIcon.Size = New-Object System.Drawing.Size(30,30)
$PictureBoxIcon.SizeMode = "StretchImage"
$GroupBoxAppCatalog.Controls.Add($PictureBoxIcon)

$CheckBoxAddPCs = New-Object System.Windows.Forms.CheckBox
$CheckBoxAddPCs.add_Click({
    if($CheckBoxAddPCs.Checked){
        $TextBoxAddPCs.Enabled = $true
        $TextBoxAddPCs.Text = $TestMachines.($env:USERNAME)
	}else{
        $TextBoxAddPCs.Text = ""
        $TextBoxAddPCs.Enabled = $false
    }
})
Add-FormObj 'CheckBox' $CheckBoxAddPCs $Form 10 560 0 "Add machine(s) to deployment group:"

$TextBoxAddPCs = New-Object System.Windows.Forms.TextBox 
Add-FormObj 'Textbox' $TextBoxAddPCs $Form 230 559 330

$ProgressBar = New-Object System.Windows.Forms.ProgressBar
$ProgressBar.Minimum = 0
$ProgressBar.Maximum = 100
Add-FormObj 'ProgressBar' $ProgressBar $Form 10 590 690

$RunButton = New-Object System.Windows.Forms.Button
$RunButton.Location = New-Object System.Drawing.Size(210,620)
$RunButton.Size = New-Object System.Drawing.Size(130,23)
$RunButton.Text = "Create"
$RunButton.Add_Click({
	Import-Settings
    Set-Vars
    if(Check-Input){
        $RunButton.Enabled = $false
        $ResetButton.Enabled = $false
        $QuitButton.Enabled = $false
        $StatusStripLabel.Text = "Running"
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

#region################ Settings Form block ######################################################
Function SettingsForm{
if(-not(Import-Settings)){
#first run - set defaults
    $SelectAll = $true
    $ADPath = 'OU=,DC=,DC=,DC='
    $ADGroupScope = 'DomainLocal'
    $ADDescription = 'Software Distribution Group'
    $CollectionFolder = 'DeviceCollection\'
    $RefreshInterval = 'Hours'
    $RefreshIntCount = 1
    $AllowTaskSeqInstall = $true
    $PrestageDP = 'AutoDownload'
    $AllowBranchCache = $false
    $InstallBehavior = 'InstallForSystem'
    $maxDeployTime = 120
    $SendWakeup = $true
    $UserNotification = 'DisplaySoftwareCenterOnly'
    $PkgDelimiter = '_'
    $MSIargs = 'REBOOT=ReallySuppress ALLUSERS=1 /qn'
    $UninstallArgs = 'REBOOT=ReallySuppress /qn'
    $LogOption = 'l*v'
    $ScriptInstallCMD = 'Deploy-Application.exe'
    $ScriptUninstallCMD = 'Deploy-Application.exe -DeploymentType "Uninstall"'
}

$SettingsForm = New-Object System.Windows.Forms.Form 
$SettingsForm.Text = "$scriptName Settings"
$Screen = [System.Windows.Forms.Screen]::PrimaryScreen 
$SettingsForm.Size = New-Object System.Drawing.Size(400,(($Screen.Bounds.Height)*.7)) 
$SettingsForm.StartPosition = "CenterScreen"
$SettingsForm.FormBorderStyle = "FixedDialog"
$SettingsForm.AutoScroll = $True
$SettingsForm.MaximizeBox = $False
$SettingsForm.KeyPreview = $True
$SettingsForm.Add_KeyDown({if ($_.KeyCode -eq "Escape") {$SettingsForm.Close()}})

$SetTooltip = New-Object System.Windows.Forms.ToolTip

$LabelOptional = New-Object System.Windows.Forms.Label
$LabelOptional.Forecolor = 'Gray'
Add-FormObj 'Label' $LabelOptional $SettingsForm 10 10 0 "*Optional. If not desired, leave blank."

$SetGroupBoxCreateComponents = New-Object System.Windows.Forms.GroupBox
$SetGroupBoxCreateComponents.Location = New-Object System.Drawing.Size(10,50)
$SetGroupBoxCreateComponents.Size = New-Object System.Drawing.Size(350,95)
$SetGroupBoxCreateComponents.Text = "Create Components (default):"
$SettingsForm.Controls.Add($SetGroupBoxCreateComponents)
$BoxFont = $SetGroupBoxCreateComponents.Font.Name
$BoxFontSize = $SetGroupBoxCreateComponents.Font.Size - 1

$SetCheckBoxSelectAll = New-Object System.Windows.Forms.CheckBox
$SetCheckBoxSelectAll.Font = New-Object System.Drawing.Font($BoxFont,$BoxFontSize)
$SetCheckBoxSelectAll.Checked = $SelectAll
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
$SetCheckBoxSelectAll.add_MouseHover({$SetTooltip.SetToolTip($this,"Create all components (Active Directory group, Collection, Application, and Deployment)")})
Add-FormObj 'CheckBox' $SetCheckBoxSelectAll $SetGroupBoxCreateComponents 10 20 0 "Select All"

$SetCheckBoxCreateAD = New-Object System.Windows.Forms.CheckBox
$SetCheckBoxCreateAD.Font = New-Object System.Drawing.Font($BoxFont,$BoxFontSize)
$SetCheckBoxCreateAD.Checked = $CreateAD
if($SetCheckBoxSelectAll.Checked){$SetCheckBoxCreateAD.Enabled = $false}
$SetCheckBoxCreateAD.add_MouseHover({$SetTooltip.SetToolTip($this,"Create an Active Directory group for the package")})
Add-FormObj 'CheckBox' $SetCheckBoxCreateAD $SetGroupBoxCreateComponents 20 38 0 "AD Group"

$SetCheckBoxCreateCollection = New-Object System.Windows.Forms.CheckBox
$SetCheckBoxCreateCollection.Font = New-Object System.Drawing.Font($BoxFont,$BoxFontSize)
$SetCheckBoxCreateCollection.Checked = $CreateCollection
if($SetCheckBoxSelectAll.Checked){$SetCheckBoxCreateCollection.Enabled = $false}
$SetCheckBoxCreateCollection.add_MouseHover({$SetTooltip.SetToolTip($this,"Create a device Collection`nIf AD group is enabled this will also create a query rule linking the two")})
Add-FormObj 'CheckBox' $SetCheckBoxCreateCollection $SetGroupBoxCreateComponents 20 54 0 "Collection"

$SetCheckBoxCreateDeployment = New-Object System.Windows.Forms.CheckBox
$SetCheckBoxCreateDeployment.Font = New-Object System.Drawing.Font($BoxFont,$BoxFontSize)
$SetCheckBoxCreateDeployment.Checked = $CreateDeployment
if($SetCheckBoxSelectAll.Checked){$SetCheckBoxCreateDeployment.Enabled = $false}
$SetCheckBoxCreateDeployment.add_Click({
    if($SetCheckBoxCreateDeployment.Checked){$SetCheckBoxCreateCollection.Checked = $true}
})
$SetCheckBoxCreateDeployment.add_MouseHover({$SetTooltip.SetToolTip($this,"Create a Deployment to the Collection`nCollection must be enabled")})
Add-FormObj 'CheckBox' $SetCheckBoxCreateDeployment $SetGroupBoxCreateComponents 20 70 0 "Deployment"

#AD
$SetGroupBoxADoptions = New-Object System.Windows.Forms.GroupBox
$SetGroupBoxADoptions.Location = New-Object System.Drawing.Size(10,160)
$SetGroupBoxADoptions.Size = New-Object System.Drawing.Size(350,125)
$SetGroupBoxADoptions.Text = "Active Directory options:"
$SettingsForm.Controls.Add($SetGroupBoxADoptions)

Add-FormObj 'Label' $null $SetGroupBoxADoptions 10 20 0 "Domain:"
$SetTextBoxADDomain = New-Object System.Windows.Forms.TextBox 
$SetTextBoxADDomain.add_MouseHover({$SetTooltip.SetToolTip($this,"Active Directory domain where the Distribution groups will be created")})
Add-FormObj 'Textbox' $SetTextBoxADDomain $SetGroupBoxADoptions 240 18 100 $ADDomain

Add-FormObj 'Label' $null $SetGroupBoxADoptions 10 45 0 "OU:"
$SetTextBoxADPath = New-Object System.Windows.Forms.TextBox
$SetTextBoxADPath.add_MouseHover({$SetTooltip.SetToolTip($this,"The full path to the OU where the groups will be created. In format:`nOU=,OU=,DC=,DC=,DC=")})
Add-FormObj 'Textbox' $SetTextBoxADPath $SetGroupBoxADoptions 160 43 180 $ADPath

Add-FormObj 'Label' $null $SetGroupBoxADoptions 10 70 0 "Group Scope:"
$SetComboBoxADGroupScope = New-Object System.Windows.Forms.ComboBox
'DomainLocal','Global','Universal' | %{$SetComboBoxADGroupScope.Items.add($_) | Out-Null}
for($i=0;$i-le $SetComboBoxADGroupScope.Items.Count-1;$i++){
    if($SetComboBoxADGroupScope.Items[$i] -eq $ADGroupScope){$SetComboBoxADGroupScope.SelectedIndex = $i}
}
$SetComboBoxADGroupScope.DropDownStyle = 'DropDownList'
$SetComboBoxADGroupScope.Add_Mousewheel({$_.Handled = $true})
$SetComboBoxADGroupScope.add_MouseHover({$SetTooltip.SetToolTip($this,"The Security type defined for the AD group")})
Add-FormObj 'ComboBox' $SetComboBoxADGroupScope $SetGroupBoxADoptions 240 68 100

$SetLabelADDescription = New-Object System.Windows.Forms.Label
$SetLabelADDescription.Forecolor = 'Gray'
Add-FormObj 'Label' $SetLabelADDescription $SetGroupBoxADoptions 10 95 0 "Description*:"
$SetTextBoxADDescription = New-Object System.Windows.Forms.TextBox
$SetTextBoxADDescription.add_MouseHover({$SetTooltip.SetToolTip($this,"Text entered in the Description field for the AD group")})
Add-FormObj 'Textbox' $SetTextBoxADDescription $SetGroupBoxADoptions 160 93 180 $ADDescription

#MECM
$SetGroupBoxMECMoptions = New-Object System.Windows.Forms.GroupBox
$SetGroupBoxMECMoptions.Location = New-Object System.Drawing.Size(10,300)
$SetGroupBoxMECMoptions.Size = New-Object System.Drawing.Size(350,425)
$SetGroupBoxMECMoptions.Text = "MECM options:"
$SettingsForm.Controls.Add($SetGroupBoxMECMoptions)

Add-FormObj 'Label' $null $SetGroupBoxMECMoptions 10 20 0 "Sitecode:"
$SetTextBoxSitecode = New-Object System.Windows.Forms.TextBox
$SetTextBoxSitecode.add_MouseHover({$SetTooltip.SetToolTip($this,"MECM site code")})
Add-FormObj 'Textbox' $SetTextBoxSitecode $SetGroupBoxMECMoptions 300 18 40 $Sitecode

Add-FormObj 'Label' $null $SetGroupBoxMECMoptions 10 45 0 "Limiting Collection:"
$SetTextBoxLimitingCollection = New-Object System.Windows.Forms.TextBox
$SetTextBoxLimitingCollection.add_MouseHover({$SetTooltip.SetToolTip($this,"The Limiting Collection to be used for the Device Collections")}) 
Add-FormObj 'Textbox' $SetTextBoxLimitingCollection $SetGroupBoxMECMoptions 160 43 180 $LimitingCollection

Add-FormObj 'Label' $null $SetGroupBoxMECMoptions 10 70 0 "Collection Folder:"
$SetTextBoxCollectionFolder = New-Object System.Windows.Forms.TextBox
$SetTextBoxCollectionFolder.add_MouseHover({$SetTooltip.SetToolTip($this,"The folder in MECM under Device Collections that the new Collections will be moved to`nTool will create folder if it doesn’t exist")})
Add-FormObj 'Textbox' $SetTextBoxCollectionFolder $SetGroupBoxMECMoptions 160 68 180 $CollectionFolder

Add-FormObj 'Label' $null $SetGroupBoxMECMoptions 10 95 0 "Refresh Interval:"
$SetComboBoxRefreshInterval = New-Object System.Windows.Forms.ComboBox
'Minutes','Hours','Days','Manual' | %{$SetComboBoxRefreshInterval.Items.add($_) | Out-Null}
for($i=0;$i-le $SetComboBoxRefreshInterval.Items.Count-1;$i++){
    if($SetComboBoxRefreshInterval.Items[$i] -eq $RefreshInterval){$SetComboBoxRefreshInterval.SelectedIndex = $i}
}
$SetComboBoxRefreshInterval.DropDownStyle = 'DropDownList'
$SetComboBoxRefreshInterval.add_SelectedIndexChanged({
    $SetComboBoxRefreshIntCount.Items.Clear()
    switch($SetComboBoxRefreshInterval.SelectedItem){
        'Minutes'{$MaxInt = 59}
        'Hours'{$MaxInt = 23}
        'Days'{$MaxInt = 31}
        'Manual'{$MaxInt = 0
            $SetComboBoxRefreshIntCount.Items.add($MaxInt) | Out-Null
        }
    }
    for($i=1;$i-le $MaxInt;$i++){$SetComboBoxRefreshIntCount.Items.add($i) | Out-Null}
    $SetComboBoxRefreshIntCount.SelectedIndex = 0
})
$SetComboBoxRefreshInterval.Add_Mousewheel({$_.Handled = $true})
$SetComboBoxRefreshInterval.add_MouseHover({$SetTooltip.SetToolTip($this,"The interval type used to refresh the Collection")})
Add-FormObj 'ComboBox' $SetComboBoxRefreshInterval $SetGroupBoxMECMoptions 210 93 70
Add-FormObj 'Label' $null $SetGroupBoxMECMoptions 285 95 0 ":"
$SetComboBoxRefreshIntCount = New-Object System.Windows.Forms.ComboBox
switch($SetComboBoxRefreshInterval.SelectedItem){
    'Minutes'{$MaxInt = 59}
    'Hours'{$MaxInt = 23}
    'Days'{$MaxInt = 31}
    'Manual'{$MaxInt = 0
        $SetComboBoxRefreshIntCount.Items.add($MaxInt) | Out-Null
    }
}
for($i=1;$i-le $MaxInt;$i++){
	$SetComboBoxRefreshIntCount.Items.add($i) | Out-Null
    if($i -eq $RefreshIntCount){$SetComboBoxRefreshIntCount.SelectedIndex = $i-1}
}
$SetComboBoxRefreshIntCount.DropDownStyle = 'DropDownList'
$SetComboBoxRefreshIntCount.Add_Mousewheel({if(-not($SetComboBoxRefreshIntCount.DroppedDown)){$_.Handled = $true}})
$SetComboBoxRefreshIntCount.add_MouseHover({$SetTooltip.SetToolTip($this,"The count used in conjunction with the Interval type")})
Add-FormObj 'ComboBox' $SetComboBoxRefreshIntCount $SetGroupBoxMECMoptions 300 93 40

Add-FormObj 'Label' $null $SetGroupBoxMECMoptions 10 120 0 "Application Folder:"
$SetTextBoxApplicationFolder = New-Object System.Windows.Forms.TextBox
$SetTextBoxApplicationFolder.add_MouseHover({$SetTooltip.SetToolTip($this,"The folder in MECM that new Applications or Packages will be moved to`nTool will create folder if it doesn’t exist")})
Add-FormObj 'Textbox' $SetTextBoxApplicationFolder $SetGroupBoxMECMoptions 160 118 180 $ApplicationFolder

$SetLabelPkgPrefix = New-Object System.Windows.Forms.Label
$SetLabelPkgPrefix.Forecolor = 'Gray'
Add-FormObj 'Label' $SetLabelPkgPrefix $SetGroupBoxMECMoptions 10 145 0 "App Name Prefix*:"
$SetTextBoxPkgPrefix = New-Object System.Windows.Forms.TextBox
$SetTextBoxPkgPrefix.add_MouseHover({$SetTooltip.SetToolTip($this,"Text to prefix to the Package Name in MECM")})
Add-FormObj 'Textbox' $SetTextBoxPkgPrefix $SetGroupBoxMECMoptions 240 143 100 $PkgPrefix

$SetCheckBoxAllowTaskSeqInstall = New-Object System.Windows.Forms.CheckBox
$SetCheckBoxAllowTaskSeqInstall.CheckAlign = "TopRight"
$SetCheckBoxAllowTaskSeqInstall.Checked = $AllowTaskSeqInstall
$SetCheckBoxAllowTaskSeqInstall.add_MouseHover({$SetTooltip.SetToolTip($this,"Application setting`nAllow this application to be installed from the Install Application task sequence action without being deployed")})
Add-FormObj 'CheckBox' $SetCheckBoxAllowTaskSeqInstall $SetGroupBoxMECMoptions 10 170 330 "Allow Task Sequence"

Add-FormObj 'Label' $null $SetGroupBoxMECMoptions 10 195 0 "Prestaged Distribution Point:"
$SetComboBoxPrestageDP = New-Object System.Windows.Forms.ComboBox
'AutoDownload','DeltaCopy','NoDownload' | %{$SetComboBoxPrestageDP.Items.add($_) | Out-Null}
for($i=0;$i-le $SetComboBoxPrestageDP.Items.Count-1;$i++){
    if($SetComboBoxPrestageDP.Items[$i] -eq $PrestageDP){$SetComboBoxPrestageDP.SelectedIndex = $i}
}
$SetComboBoxPrestageDP.DropDownStyle = 'DropDownList'
$SetComboBoxPrestageDP.Add_Mousewheel({$_.Handled = $true})
$SetComboBoxPrestageDP.add_MouseHover({$SetTooltip.SetToolTip($this,"Application Distribution setting. Prestaged distribution point.`nAutomatically download content when the packages are assigned to distribution points,`nDownload only content changes to the distribution point,`nor Manually copy the content in this package to the distribution point")})
Add-FormObj 'ComboBox' $SetComboBoxPrestageDP $SetGroupBoxMECMoptions 240 193 100

Add-FormObj 'Label' $null $SetGroupBoxMECMoptions 10 220 0 "Distribution Group:"
$SetTextBoxDPGroup = New-Object System.Windows.Forms.TextBox
$SetTextBoxDPGroup.add_MouseHover({$SetTooltip.SetToolTip($this,"The Distribution Group used to distribute content to`nMust use a pre-existing group and not an individual DP")})
Add-FormObj 'Textbox' $SetTextBoxDPGroup $SetGroupBoxMECMoptions 160 218 180 $DPGroup

$SetCheckBoxAllowBranchCache = New-Object System.Windows.Forms.CheckBox
$SetCheckBoxAllowBranchCache.CheckAlign = "TopRight"
$SetCheckBoxAllowBranchCache.Checked = $AllowBranchCache
$SetCheckBoxAllowBranchCache.add_MouseHover({$SetTooltip.SetToolTip($this,"Application Deployment Type setting`nAllow clients to share content with other clients on the same subnet")})
Add-FormObj 'CheckBox' $SetCheckBoxAllowBranchCache $SetGroupBoxMECMoptions 10 245 330 "Branch Cache"

Add-FormObj 'Label' $null $SetGroupBoxMECMoptions 10 270 0 "Install Behavior:"
$SetComboBoxInstallBehavior = New-Object System.Windows.Forms.ComboBox
'InstallForUser','InstallForSystem','InstallForSystemIfResourceIsDeviceOtherwiseInstallForUser' | %{$SetComboBoxInstallBehavior.Items.add($_) | Out-Null}
for($i=0;$i-le $SetComboBoxInstallBehavior.Items.Count-1;$i++){
    if($SetComboBoxInstallBehavior.Items[$i] -eq $InstallBehavior){$SetComboBoxInstallBehavior.SelectedIndex = $i}
}
$SetComboBoxInstallBehavior.DropDownStyle = 'DropDownList'
$SetComboBoxInstallBehavior.Add_Mousewheel({$_.Handled = $true})
$SetComboBoxInstallBehavior.add_MouseHover({$SetTooltip.SetToolTip($this,"Application Deployment Type setting`nInstall Behavior")})
Add-FormObj 'ComboBox' $SetComboBoxInstallBehavior $SetGroupBoxMECMoptions 160 268 180

Add-FormObj 'Label' $null $SetGroupBoxMECMoptions 10 295 0 "Maximum run time (minutes):"
$minmaxDeployTime = 15
$maxmaxDeployTime = 720
$SetTextBoxmaxDeployTime = New-Object System.Windows.Forms.TextBox 
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
$SetTextBoxmaxDeployTime.add_MouseHover({$SetTooltip.SetToolTip($this,"Application Deployment Type setting`nMaximum allowed run time (minutes)")})
Add-FormObj 'TextBox' $SetTextBoxmaxDeployTime $SetGroupBoxMECMoptions 300 293 40 $maxDeployTime

$SetTrackBarmaxDeployTime = New-Object System.Windows.Forms.TrackBar
$SetTrackBarmaxDeployTime.Location = New-Object System.Drawing.Size(10,315)
$SetTrackBarmaxDeployTime.AutoSize = $False
$SetTrackBarmaxDeployTime.Size = New-Object System.Drawing.Size(330,25)
$SetTrackBarmaxDeployTime.Orientation = “Horizontal”
$SetTrackBarmaxDeployTime.TickFrequency = 15
$SetTrackBarmaxDeployTime.LargeChange = 15
$SetTrackBarmaxDeployTime.SmallChange = 5
$SetTrackBarmaxDeployTime.TickStyle = “TopLeft”
$SetTrackBarmaxDeployTime.SetRange($minmaxDeployTime, $maxmaxDeployTime)
$SetTrackBarmaxDeployTime.Value = $maxDeployTime
$SetTrackBarmaxDeployTime.add_ValueChanged({$SetTextBoxmaxDeployTime.Text = $SetTrackBarmaxDeployTime.Value})
$SetTrackBarmaxDeployTime.Add_Mousewheel({$_.Handled = $true})
$SetGroupBoxMECMoptions.Controls.Add($SetTrackBarmaxDeployTime)

$SetCheckBoxSendWakeup = New-Object System.Windows.Forms.CheckBox
$SetCheckBoxSendWakeup.CheckAlign = "TopRight"
$SetCheckBoxSendWakeup.Checked = $SendWakeup
$SetCheckBoxSendWakeup.add_MouseHover({$SetTooltip.SetToolTip($this,"Application Deployment setting`nSend wake-up packets")})
Add-FormObj 'CheckBox' $SetCheckBoxSendWakeup $SetGroupBoxMECMoptions 10 345 330 "Send Wake-up"

Add-FormObj 'Label' $null $SetGroupBoxMECMoptions 10 370 0 "User Notification:"
$SetComboBoxUserNotification = New-Object System.Windows.Forms.ComboBox
'DisplayAll','DisplaySoftwareCenterOnly','HideAll' | %{$SetComboBoxUserNotification.Items.add($_) | Out-Null}
for($i=0;$i-le $SetComboBoxUserNotification.Items.Count-1;$i++){
    if($SetComboBoxUserNotification.Items[$i] -eq $UserNotification){$SetComboBoxUserNotification.SelectedIndex = $i}
}
$SetComboBoxUserNotification.DropDownStyle = 'DropDownList'
$SetComboBoxUserNotification.Add_Mousewheel({$_.Handled = $true})
$SetComboBoxUserNotification.add_MouseHover({$SetTooltip.SetToolTip($this,"Application Deployment setting. User notifications`nDisplay in Software Center and show all notifications,`nDisplay in Software Center and only show notifications for computer restarts,`nor Hide in Software Center and all notifications")})
Add-FormObj 'ComboBox' $SetComboBoxUserNotification $SetGroupBoxMECMoptions 160 368 180

$SetLabelPkgrTestCollection = New-Object System.Windows.Forms.Label
$SetLabelPkgrTestCollection.Forecolor = 'Gray'
Add-FormObj 'Label' $SetLabelPkgrTestCollection $SetGroupBoxMECMoptions 10 395 0 "Test Collection*:"
$SetTextBoxPkgrTestCollection = New-Object System.Windows.Forms.TextBox
$SetTextBoxPkgrTestCollection.add_MouseHover({$SetTooltip.SetToolTip($this,"Will create an additional Available deployment to this Collection`nThis is intended to be used for package testing")})
Add-FormObj 'Textbox' $SetTextBoxPkgrTestCollection $SetGroupBoxMECMoptions 160 393 180 $PkgrTestCollection

#Installer
$SetGroupBoxPKGoptions = New-Object System.Windows.Forms.GroupBox
$SetGroupBoxPKGoptions.Location = New-Object System.Drawing.Size(10,740)
$SetGroupBoxPKGoptions.Size = New-Object System.Drawing.Size(350,245)
$SetGroupBoxPKGoptions.Text = "Installer options:"
$SettingsForm.Controls.Add($SetGroupBoxPKGoptions)

Add-FormObj 'Label' $null $SetGroupBoxPKGoptions 10 20 0 "Package Delimiter:"
$SetTextBoxPkgDelimiter = New-Object System.Windows.Forms.TextBox 
$SetTextBoxPkgDelimiter.MaxLength = 1
$SetTextBoxPkgDelimiter.TextAlign = "Center"
$SetTextBoxPkgDelimiter.add_TextChanged({$SetLabelPkgDelimiterShown.Text = $PkgNameFormat.Replace("_",$SetTextBoxPkgDelimiter.Text)})
$SetTextBoxPkgDelimiter.add_MouseHover({$SetTooltip.SetToolTip($this,"A non-alphanumeric character to separate the Package name into Manufacturer Product and Version`nSome characters are not allowed such as / \ : | * ? < > `“ .")})
Add-FormObj 'Textbox' $SetTextBoxPkgDelimiter $SetGroupBoxPKGoptions 320 18 20 $PkgDelimiter
$SetLabelPkgDelimiterShown = New-Object System.Windows.Forms.Label 
$SetLabelPkgDelimiterShown.Font = New-Object System.Drawing.Font($SetLabelPkgDelimiterShown.Font.Name,$SetLabelPkgDelimiterShown.Font.Size,[System.Drawing.FontStyle]::Bold)
Add-FormObj 'Label' $SetLabelPkgDelimiterShown $SetGroupBoxPKGoptions 10 40 0 $PkgNameFormat.Replace("_",$SetTextBoxPkgDelimiter.Text)

Add-FormObj 'Label' $null $SetGroupBoxPKGoptions 10 65 0 "Source Files Folder:"
$SetTextBoxPkgFilesFolder = New-Object System.Windows.Forms.TextBox
$SetTextBoxPkgFilesFolder.add_MouseHover({$SetTooltip.SetToolTip($this,"The source folder that packages are stored under")})
Add-FormObj 'Textbox' $SetTextBoxPkgFilesFolder $SetGroupBoxPKGoptions 160 63 180 $PkgFilesFolder

Add-FormObj 'Label' $null $SetGroupBoxPKGoptions 10 90 0 "MSI Arguments:"
$SetTextBoxMSIargs = New-Object System.Windows.Forms.TextBox
$SetTextBoxMSIargs.add_MouseHover({$SetTooltip.SetToolTip($this,"Arguments to pass in to msiexec.exe along with the install command`nThis is if using a MSI install type")})
Add-FormObj 'Textbox' $SetTextBoxMSIargs $SetGroupBoxPKGoptions 160 88 180 $MSIargs

Add-FormObj 'Label' $null $SetGroupBoxPKGoptions 10 115 0 "Uninstall Arguments:"
$SetTextBoxUninstallArgs = New-Object System.Windows.Forms.TextBox
$SetTextBoxUninstallArgs.add_MouseHover({$SetTooltip.SetToolTip($this,"Arguments to pass in to msiexec.exe along with the uninstall command`nThis is if using a MSI install type")})
Add-FormObj 'Textbox' $SetTextBoxUninstallArgs $SetGroupBoxPKGoptions 160 113 180 $UninstallArgs

Add-FormObj 'Label' $null $SetGroupBoxPKGoptions 10 140 0 "Logging Option:"
$SetTextBoxLogOption = New-Object System.Windows.Forms.TextBox
$SetTextBoxLogOption.add_MouseHover({$SetTooltip.SetToolTip($this,"The log level to use with msiexec`nThis is if using a MSI install type")})
Add-FormObj 'Textbox' $SetTextBoxLogOption $SetGroupBoxPKGoptions 300 138 40 $LogOption

#set default?
Add-FormObj 'Label' $null $SetGroupBoxPKGoptions 10 165 0 "Log Folder:"
$SetTextBoxLogPath = New-Object System.Windows.Forms.TextBox
$SetTextBoxLogPath.add_MouseHover({$SetTooltip.SetToolTip($this,"The log path to use with msiexec`nThis is if using a MSI install type")})
Add-FormObj 'Textbox' $SetTextBoxLogPath $SetGroupBoxPKGoptions 160 163 180 $LogPath

$SetLabelScriptInstallCMD = New-Object System.Windows.Forms.Label
$SetLabelScriptInstallCMD.Forecolor = 'Gray'
Add-FormObj 'Label' $SetLabelScriptInstallCMD $SetGroupBoxPKGoptions 10 190 0 "Script Install Command*:"
$SetTextBoxScriptInstallCMD = New-Object System.Windows.Forms.TextBox
$SetTextBoxScriptInstallCMD.add_MouseHover({$SetTooltip.SetToolTip($this,"The install command for the Application if using a Script install type")})
Add-FormObj 'Textbox' $SetTextBoxScriptInstallCMD $SetGroupBoxPKGoptions 160 188 180 $ScriptInstallCMD

$SetLabelScriptUninstallCMD = New-Object System.Windows.Forms.Label
$SetLabelScriptUninstallCMD.Forecolor = 'Gray'
Add-FormObj 'Label' $SetLabelScriptUninstallCMD $SetGroupBoxPKGoptions 10 215 0 "Script Uninstall Command*:"
$SetTextBoxScriptUninstallCMD = New-Object System.Windows.Forms.TextBox
$SetTextBoxScriptUninstallCMD.add_MouseHover({$SetTooltip.SetToolTip($this,"The uninstall command for the Application if using a Script install type")})
Add-FormObj 'Textbox' $SetTextBoxScriptUninstallCMD $SetGroupBoxPKGoptions 160 213 180 $ScriptUninstallCMD

$SetSaveButton = New-Object System.Windows.Forms.Button
$SetSaveButton.Location = New-Object System.Drawing.Size(100,1000)
$SetSaveButton.Size = New-Object System.Drawing.Size(80,23)
$SetSaveButton.Text = "Save"
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
    $XmlObjectWriter.WriteElementString(“ADDescription”,$SetTextBoxADDescription.Text)
    $XmlObjectWriter.WriteComment(“MECM options”)
    $XmlObjectWriter.WriteElementString(“Sitecode”,$SetTextBoxSitecode.Text)
    $XmlObjectWriter.WriteComment(“Collection”)
    $XmlObjectWriter.WriteElementString(“LimitingCollection”,$SetTextBoxLimitingCollection.Text)
    $XmlObjectWriter.WriteElementString(“CollectionFolder”,$SetTextBoxCollectionFolder.Text)
    $XmlObjectWriter.WriteElementString(“RefreshInterval”,$SetComboBoxRefreshInterval.SelectedItem)
    $XmlObjectWriter.WriteElementString(“RefreshIntCount”,$SetComboBoxRefreshIntCount.SelectedItem)
    $XmlObjectWriter.WriteComment(“Application”)
    $XmlObjectWriter.WriteElementString(“ApplicationFolder”,$SetTextBoxApplicationFolder.Text)
    $XmlObjectWriter.WriteElementString(“PkgPrefix”,$SetTextBoxPkgPrefix.Text)
    $XmlObjectWriter.WriteElementString(“AllowTaskSeqInstall”,$SetCheckBoxAllowTaskSeqInstall.Checked)
    $XmlObjectWriter.WriteElementString(“PrestageDP”,$SetComboBoxPrestageDP.SelectedItem)
    $XmlObjectWriter.WriteComment(“Deployment”)
    $XmlObjectWriter.WriteElementString(“DPGroup”,$SetTextBoxDPGroup.Text)
    $XmlObjectWriter.WriteElementString(“AllowBranchCache”,$SetCheckBoxAllowBranchCache.Checked)
    $XmlObjectWriter.WriteElementString(“InstallBehavior”,$SetComboBoxInstallBehavior.SelectedItem)
    $XmlObjectWriter.WriteElementString(“maxDeployTime”,$SetTextBoxmaxDeployTime.Text)
    $XmlObjectWriter.WriteElementString(“SendWakeup”,$SetCheckBoxSendWakeup.Checked)
    $XmlObjectWriter.WriteElementString(“UserNotification”,$SetComboBoxUserNotification.SelectedItem)
    $XmlObjectWriter.WriteElementString(“PkgrTestCollection”,$SetTextBoxPkgrTestCollection.Text)
    $XmlObjectWriter.WriteComment(“Installer options”)
    $XmlObjectWriter.WriteElementString(“PkgDelimiter”,$SetTextBoxPkgDelimiter.Text)
    $XmlObjectWriter.WriteElementString(“PkgFilesFolder”,$SetTextBoxPkgFilesFolder.Text)
    $XmlObjectWriter.WriteElementString(“MSIargs”,$SetTextBoxMSIargs.Text)
    $XmlObjectWriter.WriteElementString(“UninstallArgs”,$SetTextBoxUninstallArgs.Text)
    $XmlObjectWriter.WriteElementString(“LogOption”,$SetTextBoxLogOption.Text)
    $XmlObjectWriter.WriteElementString(“LogPath”,$SetTextBoxLogPath.Text)
    $XmlObjectWriter.WriteElementString(“ScriptInstallCMD”,$SetTextBoxScriptInstallCMD.Text)
    $XmlObjectWriter.WriteElementString(“ScriptUninstallCMD”,$SetTextBoxScriptUninstallCMD.Text)
    $XmlObjectWriter.WriteComment(“Test options”)
    $XmlObjectWriter.WriteStartElement(“TestMachines“)
    $XmlObjectWriter.WriteElementString(“Tester”,$null)
    $XmlObjectWriter.WriteEndElement()
    $XmlObjectWriter.WriteEndElement()
    $XmlObjectWriter.WriteEndDocument()
    $XmlObjectWriter.Flush()
    $XmlObjectWriter.Close()
    
    if(-not(Test-Path $SettingsXML) -or $Error[0] -ne $null){
        $OkHolder = ShowBox "Unable to create Settings file.`nMake sure you have write access to $ScriptPath" "Error" "Error"
        $SetLabelSaved.Forecolor = 'Red'
        $SetLabelSaved.Text = "Error!"
    }else{
        $SetLabelSaved.Forecolor = 'Green'
        $SetLabelSaved.Text = "Saved!"
    }
})
$SettingsForm.Controls.Add($SetSaveButton)

$SetLabelSaved = New-Object System.Windows.Forms.Label
Add-FormObj 'Label' $SetLabelSaved $SettingsForm 120 1025 0 ""

$SetCloseButton = New-Object System.Windows.Forms.Button
$SetCloseButton.Location = New-Object System.Drawing.Size(190,1000)
$SetCloseButton.Size = New-Object System.Drawing.Size(75,23)
$SetCloseButton.Text = "Close"
$SetCloseButton.Add_Click({$SettingsForm.Close()})
$SettingsForm.Controls.Add($SetCloseButton)

$LabelFYI = New-Object System.Windows.Forms.Label
$LabelFYI.Forecolor = 'Gray'
Add-FormObj 'Label' $LabelFYI $SettingsForm 10 1050 0 "Closing this window will launch/refresh the main program.`nIt may take a few moments to load. Please be patient."

$SettingsForm.Add_Shown({$SettingsForm.Activate()})
[void] $SettingsForm.ShowDialog()
}
#endregion########################################################################################

### Start here
#if not debugging, recall the script hidden
if(-not($Dbug)){
    Write-Host "**********************************************************************************************" -ForegroundColor Yellow
    Write-Host " $scriptName may take a few moments to load depending on environment. Please be patient." -ForegroundColor Yellow
    Write-Host "**********************************************************************************************" -ForegroundColor Yellow
    Write-Host "This window will self-destruct..."
    Start-Sleep -Seconds 7
    Start-Process powershell.exe -ArgumentList ('-NoProfile -WindowStyle hidden -File "{0}" -Dbug' -f ($ThisScript))
}else{
    ### Load Forms
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

    #check prereqs and settings
    if((Check-Prereqs) -eq $false){Return}
    if(-not(Test-Path $SettingsXML)){
        $OkHolder = ShowBox "Required settings could not be found or accessed.`n$SettingsXML`n`nThis must be set before continuing." "First Run?"
        SettingsForm
    }
    #check again before launching main form
    if(Test-Path $SettingsXML){
        #launch GUI
        MainForm
    }else{
        $OkHolder = ShowBox "Settings file must exist in order to use this tool and one was not found.`nMake sure you have write access to $ScriptPath" "Error" "Error"
    }
}

<###################### TODO
-update depreciated cmdlets
-add test user/machines to settings form
-is it possible to navigate AD in the settings form?
-Appx?

#>