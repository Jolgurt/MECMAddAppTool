# SCCMAddAppTool
If consistent packaging standards and naming conventions are in place, this tool allows the packager to automatically create the Active Directory group, Collection, Application, and Deployment in SCCM for a package by providing minimal input.

For instance, if using a package with the name of “Joes_MostGreatSoftware_1.0” and all options were selected, the following would be created by the tool:
- AD Group: Joes MostGreatSoftware 1.0
- SCCM Collection: Joes_MostGreatSoftware_1.0-Install
  - linked to AD Group
- SCCM Application: Joes_MostGreatSoftware_1.0
- SCCM Deployment: Joes_MostGreatSoftware_1.0
  - linked to Collection

In many cases this automates ALL, if not most of, the steps required.

## Requirements
- Microsoft .Net Framework 2.0+
- Microsoft PowerShell 3.0 (minimum); 4.0+ (recommended)
- Active Directory and SCCM modules, which are included automatically if both AdminTools and Configuration Manager are installed.  *Note: The SCCM cmdlet library may get updated by Microsoft, in which commands within the script may become depreciated or could no longer function.*

#### Files required:
- SCCMAddAppTool.exe
- SCCMAddAppSettings.xml

*This tool was first written years ago, circa 2016.  It has gone through a few iterations to get to this point.  But I still use it today.*

## Configuration
All custom settings are stored in the settings XML.  This is so the core script does not have to be modified by the user.

Prior to launching the tool, make sure these settings are defined for the site.
| Tool Settings |  |
| :--- | --- |
| SelectAll | Create all components (Active Directory group, Collection, Application, and Deployment).  True/false. |
| CreateAD | Create an Active Directory group for the package.  Ignored if SelectAll is true.  True/false. |
| CreateCollection | Create a device Collection.  If AD group is enabled, this will also create a query rule linking the two.  Ignored if SelectAll is true.  True/false. |
| CreateDeployment | Create a Deployment to the Collection.  Collection must be enabled.  Ignored if SelectAll is true.  True/false. |
|  | *The above 4 settings can be changed within the tool itself.  But it is provided within the XML as an option to always start the tool with a custom selection.  For instance if a site did not utilize AD for software distribution, this could be set to false and AD would always start off as disabled when launching the tool rather than always having to manually deselect it.* |
| **AD Settings** |  |
| ADDomain | Active Directory domain where the Distribution groups will be created. |
| ADPath | The full path to the OU where the groups will be created. In form OU=,OU=,DC=,DC=,DC= |
| ADGroupScope | The Security type defined for the AD group.  Valid values are DomainLocal, Global, and Universal. |
| ADDescription | Text entered in the Description field for the AD group.  This can be left blank. |
| **SCCM Settings** |  |
| Sitecode | SCCM sitecode |
| LimitingCollection | The Limiting Collection to be used for the Device Collections |
| CollectionFolder | The folder in SCCM under Device Collections that the new Collections will be moved to.  Tool will create folder if it doesn’t exist. |
| RefreshInterval | The interval type used to refresh the Collection.  Valid values are Minutes, Hours, or Days. |
| RefreshIntCount | The count used in conjunction with the Interval type.  Must be numeric. |
| ApplicationFolder | The folder in SCCM that new Applications or Packages will be moved to.  Tool will create folder if it doesn’t exist. |
| PkgPrefix | Text to prefix to the Package Name in SCCM.  This can be left blank. |
| AllowTaskSeqInstall | Application setting.  Allow this application to be installed from the Install Application task sequence action without being deployed.  True/false. |
| PrestageDP | Application Distribution setting.  Prestaged distribution point.  Automatically download content when the packages are assigned to distribution points, Download only content changes to the distribution point, or Manually copy the content in this package to the distribution point.  Valid values are AutoDownload, DeltaCopy, or NoDownload. |
| DPGroup | The Distribution Group used to distribute content.  Must use a pre-existing group and not an individual DP. |
| AllowBranchCache | Application Deployment Type setting.  Allow clients to share content with other clients on the same subnet.  True/false. |
| InstallBehavior | Application Deployment Type setting.  Valid values are InstallForUser, InstallForSystem, or InstallForSystemIfResourceIsDeviceOtherwiseInstallForUser. |
| maxDeployTime | Application Deployment Type setting.  Maximum allowed run time (minutes).  Enter numeric value between 15 and 720. |
| SendWakeup | Application Deployment setting.  Send wake-up packets.  True/false. |
| UserNotification | Application Deployment setting.  User notifications.  Display in Software Center and show all notifications, Display in Software Center and only show notifications for computer restarts, or Hide in Software Center and all notifications.  Valid values are DisplayAll, DisplaySoftwareCenterOnly, or HideAll. |
| PkgrTestCollection | If defined, will create an additional Available deployment to this Collection.  This is intended to be used for package testing. |
| **Package Settings** |  |
| PkgDelimiter | A non-alphanumeric character to separate the Package name into Manufacturer Product and Version.  Example “-“ if the package names are Manufacturer-Product-Version.  Some characters are not allowed, such as / \ : \| * ? < > “ . |
| PkgFilesFolder | The source folder that packages are stored.  The package must be located in/under this folder. |
| MSIargs | Arguments to pass in to msiexec.exe along with the install command.  This is if using a MSI install type. |
| UninstallArgs | Arguments to pass in to msiexec.exe along with the uninstall command.  This is if using a MSI install type. |
| LogOption | The log level to use with msiexec.  This is if using a MSI install type.  Example: l*v |
| LogPath | The log path to use with msiexec.  This is if using a MSI install type. |
| ScriptInstallCMD | The install command to enter in the SCCM Application if using a Script install type. |
| ScriptUninstallCMD | The uninstall command to enter in the SCCM Application if using a Script install type. |
| **Testing** |  |
| TestMachines | Tool can populate test machines to add to the AD group if same one(s) are used per packager.  Define the user ID as `<Tester User=””>` followed by the machine name(s) as the value.  Multiple can be entered separated by , or ;. |

*Any True/False settings that do not have a True/False value entered will default to “False”.*

After these are set, they will remain consistent for all packages created for the site.

## How-to Launch
To run the tool, simply double-click the EXE file or right-click the file and select “Run As”.  The tool must be run with an admin account that has access to make modifications to the relevant areas of both Active Directory and SCCM.

It may take a moment before the GUI loads.  This is normal.

If the script fails to run, first check the Execution Policy on your machine. – Run Powershell.exe and enter “get-executionpolicy”.  If it returns Restricted then custom scripts cannot execute.  It’s recommended to change this to RemoteSigned by typing “set-executionpolicy remotesigned”.  Then hit Y to confirm.  (Note, you will not have to do this every time.  Setting the policy is permanent.)
