# SCCMAddAppTool
If consistent packaging standards and naming conventions are in place, this tool allows the packager/administrator to automatically create the Active Directory group, Collection, Application, and Deployment in SCCM for a package by providing minimal input.

For instance, if using a package with the name of “Joes_MostGreatSoftware_1.0” and all options were selected, the following would be created by the tool:
- **AD Group:** Joes MostGreatSoftware 1.0
- **SCCM Collection:** Joes_MostGreatSoftware_1.0-Install
  - linked to AD Group
- **SCCM Application:** Joes_MostGreatSoftware_1.0
- **SCCM Deployment:** Joes_MostGreatSoftware_1.0
  - linked to Collection

In many cases this automates ALL, if not most of, the steps required.

##### Table of Contents  
1. [Requirements](#requirements)
2. [Configuration](#configuration)
3. [How-to Launch](#howtolaunch)
4. [How-to Use](#howtouse)
5. [Example](#example)
6. [Troubleshooting](#troubleshooting)
7. [A Personal Note](#personalnote)
8. [Credits](#credits)

<a name="requirements"/>

## Requirements
- Microsoft .Net Framework 2.0+
- Microsoft PowerShell 3.0 (minimum); 4.0+ (recommended)
- Active Directory and SCCM modules, which are included automatically if both AdminTools and Configuration Manager are installed.  *Note: The SCCM cmdlet library may get updated by Microsoft, in which commands within the script may become depreciated or could no longer function.*

#### Files required:
- SCCMAddAppTool.exe
- SCCMAddAppSettings.xml

*For reference, the source PowerShell script can be found in the PS1 folder.  It is not required.*

<a name="configuration"/>

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

<a name="howtolaunch"/>

## How-to Launch
To run the tool, simply double-click the EXE file or right-click the file and select “Run As”.  The tool must be run with an admin account that has access to make modifications to the relevant areas of both Active Directory and SCCM.

It may take a moment before the GUI loads.  This is normal.

If the script fails to run, first check the Execution Policy on your machine. – Run Powershell.exe and enter “get-executionpolicy”.  If it returns Restricted then custom scripts cannot execute.  It’s recommended to change this to RemoteSigned by typing “set-executionpolicy remotesigned”.  Then hit Y to confirm.  (Note, you will not have to do this every time.  Setting the policy is permanent.)
![Xpolicy](https://user-images.githubusercontent.com/44309802/135490059-44949016-2b07-462c-819d-8cb61daae79c.png)

Then try launching the tool again. 

<a name="howtouse"/>

## How-to Use
Interface:

![Interface](https://user-images.githubusercontent.com/44309802/135490308-99556bd1-a2dc-4030-9979-8eb688271877.png)

| <img width=2000/> |  |
| --- | --- |
| ![Interface1](https://user-images.githubusercontent.com/44309802/135515805-6f82194f-b5e0-494c-bfed-66de6d23af6d.png) | Enter the package name in the textbox.  Must be in the format shown.  The delimiter (In this case “-”) may be different depending on the entry in the settings XML.  The max length for this text field is 50 when selecting a Package or 64 when selecting an Application. |
| ![Interface2](https://user-images.githubusercontent.com/44309802/135516495-828dd523-1085-400f-831a-1798913ae848.png) | Define which options you would like the tool to create or Select All to create all.  When selecting between Application or Package type, note that the tool was built for Applications.  But some functionality is there for Packages.  (It will create an empty Package with no Programs.) |
| ![Interface3](https://user-images.githubusercontent.com/44309802/135518438-c4216866-7fa8-4214-8998-35082366bccc.png) | Choose a Deployment type option.<ul><li>Manual.  This is for situations where the tool cannot create the Deployment type by the other means.  You will “manually” create it after the tool sets up everything else.</li><li>MSI.  This is for packages that are simple MSI’s only, with/without a Transform.  Install/Uninstall commands, etc. are built automatically.</li><li>App-V 5.  This is for App-V5 packages.</li><li>Script.  This creates a script-based installer in which you can define the install/uninstall commands.</li></ul> |
| ![Interface4](https://user-images.githubusercontent.com/44309802/135519626-a210d6bc-8811-4419-b76e-7385deacfea0.png) | The Source folder will be pulled from the Settings XML + the Package name.  The source files must be located in or under this location.<br>When selecting MSI type, the top box will be for the MSI.  The 2nd box for the MST.<br>When selecting AppV5, the top box will be for the AppV.<br>When selecting Script, the top box will be for the Install command.  The 2nd box will be for the Uninstall command.  This will prepopulate with settings from the XML file.<br>Browse allows you to navigate to a file. |
| ![Interface5](https://user-images.githubusercontent.com/44309802/135519911-9a84335c-ee44-4134-b1c2-6881273ae5d4.png) | If the checkbox for a 2nd Deployment Type is selected for x64, this will allow selection of two sets of MSI/MST’s.  Note that the path is changed slightly to include a “x86” and “x64” folder.  But Browse is available to change it.<br>NOTE: This will create two MSI Deployment Types in SCCM.  But it will not set the Operating System Requirements.  That will have to be a manual setting afterward. |
|   | *This may confuse some people.  But I used to work at a place with a mixture of 32 and 64-bit systems.  Many times we created a package that contained both versions of installers for a single application.  So this created a single App with 2 Deployment Types.  I have not used this in quite some time.  But decided to leave the feature available in the tool.* |
| ![Interface6](https://user-images.githubusercontent.com/44309802/135520402-12a6d3e2-765a-4654-a1fc-69a035032ff8.png) | Detection method will be enabled if selecting a Script type.  Will only accept a product code for detection at this time.<br>Browse allows you to navigate to a MSI and import the code.<br>Version information is shown, but not currently incorporated in the detection.<br>Must be in the form of {00000000-0000-0000-0000-000000000000} using only Hexadecimal numbers. |
| ![Interface7](https://user-images.githubusercontent.com/44309802/135520939-055b53f6-9dc5-4963-a4cc-49be0f3ae722.png) | This displays current Admin categories pulled from SCCM.  Any or multiple can be selected for the App.<br>New button dynamically creates a new category in SCCM and will display it at the bottom of the list. |
| ![Interface8](https://user-images.githubusercontent.com/44309802/135521400-4281fbf3-0763-4b2b-a343-2b99b668a100.png) | Fields used for Application Catalog settings.<br>Description and Keywords are text fields.<br>Category is a dropdown list.  It also pulls current categories defined in SCCM, and like the admin category, allows you to create New.  Only one can be selected though.<br>Icon file is the file to use for the application icon.  This can be a .ico or .exe.  It cannot use .dll’s.  Browse allows you to navigate to the file.  Once selected, you will see the image of the icon appear on screen.  When selecting an exe, it extracts the image into a png format to %temp%.  After the application is created, this file is removed during cleanup. |
| ![Interface9](https://user-images.githubusercontent.com/44309802/135521966-95d5438d-dae5-42c6-9051-d918a2bb26c5.png) | If you wish to add machine names to the newly created AD group, check the box and enter them in the text field.<br>If Testers are defined in the settings XML, this will prepopulate with those entries.<br>This is disabled unless AD Group is checked. |
| ![Interface10](https://user-images.githubusercontent.com/44309802/135522559-7f1e1f14-d121-4959-8849-c297b3d4e5fd.png) | Create button starts the process after all selections have been made.  Once complete, the form will reset.<br>Reset Form resets all the fields and selections to the form’s original state.<br>Quit closes the form. |
| ![Interface11](https://user-images.githubusercontent.com/44309802/135522850-03f1a0db-ebf0-4023-a10f-b29bd9776a48.png) | This box is read-only and will display messages as progress completes.  Certain actions will perform validation checks in which will display Pass or Fail messages.  Others will just continue on.<br>Clear Log button will reset this display to its original state. |

<a name="example"/>

## Example
This may look complicated.  But an Application can be created with as little as 3 button clicks.  Here’s an example with only 5…

![Capture1](https://user-images.githubusercontent.com/44309802/135523357-7b18267c-f4b1-41dc-8da1-b280321e539b.png)

1. Enter package name.
2. Select Script.
- *In this example we are using the PowerShell Application Deployment Toolkit (which is also another great free tool) for our package.  Install and Uninstall commands are set automatically, imported from the XML.*
3. Within the package we have an MSI.  Browse to this to import the Product Code for Detection.
- *I know we could have simply chosen MSI for the Deployment Type.  But I wanted to show a better example, as most cases with packaging, it’s not always simple.*
4. Here we chose to only import an icon.
5. Create.
6. Output is logged as the tool runs.

![Capture2](https://user-images.githubusercontent.com/44309802/135524146-40cc4e51-825a-49c1-9dc5-5a5d9c17920e.PNG)

<a name="troubleshooting"/>

## Troubleshooting
Additional validation checks are in place to check user input.  If any fail, an error message will appear on the screen.  Such as.

![error1](https://user-images.githubusercontent.com/44309802/135524858-d7571f39-3829-4f4a-96de-d5d93ab5eaf4.png)

![error2](https://user-images.githubusercontent.com/44309802/135524912-a79a1921-3b31-4c27-8094-e757f2fe8e57.png)

If a step errs during creation of the App, that error should also be displayed in a message window with the full error details.

Some pre-validation checks are also performed at various steps, and if that feature already exists there will be a prompt to Skip or exit.  This allows the packager to continue using the tool even if some steps were already completed.  Or cancel out if it was unintentional.

![warning1](https://user-images.githubusercontent.com/44309802/135525077-522644b7-237e-48c0-9509-88e5fde940c5.png)

<a name="personalnote"/>

## A Personal Note
This tool was first written years ago, circa 2015.  It has gone through a few iterations to get to this point.  But I have not made any significant changes to it in quite some time.  So I realize there could still be room for improvement.  Some things that I DO intend on looking at (pending time and motivation):
- Importing the settings into the GUI itself.  Something of a File>Settings option that can be customized with form fields rather than directly editing the XML.
- Detection Method improvements. At the time I included that feature, only Product Code would work.  I'm sure things have changed since then.  So I would like to include File, Registry, and Version checking of the MSI.
- Requirements.  Nearly the only thing I have to manually set after using AddApp are things like Requirements (by OS, or I have been asked to include Disk Space as a requirement on very large applications).  Assuming I can put in, maybe not all but at least the most common, I might not even have to use SCCM at all.  Imagine that.

<a name="credits"/>

## Credits
- PS2EXE-GUI by Markus Scholtes (a rework of PS2EXE by Igor Karstein) – Used to compile the AddApp ps1 script into a more user-friendly executable.
