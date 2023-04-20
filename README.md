# MECMAddAppTool
If consistent packaging standards and naming conventions are in place, this tool allows the packager to automatically create the Active Directory group (if AD is used for software distribution), Collection, Application, and Deployment in MECM/SCCM for a package by providing minimal input.

For instance, if using a package with the name of “Joes_MostGreatSoftware_1.0” and all options were selected, the following would be created by the tool:
- **AD Group:** Joes_MostGreatSoftware_1.0-Install
- **Collection:** Joes_MostGreatSoftware_1.0-Install
  - linked to AD Group
- **Application:** Joes_MostGreatSoftware_1.0
- **Deployment:** Joes_MostGreatSoftware_1.0
  - linked to Collection

In many cases this automates most, if not all, the steps required.

## 2.14 Notes
<ul>
<li>If Collection refresh interval is set to Hours or Minutes, will use the run time of the script as the Start time rather than setting to 12AM.  This is so collections updating throughout the day are more randomized.  And collections that update on Days basis do so overnight.</li>
<li>Updated deprecated -AppCategories parameter to -AddAppCategory under Set-CMApplication</li>
<li>Code improvements</li>
<li>Removed option to create a Package</li>
<li>Set main form to run non-modal</li>
<li>Changed AD: Name to match Collection name; Description to have friendly name (with spaces); removed option from Settings</li>
<li>Added option to create Uninstall deployment
	-Settings may need to be reSaved in order to update</li>
<li>Added some tooltips to main form</li>
<li>Updated AD code to be able to add machines in different domains</li>
</ul>
