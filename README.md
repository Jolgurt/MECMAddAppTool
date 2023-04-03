# MECMAddAppTool
If consistent packaging standards and naming conventions are in place, this tool allows the packager to automatically create the Active Directory group (if AD is used for software distribution), Collection, Application, and Deployment in MECM/SCCM for a package by providing minimal input.

For instance, if using a package with the name of “Joes_MostGreatSoftware_1.0” and all options were selected, the following would be created by the tool:
- **AD Group:** Joes MostGreatSoftware 1.0
- **Collection:** Joes_MostGreatSoftware_1.0-Install
  - linked to AD Group
- **Application:** Joes_MostGreatSoftware_1.0
- **Deployment:** Joes_MostGreatSoftware_1.0
  - linked to Collection

In many cases this automates most, if not all, the steps required.

## 2.13.1 Notes
<ul>
<li>Form layout change</li>
<li>Added 2nd Detection method clause</li>
<li>Set to convert "C:\Program Files" or "C:\Program Files (x86)" to %ProgramFiles% when using File detection Browse</li>
<li>Set File version when using File detection Browse</li>
<li>Removed deprecated BrachCache setting</li>
<li>Updated deprecated cmdlet Start-CMApplicationDeployment to New-CMApplicationDeployment</li>
<li>Code improvements</li>
<li>Added Disk Space Requirement</li>
<li>Added highlight to required Text fields if set empty</li>
</ul>
