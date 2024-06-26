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

## 2.15.3 Notes
<ul>
<li>Removed extra processing from Out-Null pipelines</li>
<li>Improved Add-FormObj function to include menu items</li>
<li>Added Loading screen</li>
