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

## 2.13 Notes
<ul>
<li>Code improvements</li>
<li>Reorganized menus and form layout</li>
<li>Added bat file launchers</li>
<li>Added option to set the Install deployment to either Available or Required</li>
<li>Done away with a few insignificant/rarely used options</li>
<li>Fixed a few oversights with Form behavior</li>
</ul>
