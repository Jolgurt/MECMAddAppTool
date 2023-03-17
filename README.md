# MECMAddAppTool
If consistent packaging standards and naming conventions are in place, this tool allows the packager to automatically create the Active Directory group (if AD is used for software distribution), Collection, Application, and Deployment in MECM/SCCM for a package by providing minimal input.

For instance, if using a package with the name of “Joes_MostGreatSoftware_1.0” and all options were selected, the following would be created by the tool:
- **AD Group:** Joes MostGreatSoftware 1.0
- **SCCM Collection:** Joes_MostGreatSoftware_1.0-Install
  - linked to AD Group
- **SCCM Application:** Joes_MostGreatSoftware_1.0
- **SCCM Deployment:** Joes_MostGreatSoftware_1.0
  - linked to Collection

In many cases this automates most, if not all, the steps required.

## 2.11 Release
I have not done extensive testing with this version yet. So lets consider it BETA still. But there are significant updates applied which I thought was worth publishing. Previous version saved in 2.10 folder.
<ul>
<li>No longer need to create a Settings XML file. The tool will generate the XML upon first launch by prompting a form dialog to fill out. Afterwards it can be modified in the UI through File>Settings.</li>
<li>Added more detection methods, including File, Registry, and version specific checks.</li>
<li>Some modernization with replacing SCCM with MECM throughout</li>
<li>Done away with the PS2EXE option. Unfortunately antivirus keeps picking it up as a false-positive. Only offering now as the PS1.</li>
<li>Fair amount of code cleanup and improvements.</li>
</ul>
