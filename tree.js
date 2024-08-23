// "JSONifyed" SANS poster datas
var sans_cat_mapping = {
    "Application Execution": {
        cat_name: "application_execution",
        data:[
            {
                artefact_name: "Shimcache",
                description: "The Windows Application Compatibility Database is used by Windows to identify possible application compatibility challenges with executables. It tracks the executable fi le path and binary last modifi ed time.",
                locations: [
                    "XP: SYSTEM\\CurrentControlSet\\Control\\SessionManager\\AppCompatibility",
                    "Win7+: SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache"
                ],
                interpretation: "Any executable present in the file system could be found in this key. Data can be particularly useful to identify the presence of malware on devices where other application execution data is missing (such as Windows servers).<br>• Full path of executable<br>• Windows 7+ contains up to 1,024 entries (96 entries in WinXP)<br>• Post-WinXP no execution time is available<br>• Executables can be preemptively added to the database prior to execution.<br>The existence of an executable in this key does not prove actual execution.",
            },
            {
                artefact_name: "Windows 10 Timeline",
                description: "Win10 records recently used applications and fi les in a “timeline” database in SQLite format.",
                locations: [
                    "C:\\Users\\<profile>\\AppData\\Local\\ConnectedDevicesPlatform\\<account-ID>\\ActivitiesCache.db"
                ],
                interpretation: "• Full path of executed application<br>• Start time, end time, and duration<br>• Items opened within application<br>• URLs visited<br>• Databases still present even after feature deprecation in late-Win10"
            },
            {
                artefact_name: "Task Bar Feature Usage",
                description: "Task Bar Feature Usage tracks how a user has interacted with the taskbar.",
                locations: [
                    "Win 10 1903+: NTUSER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage"
                ],
                interpretation: "• Only tracks GUI applications<br>• Does not include timestamps<br>• AppLaunch tracks data only for pinned applications, showing user knowledge of the application<br>- Data persists after an application is unpinned<br>• AppSwitched tracks a count of application focus, showing user<br>interaction directed at the application<br>- Not tied to pinned applications"
            },
            {
                artefact_name: "BAM/DAM",
                description: "Windows Background/Desktop Activity Moderator (BAM/DAM) is maintained by the Windows power management sub-system. (Available in Win10+)",
                locations: [
                    "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\{SID}",
                    "SYSTEM\\CurrentControlSet\\Services\\dam\\State\\UserSettings\\{SID}"
                ],
                interpretation: "• Provides full path of fi le executed and last execution date/time<br>• Typically up to one week of data available<br>• “State” key used in Win10 1809+"
            },
            {
                artefact_name: "Amcache.hve",
                description: "Amcache tracks installed applications, programs executed (or present), drivers loaded, and more. What sets this artifact apart is it also tracks the SHA1 hash for executables and drivers. (Available in Win7+)",
                locations: [
                    "C:\\Windows\\AppCompat\\Programs\\Amcache.hve"
                ],
                interpretation: "• A complete registry hive, with multiple sub-keys<br>• Full path, fi le size, fi le modifi cation time, compilation time, and publisher<br>metadata<br>• SHA1 hash of executables and drivers<br>• Amcache should be used as an indication of executable and driver presence on the system, but not to prove actual execution"
            },
            {
                artefact_name: "System Resource Usage Monitor (SRUM)",
                description: "SRUM records 30 to 60 days of historical system performance including applications run, user accounts responsible, network connections, and bytes sent/received per application per hour.",
                locations: [
                    "Win8+: C:\\Windows\\System32\\SRU\\SRUDB.dat"
                ],
                interpretation: "• SRUDB.dat is an Extensible Storage Engine database<br>• Three tables in SRUDB.dat are particularly important:<br>- {973F5D5C-1D90-4944-BE8E-24B94231A174} = Network Data Usage<br>- {d10ca2fe-6fcf-4f6d-848e-b2e99266fa89} = Application Resource Usage<br>- {DD6636C4-8929-4683-974E-22C046A43763} = Network Connectivity Usage"
            },
            {
                artefact_name: "Jump Lists",
                description: "Windows Jump Lists allow user access to frequently or recently used items quickly via the task bar. First introduced in Windows 7, they can identify applications in use and a wealth of metadata about items accessed via those applications.",
                locations: [
                    "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations"
                ],
                interpretation: "• Each jump list fi le is named according to an application identifier (AppID). List of Jump List IDs -> https://dfi r.to/EZJumpList<br>• Automatic Jump List Creation Time = First time an item added to the jump list. Typically, the fi rst time an object was opened by the application.<br>• Automatic Jump List Modifi cation Time = Last time item added to the jump list. Typically, the last time the application opened an object."
            },
            {
                artefact_name: "Prefetch",
                description: "Prefetch increases performance of a system by pre-loading code pages of commonly used applications. It monitors all fi les and directories referenced for each application or process and maps them into a .pf file. It provides evidence that an application was executed.<br>• Limited to 128 fi les on XP and Win7<br>• Up to 1024 fi les on Win8+",
                locations: [
                    "C:\\Windows\\Prefetch Naming format: (exename)-(hash).pf",
                    "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters EnablePrefetcher value (0 = disabled; 3 = application launch and boot enabled)"
                ],
                interpretation: "Date/Time file by that name and path was first executed<br>- Creation date of .pf fi le (-10 seconds)<br>• Date/Time fi le by that name and path was last executed<br>- Last modifi cation date of .pf fi le (-10 seconds)<br>• Each .pf fi le includes embedded data, including the last eight execution times (only one time available pre-Win8), total number of times executed, and device and fi le handles used by the program"
            },
            {
                artefact_name: "CapabilityAccessManager",
                description: "Records application use of the microphone, camera, and other application-specific settings.",
                locations: [
                    "Win 10 1903+: SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore",
                    "Win 10 1903+: NTUSER\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore"
                ],
                interpretation: "LastUsedTimeStart and LastUsedTimeStop track the last session times. The NonPackaged key tracks non-Microsoft applications."
            },
            {
                artefact_name: "Commands Executed in the Run Dialog",
                description: "A history of commands typed into the Run dialog box are stored for each user.",
                locations: [
                    "NTUSER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"
                ],
                interpretation: "It is an MRU key, so it has temporal order via the MRUList key."
            },
            {
                artefact_name: "UserAssist",
                description: "UserAssist records metadata on GUI-based program executions.",
                locations: [
                    "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{GUID}\\Count"
                ],
                interpretation: "GUIDs identify type of execution (Win7+): CEBFF5CD - Executable File Execution, F4E57C4B - Shortcut File Execution. Values are ROT-13 Encoded. Application path, last run time, run count, focus time and focus count."
            },
            {
                artefact_name: "Memory (RAM) Analysis",
                description: "Below are some volatility3 plugins that can show application execution.",
                locations: [
                    "cmdline [--pid PID] - List process command line arguments.",
                    "pstree/pslist/psscan [--pid PID] - List processes present in the memory dump.",
                    "userassist - Print userassist (metadatas on GUI-based program executions) registry keys and information.",
                    "registry.hivelist/registry.hivescan - List/scan the registry hives present in a particular memory image.",
                    "registry.printkey [--key KEY] [--recurse] - Lists the registry keys under a hive or specific key value (recursively or not).",
                    "crashinfo - Lists the information (versions, DirectoryTableBase, PfnDataBase, PsLoadedModuleList...) from a Windows crash dump.",
                    "driverscan - Scans for drivers present in a particular windows memory image.",
                    "drivermodule - Determines if any loaded drivers were hidden by a rootkit.",
                    "dlllist [--pid PID] [--dump] - Lists the loaded DLL in a particular windows memory image/a given process (if pid is set). Can also dump the loaded modules if dump is set.",
                    "envars [--pid PID] - Display process environment variables.",
                    "iat [--pid PID] - Extract Import Address Table to list API (functions) used by a program contained in external libraries. Requires additional analysis to find hooked functions.",
                    "malfind [--pid PID] - Lists process memory ranges that <b>potentially</b> contain injected code.",
                    "memmap [--pid PID] - Prints the memory map (process' memory).",
                    "modscan [--dump] - Scans for modules present in a particular windows memory image.. Extract listed modules if --dump is set.",
                    "modules - Lists the loaded kernel modules.",
                    "mutantscan - Scans for mutexes present in a particular windows memory image. <i>\"Mutual Exclusion\"</i> prevents multiple threads from accessing the same shared resource simultaneously.",
                    "privileges.Privs [--pid PID] - Lists process token privileges in a particular windows memory image or in a given process if --pid is set. Each Windows process has its access token that determines what they are allowed to access. This token is linked to user's access token.",
                    "thrdscan - Scans for windows threads."
                ],
                interpretation: "These plugins provide information about running programs, their actions on the system, the resources they use, their rights... <b>We classify a program's legitimacy by the actions it performs on the system, in relation to what it should be supposed to do</b>.<br>There is no simple interpretation to be made of this data, which would require a whole site dedicated to malware analysis. However, some of the information is quite remarkable. For example, the output of the malfind plugin is particularly interesting to analyze."
            }
        ]
    },
    "File And Folder Opening": {
        cat_name: "file_and_folder_opening",
        data: [
            {
                artefact_name: "Open/Save MRU",
                description: "In the simplest terms, this key tracks files that have been opened or saved within a Windows shell dialog box. This happens to be a big data set, including Microsoft Office applications, web browsers, chat clients, and a majority of commonly used applications.",
                locations: [
                    "XP: NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSaveMRU",
                    "Win7/8/10: NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePIDlMRU"
                ],
                interpretation: "The “*” key – This subkey tracks the most recent files of any extension input in an OpenSave dialog. .??? (Three letter extension) – This subkey stores file info from the OpenSave dialog by specific extension."
            },
            {
                artefact_name: "Recent Files",
                description: "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
                locations: [
                    "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
                ],
                interpretation: "RecentDocs – Rollup key tracking the overall order of the last 150 files or folders opened. MRU list tracks the temporal order in which each file/folder was opened. .??? – These subkeys store the last 20 files opened by the user of each extension type. MRU list tracks the temporal order in which each file was opened. The most recently used (MRU) item is associated with the last write time of the key, providing one timestamp of file opening for each file extension type. Folder – This subkey stores the last 30 folders opened by the user. The most recently used (MRU) item in this key is associated with the last write time of the key, providing the time of opening for that folder."
            },
            {
                artefact_name: "MS Word Reading Locations",
                description: "Beginning with Word 2013, the last known position of the user within a Word document is recorded.",
                locations: [
                    "NTUSER\\Software\\Microsoft\\Office\\<Version>\\Word\\Reading Locations"
                ],
                interpretation: "Another source tracking recent documents opened. The last closed time is also tracked along with the last position within the file. Together with the last opened date in the Office File MRU key, a last session duration can be determined."
            },
            {
                artefact_name: "Last Visited MRU",
                description: "Tracks applications in use by the user and the directory location for the last file accessed by the application.",
                locations: [
                    "XP: NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedMRU",
                    "Win7+: NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU"
                ],
                interpretation: "We get two important pieces of information from this key: applications executed by the user and the last place in the file system that those applications interacted with. Interesting and hidden directories are often identified via this registry key."
            },
            {
                artefact_name: "Shortcut (LNK) Files",
                description: "Shortcut files are automatically created by Windows, tracking files and folders opened by a user.",
                locations: [
                    "XP: %USERPROFILE%\\Recent",
                    "Win7+: %USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\",
                    "Win7+: %USERPROFILE%\\AppData\\Roaming\\Microsoft\\Office\\Recent\\"
                ],
                interpretation: "Date/Time file of that name was first opened - Creation Date of Shortcut (LNK) File. Date/Time file of that name was last opened - Last Modification Date of Shortcut (LNK) File. LNK Target File (Internal LNK File Information) Data: Modified, Access, and Creation times of the target file. Volume Information (Name, Type, Serial Number). Network Share information. Original Location. Name of System."
            },
            {
                artefact_name: "Office Recent Files",
                description: "MS Office programs track their own recent files list, to make it easier for users to access previously opened files.",
                locations: [
                    "NTUSER.DAT\\Software\\Microsoft\\Office\\<Version>\\<AppName>\\File MRU - 12.0 = Office 2007, 16.0 = Office 2016/2019/M365, 11.0 = Office 2003, 15.0 = Office 2013, 10.0 = Office XP, 14.0 = Office 2010",
                    "NTUSER.DAT\\Software\\Microsoft\\Office\\<Version>\\<AppName>\\User MRU\\LiveId_####\\File MRU - Microsoft 365",
                    "NTUSER.DAT\\Software\\Microsoft\\Office\\<Version>\\<AppName>\\User MRU\\AD_####\\File MRU - Microsoft 365 (Azure Active Directory)"
                ],
                interpretation: "Similar to the Recent Files registry key, this tracks the last files opened by each MS Office application. Unlike the Recent Files registry key, full path information is recorded along with a last opened time for each entry."
            },
            {
                artefact_name: "Shell Bags",
                description: "Shell bags identifies which folders were accessed on the local machine, via the network, and on removable devices, per user. It also shows evidence of previously existing folders still present after deletion/overwrite.",
                locations: [
                    "Primary Data: USRCLASS.DAT\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags",
                    "USRCLASS.DAT\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
                    "Residual Desktop Items and Network Shares: NTUSER.DAT\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
                    "NTUSER.DAT\\Software\\Microsoft\\Windows\\Shell\\Bags"
                ],
                interpretation: "Massive collection of data on folders accessed by each user. Folder file system timestamps are archived in addition to first and last interaction times. “Exotic” items recorded like mobile device info, control panel access, and Zip archive access."
            },
            {
                artefact_name: "Jump Lists",
                description: "Windows Jump Lists allow user access to frequently or recently used items quickly via the task bar. First introduced in Windows 7, they can identify applications in use and a wealth of metadata about items accessed via those applications.",
                locations: [
                    "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations",
                    "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations"
                ],
                interpretation: "Each jump list file is named according to an application identifier (AppID). List of Jump List IDs available at https://dfir.to/EZJumpList. Each Jump List contains a collection of items interacted with (up to ~2000 items per application). Each entry is represented as a LNK shell item providing additional data: Target Timestamps, File Size, Local Drive | Removable Media | Network Share Info. Entries are kept in MRU order including a timestamp for each item."
            },
            {
                artefact_name: "Office Trust Records",
                description: "Records trust relationships afforded to documents by a user when presented with a security warning. This is stored so the user is only required to grant permission the first time the document is opened.",
                locations: [
                    "NTUSER\\Software\\Microsoft\\Office\\<Version>\\<AppName>\\Security\\Trusted Documents\\TrustRecords"
                ],
                interpretation: "Can identify documents opened by the user and user interaction in trusting the file. Records file path, time the document was trusted, and which permissions were granted."
            },
            {
                artefact_name: "Office OAlerts",
                description: "MS Office programs produce alerts for the user when they attempt actions such as closing a file without saving it first.",
                locations: ["OAlerts.evtx"],
                interpretation: "All Office applications use Event ID 300. Events include the program name and dialog message, showing some user activity within the application."
            },
            {
                artefact_name: "Internet Explorer file:///",
                description: "Internet Explorer History databases have long held information on local and remote file access (via network shares), giving us an excellent means for determining files accessed on the system, per user. Information can be present even on Win11+ systems missing the Internet Explorer application.",
                locations: [
                    "IE6–7: %USERPROFILE%\\LocalSettings\\History\\History.IE5",
                    "IE8–9: %USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\History\\History.IE5",
                    "IE10–11 & Win10+: %USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\WebCache\\WebCacheV*.dat"
                ],
                interpretation: "Entries recorded as: file:///C:/directory/filename.ext. Does not mean file was opened in a browser.<br><br>Remember that even if a user never opens Internet Explorer, there may still be valuable records in their IE database including files opened on the local system, network shares, and removable devices. It may also hold evidence of malicious activity including HTTP connections initiated on behalf of malware or suspicious sites visited via links clicked in email clients.<br><br>Internet Explorer and its supporting libraries are deeply tied to the Windows operating system and WinINet API functions often interact with IE databases.<br>From <a href=\"https://www.sans.org/blog/ese-databases-are-dirty/\" class=\"btn start-button\" target=\"_blank\"><img src=\"assets/icons/kodak_imaging_file-0.png\" class=\"icon-16\"> ESE Databases are Dirty! by Chad Tilbury - SANS DFIR Blog</a>"
            },
            {
                artefact_name: "Memory (RAM) Analysis",
                description: "Below are some volatility3 plugins that can show informations about file & folder opening.",
                locations: [
                    "handles [--pid PID] - Lists process open handles. It is an abstract objects used by a process which represents a system ressource such as a file, a thread, an image, a registry key, a token... When a process wishes to access a system resource, it uses a handle without directly manipulating the resource."
                ],
                interpretation: "Without in-depth knowledge of Windows reverse engineering it is not possible to readily determine which handles are suspicious and which are not. Howerver, handle names can be known as IOC. More specifically, mutexes are often handles of interest because their names are known and they are mechanisms that can be useful to the malware's operation. For example, ensuring that the malware only runs once on the machine.<br>From <a href=\"https://publications.gc.ca/collections/collection_2015/rddc-drdc/D68-2-1-2013-eng.pdf\" class=\"btn start-button\" target=\"_blank\"><img src=\"assets/icons/kodak_imaging_file-0.png\" class=\"icon-16\"> Malware memory analysis for non-specialists Investigating publicly available memory image for the Stuxnet worm - Defence Research and Development Canada</a><br><a href=\"https://apps.dtic.mil/sti/tr/pdf/AD1004008.pdf\" class=\"btn start-button\" target=\"_blank\"><img src=\"assets/icons/kodak_imaging_file-0.png\" class=\"icon-16\"> Malware memory analysis for non-specialists Investigating publicly available memory image for the Tigger Trojan horse - Defence Research and Development Canada</a>"
            }
        ]
    },
    "Deleted Items And File Existence": {
        cat_name: "deleted_items_and_file_existence",
        data:[
            {
                artefact_name: "Thumbs.db",
                description: "The hidden database file is created in directories where images were viewed as thumbnails. It can catalog previous contents of a folder even upon file deletion.",
                locations: [
                    "Each folder maintains a separate Thumbs.db file after being viewed in thumbnail view (OS version dependent)"
                ],
                interpretation: "Includes: Thumbnail image of original picture, Last Modification Time (XP Only), Original Filename (XP Only). Most relevant for XP systems, but Thumbs.db files can be created on more modern OS versions in unusual circumstances such as when folders are viewed via UNC paths."
            },
            {
                artefact_name: "Windows Search Database",
                description: "Windows Search indexes more than 900 file types, including email and file metadata, allowing users to search based on keywords.",
                locations: [
                    "Win XP: C:\\Documents and Settings\\All Users\\Application Data\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb",
                    "Win7+: C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb",
                    "Win7+: C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\GatherLogs\\SystemIndex"
                ],
                interpretation: "Database in Extensible Storage Engine format. Gather logs contain a candidate list for files to be indexed over each 24 hour period. Extensive file metadata and even partial content can be present."
            },
            {
                artefact_name: "Internet Explorer file:///",
                description: "Internet Explorer History databases have long held information on local and remote (via network shares) file access, giving us an excellent means for determining files accessed on the system, per user. Information can be present even on Win11+ systems missing the Internet Explorer application.",
                locations: [
                    "IE6-7: %USERPROFILE%\\LocalSettings\\History\\History.IE5",
                    "IE8-9: %USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\History\\History.IE5",
                    "IE10-11 and Win10+: %USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\WebCache\\WebCacheV*.dat"
                ],
                interpretation: "Entries recorded as: file:///C:/directory/filename.ext. Does not mean file was opened in a browser.<br><br>Remember that even if a user never opens Internet Explorer, there may still be valuable records in their IE database including files opened on the local system, network shares, and removable devices. It may also hold evidence of malicious activity including HTTP connections initiated on behalf of malware or suspicious sites visited via links clicked in email clients.<br><br>Internet Explorer and its supporting libraries are deeply tied to the Windows operating system and WinINet API functions often interact with IE databases.<br>From <a href=\"https://www.sans.org/blog/ese-databases-are-dirty/\" class=\"btn start-button\" target=\"_blank\"><img src=\"assets/icons/kodak_imaging_file-0.png\" class=\"icon-16\"> ESE Databases are Dirty! by Chad Tilbury - SANS DFIR Blog</a>"            },
            {
                artefact_name: "Search – WordWheelQuery",
                description: "This maintains an ordered list of terms put into the File Explorer search dialog.",
                locations: [
                    "Win7+: NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery"
                ],
                interpretation: "Keywords are added in Unicode and listed in temporal order in an MRUlist."
            },
            {
                artefact_name: "User Typed Paths",
                description: "A user can type a path directly into the File Explorer path bar to locate a file instead of navigating the folder structure. Folders accessed in this manner are recorded in the TypedPaths key.",
                locations: [
                    "NTUSER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths"
                ],
                interpretation: "This indicates a user had knowledge of a particular file system location. It can expose hidden and commonly accessed locations, including those present on external drives or network shares."
            },
            {
                artefact_name: "Thumbcache",
                description: "Thumbnails of pictures, documents, and folders exist in a set of databases called the thumbcache. It is maintained for each user based on the thumbnail sizes viewed (e.g., small, medium, large, and extra large). It can catalog previous contents of a folder even upon file deletion. (Available in Windows Vista+)",
                locations: [
                    "%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\Explorer"
                ],
                interpretation: "Database files are named similar to: Thumbcache_256.db. Each database file represents thumbnails stored as different sizes or to fit different user interface components. Thumbnail copies of pictures can be extracted and the Thumbnail Cache ID can be cross-referenced within the Windows Search Database to identify filename, path, and additional file metadata"
            },
            {
                artefact_name: "Recycle Bin",
                description: "The recycle bin collects items soft-deleted by each user and associated metadata—only relevant for recycle-bin aware applications.",
                locations: [
                    "Hidden System Folder - Win XP: C:\\Recycler, Win7+: C:\\$Recycle.Bin"
                ],
                interpretation: "Each user is assigned a SID sub-folder that can be mapped to a user via the Registry. In Win XP, the INFO2 database contains deletion times and original filenames. In Win7+, files preceded by $I###### contain original filename and deletion date/time. Files preceded by $R###### contain original deleted file contents."
            },
            {
                artefact_name: "Memory (RAM) Analysis",
                description: "Below are some volatility3 plugins that can show deleted items & file existence.",
                locations: [
                    "dumpfiles [--pid PID] [--virtaddr VIRTADDR] [--physaddr PHYSADDR] - Dumps cached file contents from Windows memory samples. If PID is set, the plugin will target processe's files.",
                    "filescan - Scans for file objects present in a particular Windows memory image.",
                    "registry.hivelist/registry.hivescan - List/scan the registry hives present in a particular memory image.",
                    "registry.printkey [--key KEY] [--recurse] - Lists the registry keys under a hive or specific key value (recursively or not).",
                    "mftscan.ADS - Scans for Alternate Data Stream. Each file has at least one data stream called :$DATA. When a file contains more than one data stream it's called an ADS.<br><br>It is used to store additional information but can be used by hackers to hide files. For example, ADS can be used to store informations on where a file comes from when it is downloaded (can be modified by attackers).<br>More information here: <a href=\"https://owasp.org/www-community/attacks/Windows_alternate_data_stream\" class=\"btn start-button\"><img src=\"assets/icons/search_web-0.png\" class=\"icon-16\"> Windows ::DATA Alternate Data Stream - OWASP</a>",
                    "mftscan.MFTScan - Scans for $MFT file objects present in a particular Windows memory image. More information can be found in this poster: <a href=\"https://forsight.fr/static/media/mft.e01065cd365882356726.pdf\" class=\"btn start-button\" target=\"_blank\"><img src=\"assets/icons/kodak_imaging_file-0.png\" class=\"icon-16\"> Master the Master File Table - Forsight</a>"
                ],
                interpretation: "Dump files with Volatility3 could be challenging: sometimes it works, sometimes not so much. The reasons behind it are unknown to me. This is why I recommend working with <a href=\"https://github.com/ufrisk/MemProcFS\" class=\"btn start-button\" target=\"_blank\"><img src=\"assets/icons/kodak_imaging_file-0.png\" class=\"icon-16\"> MemProcFS</a>, which makes it easier to extract the MFT. The MFT contains an enormous amount of useful information for reconstructing the timeline."
            }
        ]
    },
    "Browser Activity": {
        cat_name: "browser_activity",
        data: [
            {
                artefact_name: "History and Download History",
                description: "History and Download History records websites visited by date and time.",
                locations: [
                    "Firefox - XP: %USERPROFILE%\\Application Data\\Mozilla\\Firefox\\Profiles\\<randomtext>.default\\places.sqlite",
                    "Win7+: %USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<random text>.default\\places.sqlite",
                    "Chrome/Edge - XP: %USERPROFILE%\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\<Profile>\\History",
                    "Win7+: %USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\<Profile>\\History",
                    "Win7+: %USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\<Profile>\\History"
                ],
                interpretation: "Web browser artifacts are stored for each local user account. Most browsers also record number of times visited (frequency). Look for multiple profiles in Chromium browsers, including 'Default', and 'Profile1', etc."
            },
            {
                artefact_name: "Media History",
                description: "Media History tracks media usage (audio and video played) on visited websites (Chromium browsers).",
                locations: [
                    "Chrome/Edge - %USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\<Profile>\\Media History",
                    "%USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\<Profile>\\Media History"
                ],
                interpretation: "Three primary tables: playbackSession, origin, playback. Includes URLs, last play time, watch time duration, and last video position. Not cleared when other history data is cleared."
            },
            {
                artefact_name: "HTML5 Web Storage",
                description: "HTML5 Web Storage are considered to be 'Super Cookies'. Each domain can store up to 10MB of text-based data on the local system.",
                locations: [
                    "Firefox - %USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<randomtext>.default\\webappstore.sqlite",
                    "Chrome/Edge - %USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\<Profile>\\Local Storage",
                    "%USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\<Profile>\\Local Storage"
                ],
                interpretation: "Chrome uses a LevelDB database, Firefox uses SQLite, and IE/EdgeHTML store data within XML files"
            },
            {
                artefact_name: "HTML5 FileSystem",
                description: "HTML5 FileSystem implements the HTML5 local storage FileSystem API. It is similar to Web Storage, but designed to store larger binary data.",
                locations: [
                    "Chrome/Edge - %USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\<Profile>\\File System",
                    "%USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\<Profile>\\File System"
                ],
                interpretation: "A LevelDB database in this folder stores visited URLs and assigned subfolders to locate the data. Files are stored temporarily (“t” subfolders) or in permanent (“p” subfolders) storage."
            },
            {
                artefact_name: "Auto-Complete Data",
                description: "Many databases store data that a user has typed into the browser.",
                locations: [
                    "Firefox - %USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<randomtext>.default\\places.sqlite",
                    "%USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<randomtext>.default\\formhistory.sqlite",
                    "Chrome/Edge - %USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\<Profile>\\History",
                    "%USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\<Profile>\\History - keyword_search_terms – items typed into various search engines",
                    "%USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\<Profile>\\Web Data - Items typed into web forms",
                    "%USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\<Profile>\\ Web Data - Items typed into web forms",
                    "%USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\<Profile>\\Shortcuts - Items typed in the Chrome URL address bar (Omnibox)",
                    "%USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\<Profile>\\ Shortcuts - Items typed in the Chrome URL address bar (Omnibox)",
                    "%USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\<Profile>\\Network Action Predictor - Records what was typed, letter by letter",
                    "%USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\<Profile>\\ Network Action Predictor - Records what was typed, letter by letter",
                    "%USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\<Profile>\\Login Data - Stores inputted user credentials",
                    "%USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\<Profile>\\ Login Data - Stores inputted user credentials"
                ],
                interpretation: "Includes typed-in data, as well as data types. Connects typed data and knowledge to a user account."
            },
            {
                artefact_name: "Browser Preferences",
                description: "Configuration data associated with the browser application, including privacy settings and synchronization preferences.",
                locations: [
                    "Firefox: %USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<randomtext>.default\\prefs.js",
                    "Chrome/Edge: %USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\<Profile>\\Preferences",
                    "Chrome/Edge: %USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\<Profile>\\Preferences"
                ],
                interpretation: "• Firefox prefs.js shows sync status, last sync time, and artifacts selected to sync • Chrome uses JSON format - per_host_zoom_levels, media-engagement, and site_engagement can help to show user interaction - Contains synchronization status, last sync time and artifacts selected to sync • Edge preferences include account_info, clear_data_on_exit, and sync settings"
            },
            {
                artefact_name: "Cache",
                description: "The cache is where web page components can be stored locally to speed up subsequent visits.",
                locations: [
                    "Firefox: XP: %USERPROFILE%\\Local Settings\\Application Data\\Mozilla\\Firefox\\Profiles\\<randomtext>.default\\Cache",
                    "Firefox 31-: Win7+: %USERPROFILE%\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\<randomtext>.default\\Cache",
                    "Firefox 32+: Win7+: %USERPROFILE%\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\<randomtext>.default\\cache2",
                    "Chrome/Edge: XP: %USERPROFILE%\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\<Profile>\\Cache - data_# and f_######",
                    "Chrome/Edge: Win7+: %USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\<Profile>\\Cache\\ - data_# and f_######",
                    "Chrome/Edge: Win7+: %USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\<Profile>\\Cache\\ - data_# and f_######"
                ],
                interpretation: "• Gives the investigator a “snapshot in time” of what a user was looking at online • Identifies websites which were visited • Provides the actual files the user viewed on a given website • Similar to all browser artifacts, cached files are tied to a specific local user account • Timestamps show when the site was first saved and last viewed"
            },
            {
                artefact_name: "Bookmarks",
                description: "Bookmarks include default items, as well as those the user chose to save for future reference.",
                locations: [
                    "Firefox 3+: %USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<randomtext>.default\\places.sqlite",
                    "Firefox 3+: %USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<randomtext>.default\\bookmarkbackups\\bookmarks-<date>.jsonlz4",
                    "Chrome/Edge: %USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\<Profile>\\Bookmarks",
                    "Chrome/Edge: %USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\<Profile>\\Bookmarks",
                    "Chrome/Edge: %USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\<Profile>\\Bookmarks.bak",
                    "Chrome/Edge: %USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\<Profile>\\Bookmarks.msbak"
                ],
                interpretation: "• Provides the website of interest and the specific URL that was saved • Firefox bookmarkbackups folder can contain multiple backup copies of bookmarks in JSON format. Field names match those in places.sqlite • Chromium Bookmark files are in JSON format • Note: not all bookmarks are user-generated; it is possible to bookmark a site and never visit it"
            },
            {
                artefact_name: "Stored Credentials",
                description: "Browser-based credential storage typically uses Windows DPAPI encryption. If the login account is a Microsoft cloud account in Windows 10 or 11, DPAPI uses a 44-character randomly generated password in lieu of the account password.",
                locations: [
                    "Firefox: %USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\logins.json",
                    "Chrome/Edge: %USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\<Profile>\\Login Data",
                    "Chrome/Edge: %USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\<Profile>\\Login Data"
                ],
                interpretation: "• Firefox stores the hostname and URL, creation time, last used time, times used, and time of last password change in JSON format. • Chromium-based browsers use a SQLite database and include the origin URL, action URL, username, date created, and date last used. • Credential metadata can be available even if actual credentials are encrypted. Actual credentials are easiest to retrieve on a live system with the user account logged in."
            },
            {
                artefact_name: "Browser Downloads",
                description: "Modern browsers include built-in download manager applications capable of keeping a history of every file downloaded by the user. This browser artifact can provide excellent information about websites visited and corresponding items downloaded.",
                locations: [
                    "Firefox 3-25: %USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<random text>.default\\downloads.sqlite",
                    "Firefox 26+: %USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<randomtext>.default\\places.sqlite - moz_annos table",
                    "Chrome/Edge: %USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\<Profile>\\History",
                    "Chrome/Edge: %USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\<Profile>\\History - downloads and download_url_chains tables"
                ],
                interpretation: "Download metadata includes: • Filename, size, and type • Source website and referring page • Download start and end times • File system save location • State information including success and failure"
            },
            {
                artefact_name: "Extensions",
                description: "Browser functionality can be extended through the use of extensions, or browser plugins.",
                locations: [
                    "Firefox 4-25: %USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<randomtext>.default\\extensions.sqlite",
                    "Firefox 4-25: %USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<randomtext>.default\\addons.sqlite",
                    "Firefox 26+: %USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<randomtext>.default\\addons.json",
                    "Firefox 26+: %USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<randomtext>.default\\extensions.json",
                    "Chrome/Edge: %USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\<Profile>\\Extensions\\<GUID>\\<version>",
                    "Chrome/Edge: %USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\<Profile>\\Extensions\\<GUID>\\<version>"
                ],
                interpretation: "• The newer Firefox JSON format stores more information than in older versions - Extension name, installation source, installation time, last update, and plugin status • Chrome/Edge extensions each have their own folder on the local system, named with a GUID, containing the code and metadata - Creation time of the folder indicates the installation time for the extension. Beware that extensions can be synced across devices affecting the interpretation of this timestamp. - A manifest.json file provides plugin details including name, URL, permissions, and version. - The preferences file can also include additional extension data"
            },
            {
                artefact_name: "Session Restore",
                description: "Automatic crash recovery features are built into the browser.",
                locations: [
                    "Firefox (older versions): Win7+: %USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<randomtext>.default\\sessionstore.js",
                    "Firefox (newer versions): Win7+: %USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<randomtext>.default\\sessionstore.jsonlz4",
                    "Firefox (newer versions): Win7+: %USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<randomtext>.default\\sessionstore-backups\\",
                    "Chrome/Edge (older versions): Win7+: %USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\<Profile>\\",
                    "Chrome/Edge (older versions): Win7+: %USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\<Profile>\\ - Restore files = Current Session, Current Tabs, Last Session, Last Tabs",
                    "Chrome/Edge (newer versions): Win7+: %USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\<Profile>\\Sessions",
                    "Chrome/Edge (newer versions): Win7+: %USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\<Profile>\\Sessions - Restore files = Session_<timestamp>, Tabs_<timestamp>"
                ],
                interpretation: "• Historical websites viewed in each tab • Referring websites • Time session started or ended • HTML, JavaScript, XML, and form data from the page • Other artifacts such as transition type, browser window size and pinned tabs"
            },
            {
                artefact_name: "Cookies",
                description: "Cookies provide insight into what websites have been visited and what activities might have taken place there.",
                locations: [
                    "Firefox: XP: %USERPROFILE%\\Application Data\\Mozilla\\Firefox\\Profiles\\<randomtext>.default\\cookies.sqlite",
                    "Firefox: Win7+: %USERPROFILE%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\<randomtext>.default\\cookies.sqlite",
                    "Chrome/Edge: XP: %USERPROFILE%\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\<Profile>\\Cookies",
                    "Chrome/Edge: Win7+: %USERPROFILE%\\AppData\\Local\\Google\\Chrome\\User Data\\<Profile>\\Network\\Cookies",
                    "Chrome/Edge: Win7+: %USERPROFILE%\\AppData\\Local\\Microsoft\\Edge\\User Data\\<Profile>\\Network\\Cookies"
                ],
                interpretation: ""
            }
        ]
    },
    "Cloud Storage": {
        cat_name: "cloud_storage",
        data: [
            {
                artefact_name: "OneDrive",
                description: "OneDrive is installed by default on Windows 8+ systems, although it must be enabled by a user authenticating to their Microsoft Cloud account before use.",
                locations: [
                    "Default local file storage: %USERPROFILE%\\OneDrive (Personal) %USERPROFILE%\\OneDrive - <CompanyName> (Business)",
                    "File storage folder location info: NTUSER\\Software\\Microsoft\\OneDrive\\Accounts\\<Personal | Business1>",
                    "File metadata: %USERPROFILE%\\AppData\\Local\\Microsoft\\OneDrive\\logs\\<Personal | Business1> - SyncDiagnostics.log - SyncEngine “odl” logs %USERPROFILE%\\AppData\\Local\\Microsoft\\OneDrive\\settings\\<Personal | Business1> - <UserCid>.dat"
                ],
                interpretation: "• It is critical to check the registry to confirm the local file storage location • Metadata files only exist if OneDrive is enabled • SyncDiagnostics.log can sometimes contain file metadata • Some files are only stored in the cloud and will not be stored locally • Deleted items are stored in an online recycle bin for up to 30 days (personal) or 93 days (business) • OneDrive for Business Unified Audit Logs in Microsoft 365 provide 90 days of user activity logging"
            },
            {
                artefact_name: "Google Drive for Desktop",
                description: "Google Drive for Desktop is the new name for the merged Google Backup and Sync and File Stream applications. It uses a virtual FAT32 volume named “My Drive”, which is only accessible to the user when they are logged in.",
                locations: [
                    "Local drive letter for the virtual volume and account ID: NTUSER\\Software\\Google\\DriveFS\\Share\\",
                    "Default local file cache: %USERPROFILE%\\AppData\\Local\\Google\\DriveFS\\<account identifier>\\content_cache",
                    "File metadata: %USERPROFILE%\\AppData\\Local\\Google\\DriveFS\\<account identifier>\\metadata_sqlite_db"
                ],
                interpretation: "• Assigned drive letter can help tie file and folder access artifacts to Google Drive • Google Workspace Admin Reports provide 180 days of user activity logging • metadata_sqlite_db database uses protobuf format for many important fields"
            },
            {
                artefact_name: "Box Drive",
                description: "Box Drive uses a virtual filesystem, implemented as an NTFS reparse point. Excellent metadata logging is available.",
                locations: [
                    "Default reparse point to virtual filesystem: %USERPROFILE%\\Box",
                    "Default local file cache: %USERPROFILE%\\AppData\\Local\\Box\\Box\\cache",
                    "File metadata and configuration data: %USERPROFILE%\\AppData\\Local\\Box\\Box\\logs - Box_Streem logs %USERPROFILE%\\AppData\\Local\\Box\\Box\\data - sync.db & streemsfs.db databases – file metadata - metrics.db – user account info"
                ],
                interpretation: "• Metadata available for both local and cloud-only files, including SHA1 hashes • A search for the value “logDriveInformation” within the Box_Streem logs can identify the location of the virtual filesystem folder if it is not apparent • Detailed usage logging available, but may only go back a few weeks"
            },
            {
                artefact_name: "Dropbox",
                description: "Dropbox can be a challenging application to investigate. Older versions encrypt most metadata using Windows DPAPI, but recent versions tend to have more information available.",
                locations: [
                    "Default local file storage: %USERPROFILE%\\Dropbox %USERPROFILE%\\Dropbox\\.dropbox.cache (up to 3 days of cached data)",
                    "File storage folder location: SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SyncRootManager\\Dropbox!<SID>!Personal\\UserSyncRoots",
                    "File metadata and configuration data: %USERPROFILE%\\AppData\\Local\\Dropbox\\ - nucleus.sqlite3, sync_history.db, and aggregation.dbx – usage and file metadata - v 90-: filecache.dbx, config.dbx – encrypted with Windows DPAPI - info.json – app configuration data"
                ],
                interpretation: "• Metadata for local, cloud, and deleted files can all be identified • Deleted files can exist in both the local and online recycle bins. Online recycle bin retention is 30 days (personal) or 120 days (business) • Dropbox business “advanced tier” provides detailed logging while consumer Dropbox provides only limited logs via “Events” page"
            }
        ]
    },
    "External Device/USB Usage": {
        cat_name: "external_device_usb_usage",
        data: [
            {
                artefact_name: "USB Device Identification",
                description: "Track USB devices plugged into a machine.",
                locations: [
                    "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
                    "SYSTEM\\CurrentControlSet\\Enum\\USB",
                    "SYSTEM\\CurrentControlSet\\Enum\\SCSI",
                    "SYSTEM\\CurrentControlSet\\Enum\\HID"
                ],
                interpretation: "Identify vendor, product, and version of a USB device plugged into a machine. Determine the first and last times a device was plugged into the machine. Devices that do not have a unique internal serial number will have an “&” in the second character of the serial number. The internal serial number provided in these keys may not match the serial number printed on the device. ParentIdPrefix links USB key to SCSI key. SCSI\\<ParentIdPrefix>\\Device Parameters\\Partmgr\\DiskId matches Partition/Diagnostic log and Windows Portable Devices key. Different versions of Windows store this data for different amounts of time. Windows 10/11 can store up to one year of data. Some older data may be present in SYSTEM\\Setup\\Upgrade\\PnP\\CurrentControlSet\\Control\\DeviceMigration. HID key tracks peripherals connected to the system."
            },
            {
                artefact_name: "Event Logs",
                description: "Removable device activity can be audited in multiple Windows event logs.",
                locations: [
                    "Win7+: %SYSTEM ROOT%\\System32\\winevt\\logs\\System.evtx",
                    "%SYSTEM ROOT%\\System32\\winevt\\logs\\Security.evtx",
                    "Win10+: %SYSTEM ROOT%\\System32\\winevt\\logs\\Microsoft-Windows-Partition/Diagnostic.evtx"
                ],
                interpretation: "Event IDs 20001, 20003 – Plug and Play driver install attempted. 4663 – Attempt to access removable storage object (Security log). 4656 – Failure to access removable storage object (Security log). 6416 – A new external device was recognized on system (Security log). Security log events are dependent on system audit settings. Event ID 1006 is recorded for each device connect/disconnect."
            },
            {
                artefact_name: "Drive Letter and Volume Name",
                description: "Discover the last drive letter and volume name of a device when it was plugged into the system.",
                locations: [
                    "XP: Find ParentIdPrefix – SYSTEM\\CurrentControlSet\\Enum\\USBSTOR, Using ParentIdPrefix Discover Last Mount Point – SYSTEM\\MountedDevices",
                    "Win7+:",
                    "SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices", 
                    "SYSTEM\\MountedDevices Examine available drive letter values looking for a serial number match in value data",
                    "SOFTWARE\\Microsoft\\Windows Search\\VolumeInfoCache"
                ],
                interpretation: "Only the last USB device mapped to a specific drive letter can be identified. Historical records not available."
            },
            {
                artefact_name: "User Information",
                description: "Identify user accounts tied to a unique USB Device.",
                locations: [
                    "Document device Volume GUID from SYSTEM\\MountedDevices",
                    "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2"
                ],
                interpretation: "If a Volume GUID match is made within MountPoints2, we can conclude the associated user profile was logged in while that device was present."
            },
            {
                artefact_name: "Shortcut (LNK) Files",
                description: "Shortcut files are automatically created by Windows, tracking files and folders opened by a user.",
                locations: [
                    "XP: %USERPROFILE%\\Recent",
                    "Win7+: %USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\",
                    "Win7+: %USERPROFILE%\\AppData\\Roaming\\Microsoft\\Office\\Recent\\"
                ],
                interpretation: "Date/Time file of that name was first opened - Creation Date of Shortcut (LNK) File. Date/Time file of that name was last opened - Last Modification Date of Shortcut (LNK) File. LNK Target File (Internal LNK File Information) Data: Modified, Access, and Creation times of the target file, Volume Information (Name, Type, Serial Number), Network Share information, Original Location, Name of System."
            },
            {
                artefact_name: "Connection Timestamps",
                description: "Connection timestamps determine temporal usage of specific USB devices connected to a Windows Machine.",
                locations: [
                    "First Time - Plug and Play Log Files: XP: C:\\Windows\\setupapi.log, Win7+: C:\\Windows\\inf\\setupapi.dev.log",
                    "First, Last, and Removal Times - Win7+: SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\Disk&Ven_&Prod_\\USBSerial#\\Properties\\{83da6326-97a6-4088-9453-a19231573b29}####, Win7+: SYSTEM\\CurrentControlSet\\Enum\\SCSI\\Ven_Prod_Version\\USBSerial#\\Properties\\{83da6326-97a6-4088-9453-a19231573b29}####, 0064 = First Install (Win7+), 0066 = Last Connected (Win8+), 0067 = Last Removal (Win8+)",
                    "Connection Times - Win10+: %SYSTEM ROOT%\\System32\\winevt\\logs\\Microsoft-Windows-Partition/Diagnostic.evtx"
                ],
                interpretation: "Search for Device Serial Number. Log File times are set to local time zone. Timestamps are stored in Windows 64-bit FILETIME format. Event ID 1006 is recorded for each device connect/disconnect. Log cleared during major OS updates."
            },
            {
                artefact_name: "Volume Serial Number (VSN)",
                description: "Discover the VSN assigned to the file system partition on the USB. (NOTE: This is not the USB Unique Serial Number, which is hardcoded into the device firmware, nor the serial number on any external labels attached to the device.)",
                locations: [
                    "SOFTWARE\\Microsoft\\WindowsNT\\CurrentVersion\\EMDMgmt - Find a key match using Volume Name and USB Unique Serial Number. Find last integer number in matching line. Convert decimal value to hex serial number. This key is often missing from modern systems using SSD devices.",
                    "Win10+: %SYSTEM ROOT%\\System32\\winevt\\logs\\Microsoft-Windows-Partition/Diagnostic.evtx - Event ID 1006 may include VBR data, which contains the VSN. VSN is 4 bytes located at offsets 0x43 (FAT), 0x64 (exFAT), or 0x48 (NTFS) within each VBR. Log cleared during major OS updates"
                ],
                interpretation: "The VSN and device Volume Name can help correlate devices to specific files via shell items present in LNK files and registry locations."
            }
        ]
    },
    "File System": {
        cat_name: "file_system",
        data: [
            {
                artefact_name: "$MFT filesystem index",
                description: "Maybe the most important file in the NTFS filesystem. It keeps records of all files in a volume, the files' location in the directory, the physical location of the files on the drive, and file metadata.",
                locations: [
                    "C:\\$MFT"
                ],
                interpretation: 'There is at least one entry in the MFT for every file on an NTFS file system volume, including the MFT itself. All information about a file, including its size, time and date stamps, permissions, and data content, is stored either in MFT entries, or in space outside the MFT that is described by MFT entries.<br><br>As files are added to an NTFS file system volume, more entries are added to the MFT and the MFT increases in size. When files are deleted from an NTFS file system volume, their MFT entries are marked as free and may be reused.<br><br>However, disk space that has been allocated for these entries is not reallocated, and the size of the MFT does not decrease.<br>The size of each MFT record is usually 1024-bytes.<br>Each record contains a set of attributes.<br><br>Some of the most important attributes in a MFT entry are the $STANDART_INFORMATION, $FILENAME and $DATA. The first two are rather important because among other things they contain the file time stamps. Each MFT entry for a given file or directory will contain 8 timestamps. 4 in the $STANDARD_INFORMATION and another 4 in the $FILENAME. These time stamps are known as MACE.<br><br>More information can be found in this poster : <a href="https://forsight.fr/static/media/mft.e01065cd365882356726.pdf" class="btn start-button" target="_blank"><img src="assets/icons/kodak_imaging_file-0.png" class="icon-16"> Master the Master File Table - Forsight</a>'
            },
            {
                artefact_name: "$LogFile filesystem journal activity",
                description: 'Used to keep the file system clean in the event of a system crash or power failure. The log records operate on files or folders and leaves large amounts of information in the $LogFile. This information can be used to reconstruct operations and can also be used as forensic evidence.<br>From <a href="https://link.springer.com/chapter/10.1007/978-3-642-35515-8_18" class="btn start-button" target="_blank"><img src="assets/icons/search_web-0.png" class="icon-16"> Digital Forensics and Cyber Crime - Gyu-Sang Cho & Marcus K. Rogers</a>',
                locations: [
                    "C:\\$LogFile"
                ],
                interpretation: 'This file is stored in the MFT entry number 2 and every time there is a change in the NTFS Metadata, there is a transaction recorded in the $LOGFILE. When the change is done, another transaction is logged in the form of a commit. $LOGFILE keeps record of all operations that occurred in the NTFS volume such as file creation, deletion, renaming, copy, etc.<br>From <a href="https://dfir.ru/2019/02/16/how-the-logfile-works/" class="btn start-button" target="_blank"><img src="assets/icons/search_web-0.png" class="icon-16"> How the $LogFile works? - Msuhanov</a>'
            },
            {
                artefact_name: "$J filesystem journal activity",
                description: "As files, directories, and other NTFS file system objects are added, deleted, and modified, the NTFS file system enters change journal records in streams, one for each volume on the computer. Each record indicates the type of change and the object changed.",
                locations: [
                    "C:\\$Extend\\$UsnJrnl:$J",
                    "C:\\$Extend\\$J",
                    "C:\\$Extend\\$UsnJrnl:$Max",
                    "C:\\$Extend\\$Max"
                ],
                interpretation: 'The investigator can confirm every NTFS’s events(creation, deletion, modification…) in specific period. It is possible to find trace of deleted file. The event of program execution and opening document can be found through tracking prefetch file and LNK file’s history.<br>From <a href="http://forensicinsight.org/wp-content/uploads/2013/07/F-INSIGHT-Advanced-UsnJrnl-Forensics-English.pdf" class="btn start-button" target="_blank"><img src="assets/icons/search_web-0.png" class="icon-16"> Advanced $UsnJrnl Forensics - blueangel</a>'
            },
            {
                artefact_name: "$SDS file security descriptor",
                description: "List of volume security descriptors, each file and directory refers to it. The security descriptor is necessary to prevent unauthorised access to files. It stores information about: - The owner of the file - Permissions the owner has granted to other users - What actions should be logged (auditing)",
                locations: [
                    "C:\\$Secure:$SDS",
                    "C:\\$Secure_$SDS"
                ],
                interpretation: 'The security descriptor can be summarised as: A header (may be flags), followed by one or two ACLs and two SIDs. The first ACL contains auditing information and may be absent. The second ACL contains permissions (who can do what). Each ACL contains one or many ACEs. Each ACE contains a SID. The last two SIDs show the owner of the object (User and Group).<br>From <a href="https://flatcap.github.io/linux-ntfs/ntfs/attributes/security_descriptor.html" class="btn start-button" target="_blank"><img src="assets/icons/search_web-0.png" class="icon-16"> Attribute - $SECURITY_DESCRIPTOR (0x50) - NTFS Documentation</a><br>From <a href="https://countuponsecurity.com/tag/ntfs-logfile/" class="btn start-button" target="_blank"><img src="assets/icons/search_web-0.png" class="icon-16"> Digital Forensics – Plugx And Artifacts Left Behind - Count Upon Security</a>'
            },
            {
                artefact_name: "Memory (RAM) Analysis",
                description: "Below are some volatility3 plugins that can show informations about file system.",
                locations: [
                    "mftscan.ADS - Scans for Alternate Data Stream. Each file has at least one data stream called :$DATA. When a file contains more than one data stream it's called an ADS.<br><br>It is used to store additional information but can be used by hackers to hide files. For example, ADS can be used to store informations on where a file comes from when it is downloaded (can be modified by attackers) (it's called <i>\"MOTW - mark of the web\"</i>).<br>More information here: <a href=\"https://owasp.org/www-community/attacks/Windows_alternate_data_stream\" class=\"btn start-button\"><img src=\"assets/icons/search_web-0.png\" class=\"icon-16\"> Windows ::DATA Alternate Data Stream - OWASP</a>",
                    "mftscan.MFTScan - Scans for $MFT file objects present in a particular Windows memory image. More information can be found in this poster: <a href=\"https://forsight.fr/static/media/mft.e01065cd365882356726.pdf\" class=\"btn start-button\" target=\"_blank\"><img src=\"assets/icons/kodak_imaging_file-0.png\" class=\"icon-16\"> Master the Master File Table - Forsight</a>",
                    "symlinkscan - Scans for links present in a particular windows memory image. A symbolic link is a special file which points to another location in the file system. It is not a lnk (shortcut) file, as symbolic links are located at file system level."
                ],
                interpretation: "About ADS, MOTW could contains information on where a file comes from. For example, the field Zone.Identifier can contain the following values: - 0 the content is present on the local machine. - 1 the content comes from the Internet. - 2 the content comes from a trusted website. - 3 the content comes from a site other than those identified in zone 2. - 4 content comes from untrusted sites. Be carreful because theses values could be modified by attackers. Examine the techniques used by APT32 to hide the warning/block the execution of unapproved macros <a href=\"https://cdn2.hubspot.net/hubfs/3354902/Cybereason%20Labs%20Analysis%20Operation%20Cobalt%20Kitty.pdf\" class=\"btn start-button\"><img src=\"assets/icons/search_web-0.png\" class=\"icon-16\"> Operation Cobalt Kitty - Cybereason</a>.<br><br>MFT is mostly used to list every file on the system, even deleted files, and sometimes recover them. There is various timestamps for creation, deletion, rename... In some cases, it may be the only way to prove a file once existed on the machine, even if anti-forensics was used (from Forsight' MFT poster).<br><br>Symlinks can be used for elevation of privileges. If a privilege application performs file operation on a file an attacker control, then it can perform that same operation on the file that the symlink points to. To find evidences of malicious activities, pay particular attention to symlinks that differ from those on a healthy workstation (baseline). Beware of symlinks whose source and destination do not have the same privilege level, as they could be used for elevation. More information here: <a href=\"https://www.cyberark.com/resources/threat-research-blog/follow-the-link-exploiting-symbolic-links-with-ease\" class=\"btn start-button\"><img src=\"assets/icons/search_web-0.png\" class=\"icon-16\"> Follow the Link: Exploiting Symbolic Links with Ease - Cyberark</a>. I haven't been able to find any cases where this technique has been used."
            }
        ]
    },
    "System Information": {
        cat_name: "system_information",
        data: [
            {
                artefact_name: "Operating System Version",
                description: "This determines the operating system type, version, build number, and installation dates for the current installation and previous updates.",
                locations: [
                    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                    "SYSTEM\\Setup\\Source OS"
                ],
                interpretation: "CurrentVersion key stores: • ProductName, EditionID – OS type • DisplayVersion, ReleaseId, CurrentBuildNumber – Version info • InstallTime – Installation time of current build (not original installation) Source OS keys are created for each historical OS update: • ProductName, EditionID – OS type • BuildBranch, ReleaseId, CurrentBuildNumber – Version info • InstallTime – Installation time of this build version • Times present in names of Source OS keys are extraneous: InstallTime = 64-bit FILETIME format (Win10+) InstallDate = Unix 32-bit epoch format (both times should be equivalent)"
            },
            {
                artefact_name: "Computer Name",
                description: "This stores the hostname of the system in the ComputerName value.",
                locations: [
                    "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName"
                ],
                interpretation: "Hostname can facilitate correlation of log data and other artifacts."
            },
            {
                artefact_name: "System Boot & Autostart Programs",
                description: "System Boot and Autostart Programs are lists of programs that will run on system boot or at user login.",
                locations: [
                    "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "SYSTEM\\CurrentControlSet\\Services"
                ],
                interpretation: "• Useful to find malware and to audit installed software • This is not an exhaustive list of autorun locations"
            },
            {
                artefact_name: "System Last Shutdown Time",
                description: "It is the last time the system was shutdown. On Windows XP, the number of shutdowns is also recorded.",
                locations: [
                    "SYSTEM\\CurrentControlSet\\Control\\Windows (Shutdown Time)",
                    "SYSTEM\\CurrentControlSet\\Control\\Watchdog\\Display (Shutdown Count – WinXP only)"
                ],
                interpretation: "• Determining last shutdown time can help to detect user behavior and system anomalies • Windows 64-bit FILETIME format"
            },
            {
                artefact_name: "Memory (RAM) Analysis",
                description: "Below are some volatility3 plugins that can show OS information.",
                locations: [
                    "info - Display information from Windows memory image, such as Kernel Base address, DTB address, system time...",
                    "mbrscan.MBRScan - Scans for and parses potential Master Boot Records (MBRs). MBR is the first sector of a drive. It identifies how and where the OS is located in order to be loaded into the computer's RAM. To do so, MBR contains a program which loads the OS into RAM. An interesting artifact for detecting bootkits.",
                    "statistics - Lists statistics about the memory space such as the number of valid pages, swapped pages, invalid pages...",
                    "svcscan - Scans for windows services (like daemons on Unix). A service is a program that operates in the background. Windows services can be configured to start when the operating system is started and run in the background as long as Windows is running. Alternatively, they can be started manually or by an event (Wikipedia).",
                    "symlinkscan - Scans for links present in a particular windows memory image. A symbolic link is a special file which points to another location in the file system. It is not a lnk (shortcut) file, as symbolic links are located at file system level."
                ],
                interpretation: "Dump files with Volatility3 could be challenging: sometimes it works, sometimes not so much. The reasons behind it are unknown to me. This is why I recommend working with <a href=\"https://github.com/ufrisk/MemProcFS\" class=\"btn start-button\" target=\"_blank\"><img src=\"assets/icons/kodak_imaging_file-0.png\" class=\"icon-16\"> MemProcFS</a>, which makes it easier to extract the MFT. The MFT contains an enormous amount of useful information for reconstructing the timeline."
            }
        ]
    },
    "Network Activity And Physical Location": {
        cat_name: "network_activity_and_physical_location",
        data: [
            {
                artefact_name: "Network History",
                description: "Identify networks to which the computer connected. Available information includes domain name/intranet name, SSID, first and last time connected, and Gateway MAC Address.",
                locations: [
                    "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
                    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards",
                    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged",
                    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Managed",
                    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Nla\\Cache",
                    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles"
                ],
                interpretation: "Multiple registry keys can be correlated to provide a rich picture of network activity. Interfaces info can be correlated with other keys via DhcpDomain value. Signatures and Profiles keys are correlated via the network ProfileGUID value. Network data includes VPN connections. MAC Address of SSID for Gateway can assist with device geolocation. Network Profile NameType values: 6 (0x06) = Wired, 23 (0x17) = VPN, 71 (0x47) = Wireless, 243 (0xF3) = Mobile Broadband"
            },
            {
                artefact_name: "Browser URL Parameters",
                description: "Information leaked within browser history URL parameters can provide clues to captive portal sign-ins and other similar information sources that can identify connected networks and even approximate physical locations.",
                locations: [
                    "Multiple – see the history information within the Browser Usage section"
                ],
                interpretation: ""
            },
            {
                artefact_name: "Timezone",
                description: "Registry data identifies the current system time zone. Event logs may be able to provide additional historical information.",
                locations: [
                    "SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation",
                    "%SYSTEM ROOT%\\System32\\winevt\\logs\\System.evtx"
                ],
                interpretation: "Some log files and artifact timestamps can only be correctly interpreted by knowing the system time zone. Event ID 6013 in the System.evtx log can provide information on historical time zone settings."
            },
            {
                artefact_name: "WLAN Event Log",
                description: "Determine historical view of wireless networks associations.",
                locations: [
                    "Win7+: Microsoft-Windows-WLAN-AutoConfig Operational.evtx"
                ],
                interpretation: "Provides historical record of wireless network connections. SSID can be used to correlate and retrieve additional network information from Network History registry keys. Relevant Event IDs: 11000 – Wireless network association started, 8001 – Successful connection to wireless network, 8002 – Failed connection to wireless network, 8003 – Disconnect from wireless network, 6100 – Network diagnostics (System log)"
            },
            {
                artefact_name: "Network Interfaces",
                description: "List available network interfaces and their last known configurations.",
                locations: [
                    "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
                    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards"
                ],
                interpretation: "Interfaces key includes the last known IP address, DHCP and domain information for both physical and virtual network adapters. Subkeys may be present containing historical network data. NetworkCards key can provide more detail on network availability. The two keys are mapped via the interface GUID value. Unlikely to be a complete view of every connected network"
            },
            {
                artefact_name: "System Resource Usage Monitor (SRUM)",
                description: "SRUM records 30 to 60 days of historical system performance including applications run, user accounts responsible, network connections, and bytes sent/received per application per hour.",
                locations: [
                    "Win8+: C:\\Windows\\System32\\SRU\\SRUDB.dat"
                ],
                interpretation: "SRUDB.dat is an Extensible Storage Engine database. Three tables in SRUDB.dat are particularly important: {973F5D5C-1D90-4944-BE8E-24B94231A174} = Network Data Usage, {d10ca2fe-6fcf-4f6d-848e-b2e99266fa89} = Application Resource Usage, {DD6636C4-8929-4683-974E-22C046A43763} = Network Connectivity Usage. Records data approx. once per hour, in batches."
            },
            {
                artefact_name: "Memory (RAM) Analysis",
                description: "Below are some volatility3 plugins that can show informations about network activity & physical location.",
                locations: [
                    "netscan - Scans for network objects present in a particular windows memory image. This plugin provides informations such as protocol, local and foreign address/port, connexion state, process which owns the connexion and the created timestamp.",
                    "netstat - Traverses network tracking structures present in a particular windows memory image.",
                    "registry.certificates - Lists the certificates in the registry’s Certificate Store, can also dump them. This plugin provides informations such as certificate path, ID and name."
                ],
                interpretation: "Data from netscan and netstat must be analyzed in relation to process needs and functionalities. Does this process need a connection? Is the IP known to be malicious? Is it one of the usual IPs? Is the port usual?<br><br>Certificate section contains the certificate used for signing the application. Usually, malicious applications are not signed or use a certificate from a certificate authority that is untrusted or has been compromised.<br>From <a href=\"https://ccdcoe.org/uploads/2020/07/Malware_Reverse_Engineering_Handbook.pdf\" class=\"btn start-button\" target=\"_blank\"><img src=\"assets/icons/search_web-0.png\" class=\"icon-16\"> Malware Reverse Engineering Handbook - NATO CCDCOE</a>."
            }
        ]
    },
    "Account Usage": {
        cat_name: "account_usage",
        data: [
            {
                artefact_name: "Cloud Account Details",
                description: "Microsoft Cloud Accounts store account information in the SAM hive, including the email address associated with the account.",
                locations: [
                    "SAM\\Domains\\Account\\Users\\<RID>\\InternetUserName"
                ],
                interpretation: "• InternetUserName value contains the email address tied to the account • The presence of this value identifies the account as a Microsoft cloud account"
            },
            {
                artefact_name: "Last Login and Password Change",
                description: "The SAM registry hive maintains a list of local accounts and associated configuration information.",
                locations: [
                    "SAM\\Domains\\Account\\Users"
                ],
                interpretation: "• Accounts listed by their relative identifiers (RID) • Last login time, last password change, login counts, group membership, account creation time and more can be determined"
            },
            {
                artefact_name: "Service Events",
                description: "Analyze logs for suspicious Windows service creation, persistence, and services started or stopped around the time of a suspected compromise. Service events also record account information.",
                locations: [
                    "Win7+: %SYSTEM ROOT%\\System32\\winevt\\logs\\System.evtx",
                    "Win10+: %SYSTEM ROOT%\\System32\\winevt\\logs\\Security.evtx"
                ],
                interpretation: "• Most relevant events are present in the System Log: - 7034 – Service crashed unexpectedly - 7035 – Service sent a Start/Stop control - 7036 – Service started or stopped - 7040 – Start type changed (Boot | On Request | Disabled) - 7045 – A service was installed on the system (Windows 2008R2+) • Auditing can be enabled in the Security log on Windows 10+: - 4697 – A service was installed on the system (from Security log) • A large amount of malware and worms in the wild utilize Services • Services started on boot illustrate persistence (desirable in malware) • Services can crash due to attacks like process injection"
            },
            {
                artefact_name: "User Accounts",
                description: "Identify both local and domain accounts with interactive logins to the system.",
                locations: [
                    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
                ],
                interpretation: "• Useful for mapping SID to user account name • Subkeys are named for user SIDs and contain a ProfileImagePath indicating the user’s profile path"
            },
            {
                artefact_name: "Remote Desktop Protocol (RDP) Usage",
                description: "Track RDP logons and session reconnections to target machines.",
                locations: [
                    "Win7+: %SYSTEM ROOT%\\System32\\winevt\\logs\\Security.evtx"
                ],
                interpretation: "• Multiple events can be used to track accounts used for RDP - Event ID 4624 – Logon Type 10 - Event ID 4778 – Session Connected/Reconnected - Event ID 4779 – Session Disconnected • Event log provides hostname and IP address of remote machine making the connection • Multiple dedicated RDP/Terminal Services logs are also available on modern Windows versions"
            },
            {
                artefact_name: "Successful/Failed Logons",
                description: "Profile account creation, attempted logons, and account usage.",
                locations: [
                    "Win7+: %SYSTEM ROOT%\\System32\\winevt\\logs\\Security.evtx"
                ],
                interpretation: "• Win7+: - 4624 – Successful Logon - 4625 – Failed Logon - 4634 | 4647 – Successful Logoff - 4648 – Logon using explicit credentials (runas) - 4672 – Account logon with superuser rights (Administrator) - 4720 – An account was created"
            },
            {
                artefact_name: "Authentication Events",
                description: "Authentication Events identify where authentication of credentials occurred. They can be particularly useful when tracking local vs. domain account usage.",
                locations: [
                    "Win7+: %SYSTEM ROOT%\\System32\\winevt\\logs\\Security.evtx"
                ],
                interpretation: "• Recorded on system that authenticated credentials - Local Account/Workgroup = on workstation - Domain/Active Directory = on domain controller • Event ID Codes (NTLM protocol) - 4776: Successful/Failed account authentication • Event ID Codes (Kerberos protocol) - 4768: Ticket Granting Ticket was granted (successful logon) - 4769: Service Ticket requested (access to server resource) - 4771: Pre-authentication failed (failed logon)"
            },
            {
                artefact_name: "Logon Event Types",
                description: "Logon Events provide very specific information regarding the nature of account authorizations on a system. In addition to date, time, username, hostname, and success/failure status of a logon, Logon Events also enable us to determine by exactly what means a logon was attempted.",
                locations: [
                    "Win7+: %SYSTEM ROOT%\\System32\\winevt\\logs\\Security.evtx"
                ],
                interpretation: "Event ID 4624<br><br><b>Logon Type - Explanation</b><br> 2 - Logon via console<br> 3 - Network Logon<br> 4 - Batch Logon<br> 5 - Windows Service Logon<br> 7 - Credentials used to unlock screen; RDP session reconnect<br> 8 - Network logon sending credentials (cleartext)<br> 9 - Different credentials used than logged on user<br> 10 - Remote interactive logon (RDP)<br> 11 - Cached credentials used to logon<br> 12 - Cached remote interactive (similar to Type 10)<br> 13 - Cached unlock (similar to Type 7)"
            }
        ]
    }   
}

var cy = cytoscape({
    container: document.getElementById('cy'), // container to render in

    elements: {
        nodes: [ // list of graph elements to start with
            {
                data: { id: 'a1', name: "Is the system compromised?" },
                grabbable: false,
                level: 1
            },
            {
                data: { id: 'b1', name: "Is there malicious user activity?" },
                grabbable: false,
                level: 2
            },
            {
                data: { id: 'b2', name: "Are there malicious programs?" },
                grabbable: false,
                level: 2
            },
            {
                data: { id: 'b3', name: "Are there malicious OS configuration changes?" },
                grabbable: false,
                level: 2
            },
            {
                data: { id: 'c1', name: "Are there suspicious accounts?", type: "sans_container" },
                grabbable: false,
                level: 3
            },
            {
                data: { id: 'c2', name: "Are there suspicious login events?", type: "sans_container" },
                grabbable: false,
                level: 3
            },
            {
                data: { id: 'c3', name: "Did the users do anything suspicious?" },
                grabbable: false,
                level: 3
            },
            {
                data: { id: 'c4', name: "Are there malicious persistence mechanisms?" },
                grabbable: false,
                level: 3
            },
            {
                data: { id: 'c5', name: "Are there malicious processes running?" },
                grabbable: false,
                level: 3
            },
            {
                data: { id: 'c6', name: "Are there signs that malware was run?" },
                grabbable: false,
                level: 3
            },
            {
                data: { id: 'c7', name: "Are there changes to make it easier gain access?", type: "sans_container" },
                grabbable: false,
                level: 3
            },
            {
                data: { id: 'c8', name: "Are there changes to prevent detection?", type: "sans_container" },
                grabbable: false,
                level: 3
            },
            {
                data: { id: 'c9', name: "Are there changes that could make the response harder?", type: "sans_container" },
                grabbable: false,
                level: 3
            },
            {
                data: { id: 'c10', name: "Are there changes needed by malware?", type: "sans_container" },
                grabbable: false,
                level: 3
            },
            {
                data: { id: 'd1', name: "", title: "Account Artifacts/login", type: "sans_category" },
                grabbable: false,
                level: 4
            },
            {
                data: { id: 'd3', name: "Did the users launch any suspicious programs?", type: "sans_container" },
                grabbable: false,
                level: 4
            },
            {
                data: { id: 'd4', name: "Did the users access any suspicious data?", type: "sans_container" },
                grabbable: false,
                level: 4
            },
            {
                data: { id: 'd5', name: "Did the users search for anything suspicious?", type: "sans_container" },
                grabbable: false,
                level: 4
            },
            {
                data: { id: 'd6', name: "Did the users remotely execute anything suspicious?", type: "sans_container" },
                grabbable: false,
                level: 4
            },
            {
                data: { id: 'd7', name: "Are there malicious triggered programs?", type: "sans_container" },
                grabbable: false,
                level: 4
            },
            {
                data: { id: 'd8', name: "Are there malicious programs that could get accidentally loaded?", type: "sans_container" },
                grabbable: false,
                level: 4
            },
            {
                data: { id: 'd9', name: "Are there malicious libraries that could get accidentally loaded?", type: "sans_container" },
                grabbable: false,
                level: 4
            },

            {
                data: { id: 'd10', name: "LOTS of sub-questions (not an easy task to classify a program as suspicious or not)", type: "sans_container" },
                grabbable: false,
                level: 4
            },
            {
                data: { id: 'd11', name: "Are there remnants that a malicious program started?", type: "sans_container" },
                grabbable: false,
                level: 4
            },
            {
                data: { id: 'd12', name: "Are there remnants that a malicious program made while running?", type: "sans_container" },
                grabbable: false,
                level: 4
            },
            {
                data: { id: 'd13', name: "Are there remnants that a malicious program shutdown?", type: "sans_container" },
                grabbable: false,
                level: 4
            }
        ],


        edges: [
            { data: { id: 'a1b1', source: 'a1', target: 'b1' } },
            { data: { id: 'a1b2', source: 'a1', target: 'b2' } },
            { data: { id: 'a1b3', source: 'a1', target: 'b3' } },

            { data: { id: 'b1c1', source: 'b1', target: 'c1' } },
            { data: { id: 'b1c2', source: 'b1', target: 'c2' } },
            { data: { id: 'b1c3', source: 'b1', target: 'c3' } },
            { data: { id: 'b2c4', source: 'b2', target: 'c4' } },
            { data: { id: 'b2c5', source: 'b2', target: 'c5' } },
            { data: { id: 'b2c6', source: 'b2', target: 'c6' } },
            { data: { id: 'b3c7', source: 'b3', target: 'c7' } },
            { data: { id: 'b3c8', source: 'b3', target: 'c8' } },
            { data: { id: 'b3c9', source: 'b3', target: 'c9' } },
            { data: { id: 'b3c10', source: 'b3', target: 'c10' } },

            { data: { id: 'c1d1', source: 'c1', target: 'd1' } },
            { data: { id: 'c3d3', source: 'c3', target: 'd3' } },
            { data: { id: 'c3d4', source: 'c3', target: 'd4' } },
            { data: { id: 'c3d5', source: 'c3', target: 'd5' } },
            { data: { id: 'c3d6', source: 'c3', target: 'd6' } },
            { data: { id: 'c4d7', source: 'c4', target: 'd7' } },
            { data: { id: 'c4d8', source: 'c4', target: 'd8' } },
            { data: { id: 'c4d9', source: 'c4', target: 'd9' } },
            { data: { id: 'c5d10', source: 'c5', target: 'd10' } },
            /*are there sign that malware was run */
            { data: { id: 'c6d11', source: 'c6', target: 'd11' } },
            { data: { id: 'c6d12', source: 'c6', target: 'd12' } },
            { data: { id: 'c6d13', source: 'c6', target: 'd13' } },
        ]
    },


    style: [ // the stylesheet for the graph
        {
          selector: 'node',
          style: {
            'background-color': 'silver',
            'label': 'data(name)',
            'content': 'data(name)',
            'text-wrap': 'wrap',
            'text-max-width': '200px',
            'font-size': '12pt',
            'text-halign': 'center',
            'text-valign': 'center',
            'shape': 'rectangle',
            'width': 'label',
            'height': 'label',
            'padding': '10px',

            'border-style': 'solid',
            'border-width': '1px',
            'border-color': '#424242',
            'background': 'silver',
            'color': 'black'
          }
        },
        {
            selector: 'node[type="sans_container"]',
            style: {
                'content': 'data(name)',
                'text-valign': 'center',
                'background-color': '#08216b',
                'border-color': 'white',
                'color': 'white'
            }
        },
        // leaf selector for sans_category
        {
            selector: 'node[type="sans_category"]',
            style: {
                'font-weight': 'bold',
                'color': 'white'
            }
        },
        // individual sans category style
        {
            selector: 'node[sans_category="account_usage"]',
            style: {
                'background-color': '#bdbcbc',
                'color': 'black',
                'border-color': '#858585'
            }
        },
        {
            selector: 'node[sans_category="browser_activity"]',
            style: {
                'background-color': '#f35c19',
                'border-color': '#b94714'
            }
        },
        {
            selector: 'node[sans_category="cloud_storage"]',
            style: {
                'background-color': '#ce9208',
                'border-color': '#9c6e05'
            }
        },
        {
            selector: 'node[sans_category="network_activity_and_physical_location"]',
            style: {
                'background-color': '#fbbd09',
                'color': 'black',
                'border-color': '#c09005'
            }
        },
        {
            selector: 'node[sans_category="external_device_usb_usage"]',
            style: {
                'background-color': '#3f72c2',
                'border-color': '#2e548f'
            }
        },
        {
            selector: 'node[sans_category="system_information"]',
            style: {
                'background-color': '#7a1d90',
                'border-color': '#541562'
            }
        },
        {
            selector: 'node[sans_category="application_execution"]',
            style: {
                'background-color': '#ed1c24',
                'border-color': '#b3141b'
            }
        },
        {
            selector: 'node[sans_category="file_and_folder_opening"]',
            style: {
                'background-color': '#66c530',
                'border-color': '#44851f'
            }
        },
        {
            selector: 'node[sans_category="deleted_items_and_file_existence"]',
            style: {
                'background-color': '#6b666a',
                'border-color': '#2f2c2f'
            }
        },
        {
            selector: 'node[sans_category="memory_analysis"]',
            style: {
                'background-color': '#660033',
                'border-color': '#310019'
            }
        },
        {
            selector: 'node[sans_category="file_system"]',
            style: {
                'background-color': '#000066',
                'border-color': ''
            }
        },
    
        {
          selector: 'edge',
          style: {
            'width': 3,
            'line-color': '#ccc',
            'target-arrow-color': '#ccc',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
          }
        }
      ],
      // zoom sensitivity level when a user use the wheel
      wheelSensitivity: 0.1,      
});

// click on a node
cy.on('tap', function(evt){
    var node = evt.target
    console.log(node.data('id'))
})

// click on node with type=sans_container
cy.on('tap', 'node[type = "sans_container"]', function(evt){
    var node = evt.target;

    // get all subnodes to hide/show them
    node.successors().forEach(function(e){
        if(e.isNode()){
            if(e.data('hide')=='true'){
                e.show()
                e.data('hide', 'false')
            } else {
                e.hide()
                e.data('hide', 'true')
            }
        }
    })

    // save and restore user's zoom level and pan position
    // otherwise it's not convenient for user when it clicks on nodes
    var position = {
        x: cy.pan().x,
        y: cy.pan().y,
        zoom: cy.zoom()
    }
    layout.on('layoutstop', function(){
        cy.zoom(position.zoom);
        cy.pan({x: position.x, y: position.y}); 
    });
    layout.run()
});

/*
    Set style for leaf nodes
*/
// when user fly over a node of type sans-container 
cy.on('mouseover', 'node[type = "sans_container"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#a5cef7')
});
// when user withdraw his mouse from a node of type sans-container
cy.on('mouseout', 'node[type = "sans_container"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#08216b')
});
// when a user hover an element
cy.on('mouseover', 'node[sans_category = "application_execution"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#b3141b')
});
cy.on('mouseout', 'node[sans_category = "application_execution"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#ed1c24')
});

cy.on('mouseover', 'node[sans_category = "file_and_folder_opening"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#44851f')
});
cy.on('mouseout', 'node[sans_category = "file_and_folder_opening"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#66c530')
});

cy.on('mouseover', 'node[sans_category = "deleted_items_and_file_existence"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#2f2c2f')
});
cy.on('mouseout', 'node[sans_category = "deleted_items_and_file_existence"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#6b666a')
});

cy.on('mouseover', 'node[sans_category = "memory_analysis"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#310019')
});
cy.on('mouseout', 'node[sans_category = "memory_analysis"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#660033')
});

cy.on('mouseover', 'node[sans_category = "file_system"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#000032')
});
cy.on('mouseout', 'node[sans_category = "file_system"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#000066')
});

cy.on('mouseover', 'node[sans_category = "system_information"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#541562')
});
cy.on('mouseout', 'node[sans_category = "system_information"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#7a1d90')
});

cy.on('mouseover', 'node[sans_category = "external_device_usb_usage"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#2e548f')
});
cy.on('mouseout', 'node[sans_category = "external_device_usb_usage"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#3f72c2')
});

cy.on('mouseover', 'node[sans_category = "network_activity_and_physical_location"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#c09005')
});
cy.on('mouseout', 'node[sans_category = "network_activity_and_physical_location"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#fbbd09')
});

cy.on('mouseover', 'node[sans_category = "cloud_storage"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#9c6e05')
});
cy.on('mouseout', 'node[sans_category = "cloud_storage"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#ce9208')
});

cy.on('mouseover', 'node[sans_category = "browser_activity"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#b94714')
});
cy.on('mouseout', 'node[sans_category = "browser_activity"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#f35c19')
});

cy.on('mouseover', 'node[sans_category = "account_usage"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#858585')
});
cy.on('mouseout', 'node[sans_category = "account_usage"]', function(evt){
    var node = evt.target;
    node.style('background-color', '#bdbcbc')
});

/*
    Set pop-up open on click for leaf nodes
*/
cy.on('tap', 'node[type = "sans_category"]', function(evt){
    var node = evt.target;
    var modal = document.getElementById("popup1")
    modal.style.display = 'block'
    // get DOM popup elements
    var body = document.getElementById('popup1-content')
    body.innerHTML = '' // clean the element
    var title = document.getElementById('popup1-h4-title')
    
    // fill data inside popup from a given SANS artifact category
    var node_data = sans_cat_mapping[node.data('name')]
    // add popup title
    title.innerHTML = node.data('name')

    //console.log('debug fill popup', node_data)
    // iterate over each artifact inside the category
    for(let i=0;i<node_data.data.length;i++){
        var artifact = node_data.data[i]
        var body_content = document.createElement("div")

        var title = "<h5>"+artifact.artefact_name+"</h5>"
        // content contains description, location and interpretation
        var content = "<h6>Description</h6>"
        // pas de inner HTML car ce n'est pas un élément mais une string
        content += "<p>"+artifact.description+"</p>"
        content += "<h6>Location</h6>"
        // several locations, you have to iterate over them
        content += "<ul>"
        for(let j=0;j<artifact.locations.length;j++){
            content += "<li>"+artifact.locations[j]+"</li>"
        }
        content += "</ul>"

        content += "<h6>Interpretation</h6>"
        content += "<p>"+artifact.interpretation+"</p><hr>"
        

        body_content.innerHTML = title+content
        body.appendChild(body_content)
    }
});



// add leaf nodes to the rootNode. sans_cat_list is a string list which contains
// one of a SANS category name, according to "Windows Forensic Analysis Poster"
// see sans_cat_mapping variable inside this function to know all supported categories
// nodes are hidden by default because user have to click on question to display
function add_sans_cat_to_node(cy, rootNode, sans_cat_list){
    for (let i = 0; i < sans_cat_list.length; i++) {
        var node_to_add = {
            group: 'nodes',
            data: { 
                id: 'sans_cat_'+i+'_from_'+rootNode.data('id'), 
                name: sans_cat_list[i], 
                type: "sans_category", 
                sans_category: sans_cat_mapping[sans_cat_list[i]].cat_name, 
                hide: 'true',
            },
            grabbable: false,
            level: 5
        }
        //console.log('debug', node_to_add)
        var edge_to_add = {
            group: 'edges',
            data: { id: 'sans_cat_'+i+rootNode.data('id'), source: rootNode.data('id'), target: 'sans_cat_'+i+'_from_'+rootNode.data('id') }
        }
        cy.add(node_to_add)
        cy.getElementById('sans_cat_'+i+'_from_'+rootNode.data('id')).hide()
        cy.add(edge_to_add)
    }
}

// adding leaf nodes
add_sans_cat_to_node(cy, cy.getElementById('c1'), ["Account Usage"])
add_sans_cat_to_node(cy, cy.getElementById('c2'), ["Account Usage"])

add_sans_cat_to_node(cy, cy.getElementById('d3'), ["Application Execution"])
add_sans_cat_to_node(cy, cy.getElementById('d4'), ["File And Folder Opening", "Deleted Items And File Existence", "Browser Activity", "Cloud Storage", "External Device/USB Usage", "File System"])
add_sans_cat_to_node(cy, cy.getElementById('d5'), ["File And Folder Opening", "Deleted Items And File Existence", "Browser Activity", "Cloud Storage", "File System"])
add_sans_cat_to_node(cy, cy.getElementById('d6'), ["Account Usage", "Application Execution"])

add_sans_cat_to_node(cy, cy.getElementById('d7'), ["Application Execution", "System Information", "File And Folder Opening", "Deleted Items And File Existence"])
add_sans_cat_to_node(cy, cy.getElementById('d8'), ["Application Execution"])
add_sans_cat_to_node(cy, cy.getElementById('d9'), ["System Information", "Deleted Items And File Existence"])

add_sans_cat_to_node(cy, cy.getElementById('d10'), ["Application Execution", "Network Activity And Physical Location"])

add_sans_cat_to_node(cy, cy.getElementById('d11'), ["Application Execution", "Account Usage"])
add_sans_cat_to_node(cy, cy.getElementById('d12'), ["Application Execution", "Account Usage", "Network Activity And Physical Location", "System Information", "Deleted Items And File Existence", "File System"])
add_sans_cat_to_node(cy, cy.getElementById('d13'), ["Account Usage", "File System"])

add_sans_cat_to_node(cy, cy.getElementById('c7'), ["System Information", "Cloud Storage", "Account Usage", "External Device/USB Usage", "Deleted Items And File Existence"])
add_sans_cat_to_node(cy, cy.getElementById('c8'), ["System Information", "Cloud Storage", "Account Usage", "External Device/USB Usage", "Deleted Items And File Existence"])
add_sans_cat_to_node(cy, cy.getElementById('c9'), ["System Information", "Cloud Storage", "Account Usage", "External Device/USB Usage", "Deleted Items And File Existence"])
add_sans_cat_to_node(cy, cy.getElementById('c10'), ["System Information", "Cloud Storage", "Account Usage", "External Device/USB Usage", "Deleted Items And File Existence"])

// create and run layout, must be after node and edges declarations
// layout.run() => order the graph according to the given layout (i.e dagre)
var layout = cy.layout({
    name: 'dagre',
    nodeSep: 30,
    animate: false
});
layout.run()

// center the display zone on this nodes
cy.fit(cy.$('#a1, #b2, #c5, #d10'),30)