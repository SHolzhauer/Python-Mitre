

class Attck:

    def __init__(self):
        self.version = "v8"
        self._tactics = {
            "TA0001": {
                "name": "Initial Access",
                "description": "The adversary is trying to get into your network. Initial Access consists of techniques that use various entry vectors to gain their initial foothold within a network. Techniques used to gain a foothold include targeted spearphishing and exploiting weaknesses on public-facing web servers. Footholds gained through initial access may allow for continued access, like valid accounts and use of external remote services, or may be limited-use due to changing passwords.",
                "techniques": [
                    "T1189",
                    "T1190",
                    "T1133",
                    "T1200",
                    "T1566",
                    "T1566.001",
                    "T1566.002",
                    "T1566.003",
                    "T1091",
                    "T1195",
                    "T1195.001",
                    "T1195.002",
                    "T1195.003",
                    "T1199",
                    "T1078",
                    "T1078.001",
                    "T1078.002",
                    "T1078.003",
                    "T1078.004"
                ],
                "created": "2020-10-17"
            }
        }
        self._techniques = {
            "T1189": {
                "name": "Drive-by Compromise",
                "description": """
                    Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. With this technique, the user's web browser is typically targeted for exploitation, but adversaries may also use compromised websites for non-exploitation behavior such as acquiring Application Access Token.

                    Multiple ways of delivering exploit code to a browser exist, including:

                    A legitimate website is compromised where adversaries have injected some form of malicious code such as JavaScript, iFrames, and cross-site scripting.
                    Malicious ads are paid for and served through legitimate ad providers.
                    Built-in web application interfaces are leveraged for the insertion of any other kind of object that can be used to display web content or contain a script that executes on the visiting client (e.g. forum posts, comments, and other user controllable web content).
                    Often the website used by an adversary is one visited by a specific community, such as government, a particular industry, or region, where the goal is to compromise a specific user or set of users based on a shared interest. This kind of targeted attack is referred to a strategic web compromise or watering hole attack. There are several known examples of this occurring.

                    Typical drive-by compromise process:

                    A user visits a website that is used to host the adversary controlled content.
                    Scripts automatically execute, typically searching versions of the browser and plugins for a potentially vulnerable version.
                    The user may be required to assist in this process by enabling scripting or active website components and ignoring warning dialog boxes.
                    Upon finding a vulnerable version, exploit code is delivered to the browser.
                    If exploitation is successful, then it will give the adversary code execution on the user's system unless other protections are in place.
                    In some cases a second visit to the website after the initial scan is required before exploit code is delivered.
                    Unlike Exploit Public-Facing Application, the focus of this technique is to exploit software on a client endpoint upon visiting a website. This will commonly give an adversary access to systems on the internal network instead of external systems that may be in a DMZ.

                    Adversaries may also use compromised websites to deliver a user to a malicious application designed to Steal Application Access Tokens, like OAuth tokens, to gain access to protected applications and information. These malicious applications have been delivered through popups on legitimate websites.
                """,
                "version": "1.2",
                "created": "2018-04-18",
                "contributors": [
                    "Jeff Sakowicz",
                    "Microsoft Identity Developer Platform Services (IDPM Services)",
                    "Saisha Agrawal",
                    "Microsoft Threat Intelligent Center (MSTIC)"
                ],
                "data_sources": [
                    "Network device logs",
                    "Network intrusion detection system",
                    "Packet capture",
                    "Process use of network",
                    "SSL/TLS inspection",
                    "Web proxy"
                ],
                "platforms": [
                    "Linux",
                    "SaaS",
                    "Windows",
                    "macOS"
                ],
                "tactic": "TA0001",
                "sub_techniques": [],
                "permissions_required": [
                    "User"
                ],
                "url": "https://attack.mitre.org/versions/{}/techniques/T1189/".format(self.version),
                "procedures": [
                    "APT19",
                    "APT32",
                    "APT37",
                    "APT38",
                    "BRONZE BUTLER",
                    "Bundlore",
                    "Dark Caracal",
                    "Darkhotel",
                    "Dragonfly",
                    "Dragonfly 2.0",
                    "Elderwook",
                    "KARAE",
                    "Lazarus Group",
                    "Leafminer",
                    "LoudMiner",
                    "Patchwork",
                    "PLATINUM",
                    "POORAIM",
                    "PROMETHIUM",
                    "REvil",
                    "RTM",
                    "Threat Group-3390",
                    "Turla",
                    "Windshift"
                ],
                "mitigations": [
                    "M1048",
                    "M1050",
                    "M1021",
                    "M1051"
                ],
                "detection": """
                Firewalls and proxies can inspect URLs for potentially known-bad domains or parameters. They can also do reputation-based analytics on websites and their requested resources such as how old a domain is, who it's registered to, if it's on a known bad list, or how many other users have connected to it before.

                Network intrusion detection systems, sometimes with SSL/TLS MITM inspection, can be used to look for known malicious scripts (recon, heap spray, and browser identification scripts have been frequently reused), common script obfuscation, and exploit code.
                
                Detecting compromise based on the drive-by exploit from a legitimate website may be difficult. Also look for behavior on the endpoint system that might indicate successful compromise, such as abnormal behavior of browser processes. This could include suspicious files written to disk, evidence of Process Injection for attempts to hide execution, evidence of Discovery, or other unusual network traffic that may indicate additional tools transferred to the system.
                """
            },
            "T1190": {
                "name": "Exploit Public-Facing Application",
                "description": """
                    Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior. The weakness in the system can be a bug, a glitch, or a design vulnerability. These applications are often websites, but can include databases (like SQL), standard services (like SMB or SSH), network device administration and management protocols (like SNMP and Smart Install), and any other applications with Internet accessible open sockets, such as web servers and related services. Depending on the flaw being exploited this may include Exploitation for Defense Evasion.

                    If an application is hosted on cloud-based infrastructure, then exploiting it may lead to compromise of the underlying instance. This can allow an adversary a path to access the cloud APIs or to take advantage of weak identity and access management policies.

                    For websites and databases, the OWASP top 10 and CWE top 25 highlight the most common web-based vulnerabilities.
                """,
                "version": "2.2",
                "created": "2020-04-18",
                "contributors": [
                    "Praetorian"
                ],
                "data_sources": [
                    "AWS CloudTrail logs",
                    "Application logs",
                    "Azure activity logs",
                    "Packet capture",
                    "Stackdriver logs",
                    "Web application firewall logs",
                    "Web logs"
                ],
                "platforms": [
                    "AWS",
                    "Azure",
                    "GCP",
                    "Linux",
                    "Network",
                    "Windows",
                    "macOS"
                ],
                "tactic": "TA0001",
                "sub_techniques": [],
                "permissions_required": [],
                "url": "https://attack.mitre.org/versions/{}/techniques/T1190/".format(self.version),
                "procedures": [
                    "APT28",
                    "APT29",
                    "APT39",
                    "APT41",
                    "Axiom",
                    "BlackTech",
                    "Blue Mockingbird",
                    "GOLD SOUTHFIELD",
                    "Havij",
                    "Night Dragon",
                    "Rocke",
                    "Soft Cell",
                    "SoreFang",
                    "sqlmap"
                ],
                "mitigations": [
                    "M1048",
                    "M1050",
                    "M1030",
                    "M1026",
                    "M1051",
                    "M1016"
                ],
                "detection": """
                Monitor application logs for abnormal behavior that may indicate attempted or successful exploitation. Use deep packet inspection to look for artifacts of common exploit traffic, such as SQL injection. Web Application Firewalls may detect improper inputs attempting exploitation.
                """
            },
            "T1133": {
                "name": "External Remote Services",
                "description": """
                Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as Windows Remote Management can also be used externally.

                Access to Valid Accounts to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network. Access to remote services may be used as a redundant or persistent access mechanism during an operation.
                """,
                "version": "2.1",
                "created": "2017-05-31",
                "contributors": [
                    "Daniel Oakley",
                    "Travis Smith",
                    "Tripwire"
                ],
                "data_sources": ["Authentication logs"],
                "platforms": [
                    "Linux",
                    "Windows"
                ],
                "tactic": "TA0001",
                "sub_techniques": [],
                "permissions_required": ["User"],
                "url": "https://attack.mitre.org/versions/{}/techniques/T1133/".format(self.version),
                "procedures": [
                    "APT18",
                    "APT41",
                    "Chimera",
                    "Dragonfly 2.0",
                    "FIN5",
                    "GOLD SOUTHFIELD",
                    "Ke3chang",
                    "Linux Rabbit",
                    "Night Dragon",
                    "OilRig",
                    "Sandworm Team",
                    "Soft Cell",
                    "TEMP.Veles",
                    "Threat Group-3390"
                ],
                "mitigations": [
                    "M1042",
                    "M1035",
                    "M1032",
                    "M1030"
                ],
                "detection": """
                Follow best practices for detecting adversary use of Valid Accounts for authenticating to remote services. Collect authentication logs and analyze for unusual access patterns, windows of activity, and access outside of normal business hours.
                """
            },
            "T1200": {
                "name": "Hardware Additions",
                "description": """
                Adversaries may introduce computer accessories, computers, or networking hardware into a system or network that can be used as a vector to gain access. While public references of usage by APT groups are scarce, many penetration testers leverage hardware additions for initial access. Commercial and open source products are leveraged with capabilities such as passive network tapping, man-in-the middle encryption breaking, keystroke injection, kernel memory reading via DMA, adding new wireless access to an existing network, and others.
                """,
                "version": "1.1",
                "created": "2018-04-18",
                "contributors": [],
                "data_sources": [
                    "Asset management",
                    "Data loss prevention"
                ],
                "platforms": [
                    "Linux",
                    "Windows",
                    "macOS"
                ],
                "tactic": "TA0001",
                "sub_techniques": [],
                "permissions_required": [],
                "url": "https://attack.mitre.org/versions/{}/techniques/T1200/".format(self.version),
                "procedures": [
                    "DarkVishnya"
                ],
                "mitigations": [
                    "M1035",
                    "M1034"
                ],
                "detection": """
                Asset management systems may help with the detection of computer systems or network devices that should not exist on a network.
                Endpoint sensors may be able to detect the addition of hardware via USB, Thunderbolt, and other external device communication ports.
                """
            },
            "T1566": {
                "name": "Phishing",
                "description": """
                Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In spearphishing, a specific individual, company, or industry will be targeted by the adversary. More generally, adversaries can conduct non-targeted phishing, such as in mass malware spam campaigns.
                Adversaries may send victims emails containing malicious attachments or links, typically to execute malicious code on victim systems or to gather credentials for use of Valid Accounts. Phishing may also be conducted via third-party services, like social media platforms.
                """,
                "version": "2.0",
                "created": "2020-03-02",
                "contributors": [],
                "data_sources": [
                    "Anti-virus",
                    "Detonation chamber",
                    "Email gateway",
                    "File monitoring",
                    "Mail server",
                    "Network intrusion detection system",
                    "Packet capture",
                    "SSL/TLS inspection",
                    "Web proxy"
                ],
                "platforms": [
                    "Linux",
                    "Office 365",
                    "SaaS",
                    "Windows",
                    "macOS"
                ],
                "tactic": "TA0001",
                "sub_techniques": [
                    "T1566.001",
                    "T1566.002",
                    "T1566.003"
                ],
                "permissions_required": [],
                "url": "https://attack.mitre.org/versions/{}/techniques/T1566/".format(self.version),
                "procedures": [
                    "Dragonfly",
                    "GOLD SOUTHFIELD"
                ],
                "mitigations": [
                    "M1049",
                    "M1031",
                    "M1021",
                    "M1017"
                ],
                "detection": """Network intrusion detection systems and email gateways can be used to detect phishing with malicious attachments in transit. Detonation chambers may also be used to identify malicious attachments. Solutions can be signature and behavior based, but adversaries may construct attachments in a way to avoid these systems.
                URL inspection within email (including expanding shortened links) can help detect links leading to known malicious sites. Detonation chambers can be used to detect these links and either automatically go to these sites to determine if they're potentially malicious, or wait and capture the content if a user visits the link.
                Because most common third-party services used for phishing via service leverage TLS encryption, SSL/TLS inspection is generally required to detect the initial communication/delivery. With SSL/TLS inspection intrusion detection signatures or other security gateway appliances may be able to detect malware.
                Anti-virus can potentially detect malicious documents and files that are downloaded on the user's computer. Many possible detections of follow-on behavior may take place once User Execution occurs."""
            },
            "T1566.001": {
                "name": "Phishing: Spearphishing Attachment",
                "description": """Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon User Execution to gain execution.
                There are many options for the attachment such as Microsoft Office documents, executables, PDFs, or archived files. Upon opening the attachment (and potentially clicking past protections), the adversary's payload exploits a vulnerability or directly executes on the user's system. The text of the spearphishing email usually tries to give a plausible reason why the file should be opened, and may explain how to bypass system protections in order to do so. The email may also contain instructions on how to decrypt an attachment, such as a zip file password, in order to evade email boundary defenses. Adversaries frequently manipulate file extensions and icons in order to make attached executables appear to be document files, or files exploiting one application appear to be a file for a different one.""",
                "version": "2.0",
                "created": "2020-03-02",
                "contributors": [],
                "data_sources": [
                    "Detonation chamber",
                    "Email gateway",
                    "File monitoring",
                    "Mail server",
                    "Network intrusion detection system"
                    "Packet capture"
                ],
                "platforms": [
                    "Linux",
                    "Windows",
                    "macOS"
                ],
                "tactic": "TA0001",
                "sub_techniques": ["T1566"],
                "permissions_required": [],
                "url": "https://attack.mitre.org/versions/{}/techniques/T1566/001/".format(self.version),
                "procedures": [
                    "admin@338",
                    "APT-C-36",
                    "APT1",
                    "APT12",
                    "APT19",
                    "APT28",
                    "APT29",
                    "APT30",
                    "APT32",
                    "APT33",
                    "APT37",
                    "APT39",
                    "APT41",
                    "BlackTech",
                    "BRONZE BUTLER",
                    "Cobalt Group",
                    "Darkhotel",
                    "DarkHydrus",
                    "Dragonfly 2.0",
                    "Elderwood",
                    "Emotet",
                    "FIN4",
                    "FIN6",
                    "FIN7",
                    "FIN8",
                    "Frankenstein",
                    "Gallmaker",
                    "Gamaredon Group",
                    "Gorgon Group",
                    "Hancitor",
                    "IcedID",
                    "Inception",
                    "Kimsuky",
                    "Lazarus Group",
                    "Leviathan",
                    "Machete",
                    "Magic Hound",
                    "menuPass",
                    "Metamorfo",
                    "Mofang",
                    "Molerats",
                    "MuddyWater",
                    "Naikon",
                    "OceanSalt",
                    "OilRig",
                    "Patchwork",
                    "PLATINUM",
                    "PoetRAT",
                    "Pony",
                    "Rancor",
                    "REvil",
                    "Rifdoor",
                    "RTM",
                    "Sandworm Team",
                    "Sharpshooter",
                    "Silence",
                    "TA459",
                    "TA505",
                    "The White Company",
                    "TrickBot",
                    "Tropic Trooper",
                    "Turla",
                    "Valak",
                    "Windshift",
                    "Wizard Spider"
                ],
                "mitigations": [
                    "M1049",
                    "M1031",
                    "M1021",
                    "M1017"
                ],
                "detection": """Network intrusion detection systems and email gateways can be used to detect spearphishing with malicious attachments in transit. Detonation chambers may also be used to identify malicious attachments. Solutions can be signature and behavior based, but adversaries may construct attachments in a way to avoid these systems.
                Anti-virus can potentially detect malicious documents and attachments as they're scanned to be stored on the email server or on the user's computer. Endpoint sensing or network sensing can potentially detect malicious events once the attachment is opened (such as a Microsoft Word document or PDF reaching out to the internet or spawning Powershell.exe) for techniques such as Exploitation for Client Execution or usage of malicious scripts."""
            },
            "T1566.002": {
                "name": "",
                "description": """""",
                "version": "",
                "created": "",
                "contributors": [],
                "data_sources": [],
                "platforms": [],
                "tactic": "TA0001",
                "sub_techniques": [],
                "permissions_required": [],
                "url": "https://attack.mitre.org/versions/{}/techniques/T1189/".format(self.version),
                "procedures": [],
                "mitigations": [],
                "detection": """"""
            },
            "T1566.003": {
                "name": "",
                "description": """""",
                "version": "",
                "created": "",
                "contributors": [],
                "data_sources": [],
                "platforms": [],
                "tactic": "TA0001",
                "sub_techniques": [],
                "permissions_required": [],
                "url": "https://attack.mitre.org/versions/{}/techniques/T1189/".format(self.version),
                "procedures": [],
                "mitigations": [],
                "detection": """"""
            },
            "T1091": {
                "name": "",
                "description": """""",
                "version": "",
                "created": "",
                "contributors": [],
                "data_sources": [],
                "platforms": [],
                "tactic": "TA0001",
                "sub_techniques": [],
                "permissions_required": [],
                "url": "https://attack.mitre.org/versions/{}/techniques/T1189/".format(self.version),
                "procedures": [],
                "mitigations": [],
                "detection": """"""
            },
            "T1195": {
                "name": "",
                "description": """""",
                "version": "",
                "created": "",
                "contributors": [],
                "data_sources": [],
                "platforms": [],
                "tactic": "TA0001",
                "sub_techniques": [],
                "permissions_required": [],
                "url": "https://attack.mitre.org/versions/{}/techniques/T1189/".format(self.version),
                "procedures": [],
                "mitigations": [],
                "detection": """"""
            },
            "T1195.001": {
                "name": "",
                "description": """""",
                "version": "",
                "created": "",
                "contributors": [],
                "data_sources": [],
                "platforms": [],
                "tactic": "TA0001",
                "sub_techniques": [],
                "permissions_required": [],
                "url": "https://attack.mitre.org/versions/{}/techniques/T1189/".format(self.version),
                "procedures": [],
                "mitigations": [],
                "detection": """"""
            },
            "T1195.002": {
                "name": "",
                "description": """""",
                "version": "",
                "created": "",
                "contributors": [],
                "data_sources": [],
                "platforms": [],
                "tactic": "TA0001",
                "sub_techniques": [],
                "permissions_required": [],
                "url": "https://attack.mitre.org/versions/{}/techniques/T1189/".format(self.version),
                "procedures": [],
                "mitigations": [],
                "detection": """"""
            },
            "T1195.003": {
                "name": "",
                "description": """""",
                "version": "",
                "created": "",
                "contributors": [],
                "data_sources": [],
                "platforms": [],
                "tactic": "TA0001",
                "sub_techniques": [],
                "permissions_required": [],
                "url": "https://attack.mitre.org/versions/{}/techniques/T1189/".format(self.version),
                "procedures": [],
                "mitigations": [],
                "detection": """"""
            },
            "T1199": {
                "name": "",
                "description": """""",
                "version": "",
                "created": "",
                "contributors": [],
                "data_sources": [],
                "platforms": [],
                "tactic": "TA0001",
                "sub_techniques": [],
                "permissions_required": [],
                "url": "https://attack.mitre.org/versions/{}/techniques/T1189/".format(self.version),
                "procedures": [],
                "mitigations": [],
                "detection": """"""
            },
            "T1078": {
                "name": "",
                "description": """""",
                "version": "",
                "created": "",
                "contributors": [],
                "data_sources": [],
                "platforms": [],
                "tactic": "TA0001",
                "sub_techniques": [],
                "permissions_required": [],
                "url": "https://attack.mitre.org/versions/{}/techniques/T1189/".format(self.version),
                "procedures": [],
                "mitigations": [],
                "detection": """"""
            },
            "T1078.001": {
                "name": "",
                "description": """""",
                "version": "",
                "created": "",
                "contributors": [],
                "data_sources": [],
                "platforms": [],
                "tactic": "TA0001",
                "sub_techniques": [],
                "permissions_required": [],
                "url": "https://attack.mitre.org/versions/{}/techniques/T1189/".format(self.version),
                "procedures": [],
                "mitigations": [],
                "detection": """"""
            },
            "T1078.002": {
                "name": "",
                "description": """""",
                "version": "",
                "created": "",
                "contributors": [],
                "data_sources": [],
                "platforms": [],
                "tactic": "TA0001",
                "sub_techniques": [],
                "permissions_required": [],
                "url": "https://attack.mitre.org/versions/{}/techniques/T1189/".format(self.version),
                "procedures": [],
                "mitigations": [],
                "detection": """"""
            },
            "T1078.003": {
                "name": "",
                "description": """""",
                "version": "",
                "created": "",
                "contributors": [],
                "data_sources": [],
                "platforms": [],
                "tactic": "TA0001",
                "sub_techniques": [],
                "permissions_required": [],
                "url": "https://attack.mitre.org/versions/{}/techniques/T1189/".format(self.version),
                "procedures": [],
                "mitigations": [],
                "detection": """"""
            },
            "T1078.004": {
                "name": "",
                "description": """""",
                "version": "",
                "created": "",
                "contributors": [],
                "data_sources": [],
                "platforms": [],
                "tactic": "TA0001",
                "sub_techniques": [],
                "permissions_required": [],
                "url": "https://attack.mitre.org/versions/{}/techniques/T1189/".format(self.version),
                "procedures": [],
                "mitigations": [],
                "detection": """"""
            }
        }
        self._procedures = {
            "APT18": None,
            "APT19": None,
            "APT28": None,
            "APT29": None,
            "APT32": None,
            "APT37": None,
            "APT38": None,
            "APT39": None,
            "APT41": None,
            "Axiom": None,
            "BlackTech": None,
            "Blue Mockingbird": None,
            "BRONZE BUTLER": None,
            "Bundlore": None,
            "Chimera": None,
            "Dark Caracal": None,
            "Darkhotel": None,
            "DarkVishnya": None,
            "Dragonfly": None,
            "Dragonfly 2.0": None,
            "Elderwook": None,
            "FIN5": None,
            "GOLD SOUTHFIELD": None,
            "Havij": None,
            "KARAE": None,
            "Ke3chang": None,
            "Lazarus Group": None,
            "Leafminer": None,
            "Linux Rabbit": None,
            "LoudMiner": None,
            "Night Dragon": None,
            "OilRig": None,
            "Patchwork": None,
            "PLATINUM": None,
            "POORAIM": None,
            "PROMETHIUM": None,
            "REvil": None,
            "Rocke": None,
            "RTM": None,
            "Sandworm Team": None,
            "Soft Cell": None,
            "SoreFang": None,
            "sqlmap": None,
            "TEMP.Veles": None,
            "Threat Group-3390": None,
            "Turla": None,
            "Windshift": None
        }
        self._mitigations = {
            "TEMPLATE": {
                "url": "https://attack.mitre.org/versions/{}/mitigations/M1048/".format(self.version),
                "title": "",
                "description": """
                        """,
                "version": "",
                "created": ""
            },
            "M1016": {
                "url": "https://attack.mitre.org/versions/{}/mitigations/M1021/".format(self.version),
                "title": "",
                "description": """
                                """,
                "version": "",
                "created": ""
            },
            "M1017": {
                "url": "https://attack.mitre.org/versions/{}/mitigations/M1021/".format(self.version),
                "title": "",
                "description": """
                                """,
                "version": "",
                "created": ""
            },
            "M1021": {
                "url": "https://attack.mitre.org/versions/{}/mitigations/M1021/".format(self.version),
                "title": "",
                "description": """
                                """,
                "version": "",
                "created": ""
            },
            "M1026": {
                "url": "https://attack.mitre.org/versions/{}/mitigations/M1021/".format(self.version),
                "title": "",
                "description": """
                                """,
                "version": "",
                "created": ""
            },
            "M1030": {
                "url": "https://attack.mitre.org/versions/{}/mitigations/M1021/".format(self.version),
                "title": "",
                "description": """
                                """,
                "version": "",
                "created": ""
            },
            "M1031": {
                "url": "https://attack.mitre.org/versions/{}/mitigations/M1021/".format(self.version),
                "title": "",
                "description": """
                                """,
                "version": "",
                "created": ""
            },
            "M1032": {
                "url": "https://attack.mitre.org/versions/{}/mitigations/M1021/".format(self.version),
                "title": "",
                "description": """
                                """,
                "version": "",
                "created": ""
            },
            "M1034": {
                "url": "https://attack.mitre.org/versions/{}/mitigations/M1021/".format(self.version),
                "title": "",
                "description": """
                                """,
                "version": "",
                "created": ""
            },
            "M1035": {
                "url": "https://attack.mitre.org/versions/{}/mitigations/M1021/".format(self.version),
                "title": "",
                "description": """
                                """,
                "version": "",
                "created": ""
            },
            "M1042": {
                "url": "https://attack.mitre.org/versions/{}/mitigations/M1021/".format(self.version),
                "title": "",
                "description": """
                                """,
                "version": "",
                "created": ""
            },
            "M1048": {
                "url": "https://attack.mitre.org/versions/{}/mitigations/M1048/".format(self.version),
                "title": "Application Isolation and Sandboxing",
                "description": """
                Restrict execution of code to a virtual environment on or in transit to an endpoint system.
                """,
                "version": "1.1",
                "created": "2019-05-11"
            },
            "M1049": {
                "url": "https://attack.mitre.org/versions/{}/mitigations/M1048/".format(self.version),
                "title": "Application Isolation and Sandboxing",
                "description": """
                Restrict execution of code to a virtual environment on or in transit to an endpoint system.
                """,
                "version": "1.1",
                "created": "2019-05-11"
            },
            "M1050": {
                "url": "https://attack.mitre.org/versions/{}/mitigations/M1050/".format(self.version),
                "title": "",
                "description": """
                                """,
                "version": "",
                "created": ""
            },
            "M1051": {
                "url": "https://attack.mitre.org/versions/{}/mitigations/M1021/".format(self.version),
                "title": "",
                "description": """
                                """,
                "version": "",
                "created": ""
            }
        }
        self._groups = {}
        self._software = {}

    def tactic(self, id=None):

        if id in self._tactics:
            t = Tactic(
                tid=id,
                tname=self._tactics[id]["name"],
                tdescr=self._tactics[id]["description"],
                ttech=self._tactics[id]["techniques"],
                tcreated=self._tactics[id]["created"]
            )
            return t
        else:
            raise UnknownTacticException("The tactic {} is not known in version {} of Mitre ATT&CK".format(id, self.version))

    def technique(self, id=None):

        if id in self._techniques:
            t = Technique(
                id,
                self._techniques[id]["name"],
                self._techniques[id]["description"],
                self._techniques[id]["version"],
                self._techniques[id]["created"],
                self._techniques[id]["contributors"],
                self._techniques[id]["data_sources"],
                self._techniques[id]["platforms"],
                self._techniques[id]["tactic"],
                self._techniques[id]["sub_techniques"],
                self._techniques[id]["permissions_required"],
                self._techniques[id]["url"],
                self._techniques[id]["procedures"],
                self._techniques[id]["mitigations"],
                self._techniques[id]["detection"],
            )
            return t
        else:
            raise UnknownTechniqueException("The tactic {} is not known in version {} of Mitre ATT&CK".format(id, self.version))


class Tactic:

    def __init__(self, tid, tname, tdescr, ttech, tcreated):
        self.id = tid
        self.name = tname
        self.description = tdescr
        self.techniques = ttech
        self.created = tcreated


class Technique:

    def __init__(self, id, name, descr, version, created, contr, sources, platforms, tactic, subtech, permissions, url, proc, mit, detect):
        self.id = id
        self.name = name
        self.description = descr
        self.version = version
        self.created = created
        self.contributors = contr
        self.data_sources = sources
        self.platforms = platforms
        self.tactic = tactic
        self.sub_techniques = subtech
        self.permissions_required = permissions
        self.url = url
        self.procedures = proc
        self.mitigations = mit
        self.detection = detect


class UnknownTacticException(Exception):
    pass


class UnknownTechniqueException(Exception):
    pass
