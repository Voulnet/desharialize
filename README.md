
# Desharialize
Desharialize: Easy mode to Exploit CVE-2019-0604 (Sharepoint XML Deserialization Unauthenticated RCE)

## What is it?

While there have been public POCs for CVE-2019-0604, I have noticed that those POCs are not clear, extensible or flexible. Some of them only have on hardcoded (and serialized/encoded) payloads, some of them require running custom .NET code before every payload, and some would run the payload on your machine first during the serialization process. I have reversed and analyzed the simple serialization/encoding algorithm used by Sharepoint, and I have created a raw template that can be used to serialize any custom payload on the fly without having to run .NET code for each payload, or run payloads that you can't read.

Find below usage examples for Desharialize as well as a brief explanation of the serialization process.

## Assumptions

To better utilize this tool in pentesting Sharepoint:
- It is assumed that you know what is the Sharepoint CVE-2019-0604
- It is assumed that you have found a vulnerable (Unpatched) Sharepoint server.
- It is assumed that you have found a vulnerable endpoint on that Sharepoint server (e.g. example.com/_layouts/15/Picker.aspx)


## Prerequisites

- Python 3.
- The requirements listed in the requirements.txt file


## Installing

pip3 install -r requirements.txt


Better to create a virtualenv environment for the tool. Please note that using sudo with pip is not recommended.


## Author

* **Mohammed Aldoub**, also known as **Voulnet**, find me on [Twitter](https://www.twitter.com/Voulnet)

## Main Features

- Run custom serialized payloads on targets (Make sure you have authorization from system owners!).
- Launch the payload on any vulnerable Sharepoint version without having to look for compatible Assembly names.
- No need to play musical chairs with dynamically changing VIEWSTATE and EVENTVALIDATION values, Desharialize scrapes them from the target automatically.
- Make pentesting Sharepoint fun again.
- This tool is aimed at testing Picker.aspx endpoints in particular. Not tested at other endpoints.
- This tool runs commands through the target's command shell using Sharepoint privilges, but no way to read output directly.
- To read output, another channel is needed: Sending result through HTTP, DNS or other options.
- Burp Collaborator can help!

## Contributing

PRs are welcome!

### TODO:

- More testing against a wider range of versions and service packs for Sharepoint.
- Integrate fully with Metasploit.

## Detection

Check your web server logs for request containing "71e9bce111e9429c"
For more awesome detection steps, Snort and Sigma rules, please visit: [Mansour Alsaidie Blog](https://adraft.page/index.php/2019/09/14/cve-2019-0604-sharepoint-rce-forensics-analysis-and-detection-methods/)

## References and further info

[Mansour Alsaidie Blog](https://adraft.page/index.php/2019/09/14/cve-2019-0604-sharepoint-rce-forensics-analysis-and-detection-methods/)

[ZDI](https://www.zerodayinitiative.com/blog/2019/3/13/cve-2019-0604-details-of-a-microsoft-sharepoint-rce-vulnerability)

[k8gege POC](https://github.com/k8gege/CVE-2019-0604)

## Disclaimer

By using this tool, you absolve the tool author from any effect or repercussions resulting, directly or indirectly, from usage of this tool. This tool is provided as is, with no waranty or guarantee. This tool must only be used on legally authorized targets, and by using this tool you hereby declare that you have obtained proper legal permission from the tested targets, and that you fully absolve the tool author from any and all means and results, directly or indirectly, of utilizing this free open source tool. 

## Questions?

- Raise an issue here in Github.
- Contact me on Twitter.
