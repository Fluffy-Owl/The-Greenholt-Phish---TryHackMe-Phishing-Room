# The Greenholt Phish - TryHackMe Walkthrough

## Overview
In this lab, we analyze a phishing email and investigate the domain and infrastructure behind the phishing campaign. This walkthrough covers the following aspects:
- Email header analysis
- Domain investigation
- Phishing kit identification

## Objectives
- Analyze the phishing email header.
- Investigate the domain hosting the phishing kit.
- Uncover details about the phishing infrastructure.

## Tools Used
- **TryHackMe**: For the environment and challenge scenario.
- **Email Header Analyzer**: For reviewing the email header.
- **WHOIS Lookup**: For gathering domain information.
- **VirusTotal**: To check the reputation of the phishing domain.
- **curl**: For downloading phishing kit archives.

---

## Step-by-Step Walkthrough

### 1. Analyze the Phishing Email
The phishing email contained a link to a suspicious domain, leading to a fake login page. Here’s how the email analysis was performed:

- **Email Header Analysis**: The email header provides clues about the sender, relay servers, and potential spoofing. In this case, the sender's domain did not match the displayed domain, indicating spoofing.
  
  Example of analyzing the `Received` headers to trace the source:
  ```
  Received: from unknown.domain ([XX.XX.XX.XX])
  ```

- **Links in the Email**: The phishing email contained a URL redirecting the user to a fake login page:
  ```
  hxxp://kennaroads.buzz/login
  ```

### 2. Investigating the Phishing Domain
We used several tools to investigate the domain mentioned in the phishing email.

- **WHOIS Lookup**: To gather registration details of the domain `kennaroads.buzz`. The WHOIS information pointed to a recently registered domain, commonly used in phishing campaigns.
  
- **VirusTotal**: The domain was submitted to VirusTotal for reputation analysis. VirusTotal flagged it as malicious, confirming that it was being used in phishing activities.

- **curl**: Using `curl`, we attempted to retrieve the contents of the phishing site, particularly focusing on the phishing kit:
  ```bash
  curl -O hxxp://kennaroads.buzz/phishingkit.zip
  ```

  The downloaded phishing kit archive revealed fake login pages used for credential harvesting.

### 3. Identifying the Phishing Kit
By analyzing the files in the phishing kit, we found that the phishing kit contained HTML files mimicking legitimate login portals, as well as scripts for collecting user credentials. The investigation uncovered:

- **Phishing page HTML**: Fake login forms designed to look identical to a legitimate service.
- **Credential collection scripts**: PHP scripts that captured credentials and forwarded them to an attacker-controlled email address.

---

## Conclusion
In this lab, we successfully identified a phishing email, investigated the domain hosting the phishing page, and uncovered a phishing kit used for credential harvesting. This exercise provided valuable insight into phishing tactics and how to respond to them.

---

## References
- [TryHackMe - The Greenholt Phish](https://tryhackme.com/room/thegreenholtphish)
- [VirusTotal](https://www.virustotal.com)
- [WHOIS Lookup](https://whois.domaintools.com/)

---
