#!/usr/bin/env python3

__copyright__ = "Copyright (c) Microsoft Corporation."

import argparse
import requests
import base64
import json
import subprocess
from sys import exit

parser = argparse.ArgumentParser()
parser.add_argument("--ado-org", help="Name of the Azure DevOps organization", required=True)
parser.add_argument("--ado-project", help="Name of the Azure DevOps project", required=True)
parser.add_argument("--ado-access-token", help="Azure DevOps access token", required=True)
parser.add_argument("--token-type", help="Token type: PAT or OAUTH", default="OAUTH")
parser.add_argument("--repo-id", help="Repository ID", required=True)
parser.add_argument("--pr-id", help="Pull Request ID", required=True)
parser.add_argument("--source-branch", help="Source branch of the pull request", required=True)
args = parser.parse_args()

PR_API_BASE_URL = f"https://dev.azure.com/{args.ado_org}/{args.ado_project}/_apis/git/repositories/{args.repo_id}/pullRequests/{args.pr_id}"
auth_headers = {}
if args.token_type == "OAUTH":
    auth_headers = {
        "Authorization": f"Bearer {args.ado_access_token}",
    }
else:
    b64_token = base64.b64encode(f":{args.ado_access_token}".encode("ascii")).decode("ascii")
    auth_headers = {
        "Authorization": f"Basic {b64_token}",
    }

def separator():
    print('-' * 100)

def comment_on_pr(comment_text):
    payload = {
        "comments": [
            {
                "parentCommentId": 0,
                "content": comment_text,
                "commentType": 1,
            }
        ],
        "status": 1
    }

    api_url = f"{PR_API_BASE_URL}/threads?api-version=6.0"
    resp = requests.post(api_url, json=payload, headers=auth_headers)
    print(f"Comment API returned {resp.status_code}")
    if (resp.status_code != 200):
        print(resp.text)

def deepen(depth):
    print(f"Fetch {args.source_branch} with depth {depth}")
    result = subprocess.run(["git", "fetch", f"--depth={depth}", "origin", args.source_branch], capture_output=True)
    if result.returncode == 0:
        return

    print(f"git fetch failed with exit code: {result.returncode}")
    print(result.stdout.decode("ascii"))
    print(result.stderr.decode("ascii"))

def is_merge_commit(commit_id):
    result = subprocess.run([f"git show --summary {commit_id} | grep -q ^Merge:"], shell=True)
    if result.returncode == 0:
        return True

    return False

def main():
    commits_api_url = f"{PR_API_BASE_URL}/commits?api-version=6.0"
    resp = requests.get(commits_api_url, headers=auth_headers)
    commits_json = resp.json()

    commits = [commit for commit in commits_json["value"]]

    separator()
    print(f"The PR has {len(commits)} commits")
    separator()

    # The pipeline does a shallow fetch. Deepen it a bit to find the PR's
    # commits.
    deepen(len(commits) + 1)

    has_issues = False
    for commit in commits:
        commit_id = commit["commitId"]
        comment = commit["comment"]
        print(f"{commit_id}: {comment}")

        if is_merge_commit(commit_id):
            print("Is a merge commit. Skipping.")
            separator()
            continue

        print("Running scripts/checkpatch.pl")
        result = subprocess.run(
            ["./scripts/checkpatch.pl", "-g", commit_id],
            capture_output=True,
        )

        output = result.stdout.decode("ascii")
        print(output)
        print(f"Exit code: {result.returncode}")

        if result.returncode != 0:
            has_issues = True
            print(result.stderr.decode("ascii"))
            print("Commenting on PR")
            html_output = output.replace("\n", "<br/>")
            comment = f"checkpatch.pl found issues:<pre>{html_output}</pre>"
            comment_on_pr(comment)

        separator()

    if has_issues:
        exit(1)

main()
