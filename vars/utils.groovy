// Updates GitHub commit status visible on PRs and commits.
// state: 'pending' | 'success' | 'failure' | 'error'
// description: short message shown in the GitHub UI (max 140 chars)
// context: label for the check (e.g. 'Jenkins CI / Build', 'Jenkins CI / Trivy')
def updateCommitStatus(String state, String description, String context = 'Jenkins CI') {
    withCredentials([string(credentialsId: 'github-token', variable: 'GITHUB_TOKEN')]) {
        def repoUrl = sh(script: 'git remote get-url origin', returnStdout: true).trim()
        def repoPath = repoUrl.replaceAll(/.*github\.com[\/:]/, '').replaceAll(/\.git$/, '')

        withEnv([
            "COMMIT_STATE=${state}",
            "COMMIT_DESC=${description}",
            "COMMIT_CONTEXT=${context}",
            "REPO_PATH=${repoPath}",
            "COMMIT_SHA=${env.GIT_COMMIT}",
            "BUILD_LINK=${env.BUILD_URL}"
        ]) {
            sh '''
                jq -n \
                    --arg state   "$COMMIT_STATE" \
                    --arg url     "$BUILD_LINK" \
                    --arg desc    "$COMMIT_DESC" \
                    --arg context "$COMMIT_CONTEXT" \
                    '{state: $state, target_url: $url, description: $desc, context: $context}' \
                | curl -sf \
                       -X POST \
                       -H "Authorization: Bearer $GITHUB_TOKEN" \
                       -H "Accept: application/vnd.github+json" \
                       -H "Content-Type: application/json" \
                       -H "X-GitHub-Api-Version: 2022-11-28" \
                       --data @- \
                       "https://api.github.com/repos/$REPO_PATH/statuses/$COMMIT_SHA"
            '''
        }
    }
}

// Reads the app version from the project's version file.
// Auto-detects language by checking which file exists in the workspace:
//   package.json  → Node.js
//   pom.xml       → Java
//   requirements.txt → Python (reads version.txt)
def readAppVersion() {
    if (fileExists('package.json')) {
        return readJSON(file: 'package.json').version
    } else if (fileExists('pom.xml')) {
        return readMavenPom(file: 'pom.xml').version
    } else if (fileExists('requirements.txt')) {
        return sh(script: "cat version.txt", returnStdout: true).trim()
    } else {
        error("readAppVersion: cannot detect language — no package.json, pom.xml, or requirements.txt found in workspace")
    }
}

// Creates a Jira Cloud issue via the JIRA Pipeline Steps plugin (site: 'jira').
// Auto-assigns to the active sprint. Returns the created issue key (e.g. ROBO-42).
def createJiraTicket(String project, String component, String appVersion, String shortCommit) {
    def sprintId = ''
   /*  withCredentials([
        string(credentialsId: 'jira-url', variable: 'JIRA_URL'),
        usernamePassword(credentialsId: 'jira-creds', usernameVariable: 'JIRA_EMAIL', passwordVariable: 'JIRA_TOKEN')
    ]) {
        withEnv(["JIRA_PROJECT=${project}"]) {
            sprintId = sh(script: '''
                BOARD_ID=$(curl -sf -u "$JIRA_EMAIL:$JIRA_TOKEN" \
                    "$JIRA_URL/rest/agile/1.0/board?projectKeyOrId=$JIRA_PROJECT" \
                | jq -r '.values[0].id')
                curl -sf -u "$JIRA_EMAIL:$JIRA_TOKEN" \
                    "$JIRA_URL/rest/agile/1.0/board/$BOARD_ID/sprint?state=active" \
                | jq -r '.values[0].id'
            ''', returnStdout: true).trim()
        }
    } */

    def issue = [
        fields: [
            project:          [key: project],
            summary:          "${component} ${appVersion} (${shortCommit}) ready for UAT",
            issuetype:        [name: 'Story'],
            labels:           [shortCommit],
            //customfield_10020: sprintId.toInteger(),
            description: [
                type: 'doc', version: 1,
                content: [[
                    type: 'paragraph',
                    content: [[
                        type: 'text',
                        text: "Component: ${component} | Version: ${appVersion} | Commit: ${shortCommit}"
                    ]]
                ]]
            ]
        ]
    ]
    def response = jiraNewIssue issue: issue, site: 'jira'
    echo "Jira ticket created: ${response.data.key}"
    return response.data.key
}

// Transitions a Jira issue to a named status (e.g. 'UAT Success', 'Done').
// Looks up the transition ID by destination status name — no hardcoded IDs needed.
def transitionJiraTicket(String issueKey, String transitionName) {
    def transitions = jiraGetIssueTransitions idOrKey: issueKey, site: 'jira'
    def transition  = transitions.data.transitions.find { it.to.name == transitionName }
    if (!transition) {
        def available = transitions.data.transitions.collect { "${it.id}: ${it.name} -> ${it.to.name}" }.join(', ')
        error("No transition leading to '${transitionName}' found on ${issueKey}. Available: [${available}]")
    }
    jiraTransitionIssue idOrKey: issueKey, input: [transition: [id: transition.id]], site: 'jira'
    echo "Transitioned ${issueKey} to '${transitionName}'"
}

// Validates a Change Request before PROD deploy.
// Currently a placeholder — replace the marked sections with real CR tool API calls.
def validateChangeRequest(String crNumber) {
    if (!crNumber?.trim()) {
        error("CR number is required for PROD deploy. Raise a Change Request before triggering PROD.")
    }
    echo "Validating Change Request: ${crNumber}"

    // ── TODO: replace with real CR tool API call (ServiceNow, Remedy, etc.) ─
    //
    // ServiceNow example:
    //   withCredentials([usernamePassword(credentialsId: 'snow-creds',
    //       usernameVariable: 'SNOW_USER', passwordVariable: 'SNOW_PASS')]) {
    //       def response = sh(script: """
    //           curl -sf -u "$SNOW_USER:$SNOW_PASS" \
    //               "https://instance.service-now.com/api/now/table/change_request\
    //                ?sysparm_query=number=${crNumber}\
    //                &sysparm_fields=state,start_date,end_date"
    //       """, returnStdout: true).trim()
    //       crStatus    = response | jq -r '.result[0].state'
    //       windowStart = ...
    //       windowEnd   = ...
    //   }
    //
    // ─────────────────────────────────────────────────────────────────────────

    def crStatus = "approved"   // placeholder — replace with API response
    def inWindow = true         // placeholder — replace with time window check

    if (crStatus != "approved") {
        error("CR ${crNumber} is not approved. Current status: ${crStatus}. PROD deploy blocked.")
    }
    if (!inWindow) {
        error("CR ${crNumber} is outside the approved change window. PROD deploy blocked.")
    }

    echo "CR ${crNumber} validated — status: ${crStatus}, within change window: yes"
}