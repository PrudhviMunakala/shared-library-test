def call(map ConfigMap) {
    pipeline {
        agent {
            node {
                label 'roboshop'
            }
        }
        environment {
            appVersion = ""
            AWS_ACCOUNT_ID = "534409839269"
            region = "us-east-1"
            GITHUB_TOKEN = credentials('github-token')
        }
        stages {
            stage('Read version') {
                steps {
                    script {
                        def packageJson = readJSON file: 'package.json'
                        appVersion = packageJson.version
                        echo "Building version ${appVersion}"
                    }
                }
            }

            // stage('Install dependencies') {
            //     steps {
            //         sh """
            //             npm install
            //         """
            //     }
            // }

            stage('Dependabot Security Scan') {
                steps {
                    script {
                        def repoOwner = 'PrudhviMunakala'
                        def repoName  = 'catalogue'

                        def response = sh(
                            script: """
                                curl -s -w "\\nHTTP_STATUS:%{http_code}" \\
                                -H "Authorization: Bearer \${GITHUB_TOKEN}" \\
                                -H "Accept: application/vnd.github+json" \\
                                -H "X-GitHub-Api-Version: 2022-11-28" \\
                                "https://api.github.com/repos/${repoOwner}/${repoName}/dependabot/alerts?state=open&severity=high,critical&per_page=100"
                            """,
                            returnStdout: true
                        ).trim()

                        def bodyAndStatus = response.split('HTTP_STATUS:')
                        def responseBody  = bodyAndStatus[0].trim()
                        def httpStatus    = bodyAndStatus[1].trim()

                        if (httpStatus != '200') {
                            error("GitHub API call failed with HTTP ${httpStatus}. Check your GITHUB_TOKEN and repo permissions.")
                        }

                        def alerts      = readJSON text: responseBody
                        def totalAlerts = alerts.size()

                        if (totalAlerts == 0) {
                            echo "✅ No HIGH or CRITICAL Dependabot alerts found. Pipeline is safe to proceed."
                        } else {
                            def criticalAlerts = alerts.findAll { it.security_advisory?.severity?.toUpperCase() == 'CRITICAL' }
                            def highAlerts     = alerts.findAll { it.security_advisory?.severity?.toUpperCase() == 'HIGH' }

                            echo "❌ Dependabot Security Scan FAILED!"
                            echo "   CRITICAL : ${criticalAlerts.size()}"
                            echo "   HIGH     : ${highAlerts.size()}"
                            echo "=== Vulnerable Packages ==="

                            alerts.each { alert ->
                                def severity  = alert.security_advisory?.severity?.toUpperCase()
                                def pkg       = alert.dependency?.package?.name
                                def ecosystem = alert.dependency?.package?.ecosystem
                                def cvss      = alert.security_advisory?.cvss?.score ?: 'N/A'
                                def cveId     = alert.security_advisory?.cve_id      ?: 'N/A'
                                def summary   = alert.security_advisory?.summary     ?: 'N/A'
                                def fixedIn   = alert.security_vulnerability?.first_patched_version?.identifier ?: 'No fix available'
                                def alertUrl  = alert.html_url

                                echo """
                                ----------------------------------------
                                [${severity}] ${pkg} (${ecosystem})
                                CVE      : ${cveId}
                                CVSS     : ${cvss}
                                Summary  : ${summary}
                                Fix In   : ${fixedIn}
                                URL      : ${alertUrl}
                                ----------------------------------------"""
                            }
                            error("Pipeline failed: Found ${criticalAlerts.size()} CRITICAL and ${highAlerts.size()} HIGH Dependabot alerts.")
                        }
                    }
                }
            }

            stage('Build Image') {        // ← only docker build here
                steps {
                    sh """
                        docker build -t ${AWS_ACCOUNT_ID}.dkr.ecr.${region}.amazonaws.com/roboshop/catalogue:${appVersion} .
                    """
                }
            }

            stage('Trivy Image Scan') {
                steps {
                    script {
                        def imageName = "${AWS_ACCOUNT_ID}.dkr.ecr.${region}.amazonaws.com/roboshop/catalogue:${appVersion}"

                        sh """
                            trivy image \
                                --severity HIGH,CRITICAL \
                                --vuln-type os \
                                --exit-code 0 \
                                --quiet \
                                --format template \
                                --template "@/usr/local/share/trivy/templates/html.tpl" \
                                --output trivy-report.html \
                                ${imageName}
                        """

                        def trivyExitCode = sh(
                            script: """
                                trivy image \
                                    --severity HIGH,CRITICAL \
                                    --vuln-type os \
                                    --exit-code 1 \
                                    --quiet \
                                    ${imageName}
                            """,
                            returnStatus: true
                        )

                        if (trivyExitCode == 1) {
                            error("❌ Trivy scan FAILED: HIGH or CRITICAL OS vulnerabilities found.")
                        } else {
                            echo "✅ Trivy scan PASSED: No HIGH or CRITICAL OS vulnerabilities found."
                        }
                    }
                }
            
            }

            stage('Push Image') {         // ← renamed from 'Build Image' to 'Push Image'
                steps {
                    withAWS(credentials: 'aws-creds', region: "${region}") {
                        sh """
                            aws ecr get-login-password --region ${region} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${region}.amazonaws.com
                            docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${region}.amazonaws.com/roboshop/catalogue:${appVersion}
                        """
                    }
                }
            }
        }
  }
}