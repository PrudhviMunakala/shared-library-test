def call (Map configMap){
    pipeline {
        agent {
            node {
                label 'roboshop'
            }
        }
        environment {
            acc_id    = "534409839269"
            region    = "us-east-1"
            project   = "${configMap.project}"
            component = "${configMap.component}"
        }
        options {
            timeout(time: 15, unit: 'MINUTES')
        }
        parameters {
            booleanParam(name: 'DEPLOY', defaultValue: false, description: 'deploy to dev environment')
        }
        stages {
            stage('Read version') {
                steps {
                    script {
                        def packageJson  = readJSON file: 'package.json'
                        env.appVersion   = packageJson.version       // ✅ set globally
                        echo "Building version ${env.appVersion}"
                    }
                }
            }
            stage('Install dependencies') {
                steps {
                    sh "npm install"
                }
            }
            stage('unit tests') {
                steps {
                     script{
                        def testResult = sh(script: 'npm test', returnStatus: true)
                        if (testResult != 0) {
                            utils.updateCommitStatus('failure', 'Unit tests failed', 'unit-tests')
                            error "Unit tests failed."
                        } else {
                            utils.updateCommitStatus('success', 'Unit tests passed', 'unit-tests')
                        }
                    }
                }
            }
            stage('SonarQube Analysis') {
                steps {
                    script {
                        def scannerHome = tool name: 'sonar-8'
                        withSonarQubeEnv('sonar-server') {
                            sh "${scannerHome}/bin/sonar-scanner"
                        }
                    }
                }
            }
            stage('Quality Gate') {
                steps {
                    script {
                        timeout(time: 1, unit: 'HOURS') {
                            def qg = waitForQualityGate()
                            if (qg.status != 'OK') {
                                utils.updateCommitStatus('failure', "SonarQube quality gate failed: ${qg.status}", 'sonar-scan')
                                error "Quality gate failed: ${qg.status}"
                            } else {
                                utils.updateCommitStatus('success', 'SonarQube quality gate passed', 'sonar-scan')
                            }
                        }
                    }
                }
            }
            stage('Dependabot Security Scan') {
                steps {
                    script {
                        withCredentials([string(credentialsId: 'github-token', variable: 'GITHUB_TOKEN_SCAN')]) {
                            def repoUrl = sh(script: 'git remote get-url origin', returnStdout: true).trim()
                            def repoPath = repoUrl.replaceAll(/.*github\.com[\/:]/, '').replaceAll(/\.git$/, '')

                            def alertCount = sh(
                                script: """
                                    curl -sf \
                                        -H "Authorization: Bearer \$GITHUB_TOKEN_SCAN" \
                                        -H "Accept: application/vnd.github+json" \
                                        -H "X-GitHub-Api-Version: 2022-11-28" \
                                        "https://api.github.com/repos/${repoPath}/dependabot/alerts?state=open&per_page=100" \
                                    | jq '[.[] | select(.security_vulnerability.severity == "high" or .security_vulnerability.severity == "critical")] | length'
                                """,
                                returnStdout: true
                            ).trim()

                            if (alertCount.toInteger() > 0) {
                                utils.updateCommitStatus('failure', "${alertCount} HIGH/CRITICAL Dependabot alert(s) detected", 'library-scan')
                                error("Build aborted: ${alertCount} HIGH/CRITICAL Dependabot alert(s) detected. Resolve them before proceeding.")
                            }
                            utils.updateCommitStatus('success', 'Dependabot check passed — no HIGH/CRITICAL alerts', 'library-scan')
                            echo "Dependabot check passed — no HIGH or CRITICAL vulnerabilities found."
                        }
                    }
                }
            }
            stage('Build Image') {
                steps {
                    sh """
                        docker build -t ${acc_id}.dkr.ecr.${region}.amazonaws.com/${project}/${component}:${env.appVersion} .
                    """                                                                                  // ✅ env.appVersion
                }
            }
            stage('Trivy os Scan') {
                steps {
                    script {
                        // Generate table report
                        sh """
                            trivy image \
                                --scanners vuln \
                                --pkg-types os \
                                --severity HIGH,MEDIUM \
                                --format table \
                                --output trivy-os-report.txt \
                                --exit-code 0 \
                                ${acc_id}.dkr.ecr.${region}.amazonaws.com/${project}/${component}:${appVersion}
                        """

                        // Print table to console
                        sh 'cat trivy-os-report.txt'

                        // Fail pipeline if vulnerabilities found
                        def scanResult = sh(
                            script: """
                                trivy image \
                                    --scanners vuln \
                                    --pkg-types os \
                                    --severity HIGH,MEDIUM \
                                    --format table \
                                    --exit-code 1 \
                                    --quiet \
                                    ${acc_id}.dkr.ecr.${region}.amazonaws.com/${project}/${component}:${appVersion}
                            """,
                            returnStatus: true
                        )

                        if (scanResult != 0) {
                            utils.updateCommitStatus('failure', 'Trivy OS scan: HIGH/MEDIUM vulnerabilities found', 'trivy-scan')
                            error "🚨 Trivy found HIGH/MEDIUM OS vulnerabilities. Pipeline failed."
                        } else {
                            utils.updateCommitStatus('success', 'Trivy OS scan passed — no HIGH/MEDIUM vulnerabilities', 'trivy-scan')
                            echo "✅ No HIGH or MEDIUM OS vulnerabilities found. Pipeline continues."
                        }
                    }
                }
            }
             stage('Trivy Dockerfile Scan'){
                steps {
                    script {
                        sh """
                            trivy config \
                                --severity HIGH,MEDIUM \
                                --format table \
                                --output trivy-dockerfile-report.txt \
                                Dockerfile
                        """

                        sh 'cat trivy-dockerfile-report.txt'

                        def scanResult = sh(
                            script: """
                                trivy config \
                                    --severity HIGH,MEDIUM \
                                    --exit-code 1 \
                                    --format table \
                                    Dockerfile
                            """,
                            returnStatus: true
                        )

                        if (scanResult != 0) {
                            error "🚨 Trivy found HIGH/MEDIUM misconfigurations in Dockerfile. Pipeline failed."
                        } else {
                            echo "✅ No HIGH or MEDIUM Dockerfile misconfigurations found. Pipeline continues."
                        }
                    }
                }
            }
            stage('Push Image') {
                steps {
                     script {
                        try {
                            withAWS(credentials: 'aws-creds', region: "${region}") {
                                sh """
                                    aws ecr get-login-password --region ${region} | docker login --username AWS --password-stdin ${acc_id}.dkr.ecr.us-east-1.amazonaws.com
                                    docker push ${acc_id}.dkr.ecr.${region}.amazonaws.com/${project}/${component}:${appVersion}
                                """
                            }
                            utils.updateCommitStatus('success', "Image ${appVersion} pushed to ECR", 'push-image')
                        } catch (err) {
                            utils.updateCommitStatus('failure', 'Failed to push image to ECR', 'push-image')
                            throw err
                        }
                    }
                }
            }
        }
    }
}