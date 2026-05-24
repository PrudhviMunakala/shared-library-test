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
            stage('Run tests') {
                steps {
                    sh "npm test"
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
                    timeout(time: 1, unit: 'HOURS') {
                        waitForQualityGate abortPipeline: true
                    }
                }
            }
            stage('Dependabot Security Scan') {
                steps {
                    withCredentials([string(credentialsId: 'github-token', variable: 'GITHUB_TOKEN')]) {
                        script {
                            def repoOwner = 'PrudhviMunakala'
                            def repoName  = "${component}"
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
                                error("GitHub API call failed with HTTP ${httpStatus}.")
                            }
                            def alerts      = readJSON text: responseBody
                            def totalAlerts = alerts.size()
                            if (totalAlerts == 0) {
                                echo "✅ No HIGH or CRITICAL Dependabot alerts found."
                            } else {
                                def criticalAlerts = alerts.findAll { it.security_advisory?.severity?.toUpperCase() == 'CRITICAL' }
                                def highAlerts     = alerts.findAll { it.security_advisory?.severity?.toUpperCase() == 'HIGH' }
                                error("Pipeline failed: Found ${criticalAlerts.size()} CRITICAL and ${highAlerts.size()} HIGH alerts.")
                            }
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
            stage('Trivy Image Scan') {
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
                            error "🚨 Trivy found HIGH/MEDIUM misconfigurations. Pipeline failed."
                        } else {
                            echo "✅ No HIGH or MEDIUM misconfigurations found."
                        }
                    }
                }
            }
            stage('Push Image') {
                steps {
                    withAWS(credentials: 'aws-creds', region: "${region}") {
                        sh """
                            aws ecr get-login-password --region ${region} | docker login --username AWS --password-stdin ${acc_id}.dkr.ecr.${region}.amazonaws.com
                            docker push ${acc_id}.dkr.ecr.${region}.amazonaws.com/${project}/${component}:${env.appVersion}
                        """                                                                                               // ✅ env.appVersion
                    }
                }
            }
        }
    }
}