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
            stage('test') {
                steps {
                    sh """
                        echo "Testing stage"
                    """
                }
            }
        }
  }
}