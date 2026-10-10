pipeline {
    agent any

    options {
        timeout(time: 10, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    environment {
        // Jenkins runs as a Windows service, so it does not see your user PATH.
        // Use the full path to python.exe (check yours with: where python)
        PYTHON = 'C:\\Users\\LENOVO\\AppData\\Local\\Programs\\Python\\Python313\\python.exe'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Python check') {
            steps {
                bat '"%PYTHON%" --version'
            }
        }

        stage('Dependency Quarantine Gate') {
            steps {
                // Fails the build if a package is malicious, younger than 7 days,
                // or if the OSV lookup could not be completed.
                bat '"%PYTHON%" gate.py --path . --min-age-days 3650 --require-network --out gate-report'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'gate-report/**', allowEmptyArchive: true
        }
        success {
            echo 'Gate PASSED: no malicious or very fresh packages found. Check warnings for known vulnerabilities.'
        }
        failure {
            echo 'Gate FAILED: check the console output and the gate-report artifact.'
        }
    }
}
