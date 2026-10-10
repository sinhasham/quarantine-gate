pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Python check') {
            steps {
                bat '"C:\\Users\\LENOVO\\AppData\\Local\\Programs\\Python\\Python313\\python.exe" --version'
            }
        }

        stage('Dependency Quarantine Gate') {
            steps {
                bat '"C:\\Users\\LENOVO\\AppData\\Local\\Programs\\Python\\Python313\\python.exe" gate.py --path . --min-age-days 3650 --require-network'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'gate-report/**', allowEmptyArchive: true
        }
    }
}