pipeline {
    agent any
    
    environment {
        TRIVY_VERSION = '0.45.0'
        APP_NAME = 'vulnerable-python-app'
        APP_VERSION = "${BUILD_NUMBER}"
        DOCKER_IMAGE = "${APP_NAME}:${APP_VERSION}"
        // Security thresholds
        MAX_CRITICAL = '5'
        MAX_HIGH = '10'
        MAX_MEDIUM = '20'
    }
    
    stages {
        stage('Checkout') {
            steps {
                echo 'Code already checked out by Jenkins SCM'
                sh '''
                    echo "Repository: ${GIT_URL}"
                    echo "Branch: ${GIT_BRANCH}"
                    echo "Commit: ${GIT_COMMIT}"
                    ls -la
                '''
            }
        }
        
        stage('Build Application') {
            steps {
                echo 'Building vulnerable Python application...'
                script {
                    sh '''
                        # Remove existing image if it exists
                        docker rmi ${DOCKER_IMAGE} 2>/dev/null || echo "Image not found, continuing..."
                        
                        # Build the application with build args
                        docker build \
                            --build-arg BUILD_NUMBER=${BUILD_NUMBER} \
                            --build-arg GIT_COMMIT=${GIT_COMMIT} \
                            -t ${DOCKER_IMAGE} .
                        
                        # Also tag as latest for convenience
                        docker tag ${DOCKER_IMAGE} ${APP_NAME}:latest
                        
                        # Verify image was built
                        echo "Built images:"
                        docker images | grep ${APP_NAME}
                    '''
                }
            }
        }
        
        stage('Test Application') {
            steps {
                echo 'Testing application container...'
                script {
                    sh '''
                        # Start container in background for testing
                        echo "Starting test container..."
                        docker run -d --name test-app-${BUILD_NUMBER} -p 5001:5001 ${DOCKER_IMAGE}
                        
                        # Wait for container to start
                        sleep 10
                        
                        # Check if container is still running (basic health check)
                        if docker ps | grep test-app-${BUILD_NUMBER}; then
                            echo "✅ Container is running successfully"
                            
                            # Check application logs
                            echo "Application logs:"
                            docker logs test-app-${BUILD_NUMBER}
                            
                            # Simple connectivity test using docker exec
                            echo "Testing application response..."
                            docker exec test-app-${BUILD_NUMBER} python -c "
import socket
import sys

# Test if port 5001 is listening
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
result = sock.connect_ex(('localhost', 5001))
sock.close()

if result == 0:
    print('✅ Application is listening on port 5001')
    sys.exit(0)
else:
    print('❌ Application is not responding on port 5001')
    sys.exit(1)
"
                            
                        else
                            echo "❌ Container failed to start or stopped unexpectedly"
                            docker logs test-app-${BUILD_NUMBER}
                            exit 1
                        fi
                        
                        echo "Basic application tests completed!"
                    '''
                }
            }
            post {
                always {
                    // Clean up test container
                    sh '''
                        docker stop test-app-${BUILD_NUMBER} 2>/dev/null || true
                        docker rm test-app-${BUILD_NUMBER} 2>/dev/null || true
                    '''
                }
            }
        }
        
        stage('Trivy Security Scan') {
            steps {
                script {
                    echo 'Running comprehensive Trivy security scan...'
                    
                    sh '''
                        # Create reports directory
                        mkdir -p trivy-reports
                        
                        # Run comprehensive Trivy scan
                        docker run --rm \
                            -v /var/run/docker.sock:/var/run/docker.sock \
                            -v ${WORKSPACE}/trivy-reports:/reports \
                            aquasec/trivy:${TRIVY_VERSION} image \
                            --format table \
                            --output /reports/trivy-detailed-report.txt \
                            ${DOCKER_IMAGE}
                        
                        # Generate JSON report for parsing
                        docker run --rm \
                            -v /var/run/docker.sock:/var/run/docker.sock \
                            -v ${WORKSPACE}/trivy-reports:/reports \
                            aquasec/trivy:${TRIVY_VERSION} image \
                            --format json \
                            --output /reports/trivy-report.json \
                            ${DOCKER_IMAGE}
                        
                        # Generate severity-specific reports
                        docker run --rm \
                            -v /var/run/docker.sock:/var/run/docker.sock \
                            -v ${WORKSPACE}/trivy-reports:/reports \
                            aquasec/trivy:${TRIVY_VERSION} image \
                            --severity CRITICAL,HIGH \
                            --format table \
                            --output /reports/trivy-critical-high.txt \
                            ${DOCKER_IMAGE}
                        
                        # Create a summary report
                        echo "=== VULNERABILITY SUMMARY ===" > trivy-reports/trivy-summary.txt
                        echo "Scan Date: $(date)" >> trivy-reports/trivy-summary.txt
                        echo "Image: ${DOCKER_IMAGE}" >> trivy-reports/trivy-summary.txt
                        echo "Git Commit: ${GIT_COMMIT}" >> trivy-reports/trivy-summary.txt
                        echo "Git Branch: ${GIT_BRANCH}" >> trivy-reports/trivy-summary.txt
                        echo "" >> trivy-reports/trivy-summary.txt
                        
                        # Count vulnerabilities by severity
                        if [ -f trivy-reports/trivy-report.json ]; then
                            echo "Parsing vulnerability counts..." >> trivy-reports/trivy-summary.txt
                            
                            # Count vulnerabilities by severity
                            CRITICAL_COUNT=$(grep -o '"Severity":"CRITICAL"' trivy-reports/trivy-report.json | wc -l || echo "0")
                            HIGH_COUNT=$(grep -o '"Severity":"HIGH"' trivy-reports/trivy-report.json | wc -l || echo "0")
                            MEDIUM_COUNT=$(grep -o '"Severity":"MEDIUM"' trivy-reports/trivy-report.json | wc -l || echo "0")
                            LOW_COUNT=$(grep -o '"Severity":"LOW"' trivy-reports/trivy-report.json | wc -l || echo "0")
                            
                            echo "CRITICAL: $CRITICAL_COUNT" >> trivy-reports/trivy-summary.txt
                            echo "HIGH: $HIGH_COUNT" >> trivy-reports/trivy-summary.txt
                            echo "MEDIUM: $MEDIUM_COUNT" >> trivy-reports/trivy-summary.txt
                            echo "LOW: $LOW_COUNT" >> trivy-reports/trivy-summary.txt
                            
                            # Store counts for threshold checking
                            echo $CRITICAL_COUNT > trivy-reports/critical-count.txt
                            echo $HIGH_COUNT > trivy-reports/high-count.txt
                            echo $MEDIUM_COUNT > trivy-reports/medium-count.txt
                        fi
                    '''
                }
            }
        }
        
        stage('Security Gate - Evaluate Thresholds') {
            steps {
                script {
                    echo 'Evaluating security thresholds...'
                    
                    def criticalCount = 0
                    def highCount = 0
                    def mediumCount = 0
                    
                    // Read vulnerability counts
                    if (fileExists('trivy-reports/critical-count.txt')) {
                        criticalCount = readFile('trivy-reports/critical-count.txt').trim() as Integer
                    }
                    if (fileExists('trivy-reports/high-count.txt')) {
                        highCount = readFile('trivy-reports/high-count.txt').trim() as Integer
                    }
                    if (fileExists('trivy-reports/medium-count.txt')) {
                        mediumCount = readFile('trivy-reports/medium-count.txt').trim() as Integer
                    }
                    
                    echo "Found vulnerabilities:"
                    echo "  CRITICAL: ${criticalCount}"
                    echo "  HIGH: ${highCount}"
                    echo "  MEDIUM: ${mediumCount}"
                    
                    echo "Security thresholds:"
                    echo "  MAX_CRITICAL: ${env.MAX_CRITICAL}"
                    echo "  MAX_HIGH: ${env.MAX_HIGH}"
                    echo "  MAX_MEDIUM: ${env.MAX_MEDIUM}"
                    
                    // Check thresholds
                    def securityGatePassed = true
                    def failureReasons = []
                    
                    if (criticalCount > (env.MAX_CRITICAL as Integer)) {
                        failureReasons.add("CRITICAL vulnerabilities (${criticalCount}) exceed threshold (${env.MAX_CRITICAL})")
                        securityGatePassed = false
                    }
                    
                    if (highCount > (env.MAX_HIGH as Integer)) {
                        failureReasons.add("HIGH vulnerabilities (${highCount}) exceed threshold (${env.MAX_HIGH})")
                        securityGatePassed = false
                    }
                    
                    if (mediumCount > (env.MAX_MEDIUM as Integer)) {
                        failureReasons.add("MEDIUM vulnerabilities (${mediumCount}) exceed threshold (${env.MAX_MEDIUM})")
                        securityGatePassed = false
                    }
                    
                    // Write results to file
                    writeFile file: 'trivy-reports/security-gate-result.txt', text: """
Security Gate Evaluation Result
==============================
Date: ${new Date()}
Image: ${env.DOCKER_IMAGE}
Git Commit: ${env.GIT_COMMIT}
Git Branch: ${env.GIT_BRANCH}
Jenkins Build: #${env.BUILD_NUMBER}

Vulnerability Counts:
- CRITICAL: ${criticalCount} (Threshold: ${env.MAX_CRITICAL})
- HIGH: ${highCount} (Threshold: ${env.MAX_HIGH})
- MEDIUM: ${mediumCount} (Threshold: ${env.MAX_MEDIUM})

Security Gate: ${securityGatePassed ? 'PASSED' : 'FAILED'}

${failureReasons.size() > 0 ? 'Failure Reasons:\n' + failureReasons.collect{ '- ' + it }.join('\n') : 'All vulnerability counts are within acceptable thresholds.'}
"""
                    
                    if (!securityGatePassed) {
                        echo "🚨 Security Gate FAILED!"
                        failureReasons.each { reason ->
                            echo "  ❌ ${reason}"
                        }
                        echo ""
                        echo "Build will continue for educational purposes, but in production this would fail the build."
                        echo "To fail the build, uncomment the error() line in the Jenkinsfile."
                        // error("Security gate failed: ${failureReasons.join(', ')}")
                    } else {
                        echo "✅ Security Gate PASSED - All vulnerability counts within thresholds"
                    }
                }
            }
        }
        
        stage('Generate HTML Report') {
            steps {
                script {
                    // Create a comprehensive HTML report
                    sh '''
                        cat > trivy-reports/trivy-report.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Trivy Vulnerability Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .critical { color: #dc3545; font-weight: bold; }
        .high { color: #fd7e14; font-weight: bold; }
        .medium { color: #ffc107; font-weight: bold; }
        .low { color: #28a745; }
        .passed { color: #28a745; font-weight: bold; }
        .failed { color: #dc3545; font-weight: bold; }
        pre { background-color: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .info-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .info-table th, .info-table td { padding: 8px 12px; text-align: left; border: 1px solid #dee2e6; }
        .info-table th { background-color: #e9ecef; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Trivy Vulnerability Scan Report</h1>
        <table class="info-table">
            <tr><th>Image</th><td>vulnerable-python-app:${BUILD_NUMBER}</td></tr>
            <tr><th>Scan Date</th><td>$(date)</td></tr>
            <tr><th>Jenkins Build</th><td>#${BUILD_NUMBER}</td></tr>
            <tr><th>Git Commit</th><td>${GIT_COMMIT}</td></tr>
            <tr><th>Git Branch</th><td>${GIT_BRANCH}</td></tr>
        </table>
    </div>
    
    <h2>📊 Vulnerability Summary</h2>
EOF
                        
                        if [ -f trivy-reports/trivy-summary.txt ]; then
                            echo "<pre>" >> trivy-reports/trivy-report.html
                            cat trivy-reports/trivy-summary.txt >> trivy-reports/trivy-report.html
                            echo "</pre>" >> trivy-reports/trivy-report.html
                        fi
                        
                        echo "<h2>🚨 Critical & High Vulnerabilities</h2>" >> trivy-reports/trivy-report.html
                        echo "<pre>" >> trivy-reports/trivy-report.html
                        if [ -f trivy-reports/trivy-critical-high.txt ]; then
                            cat trivy-reports/trivy-critical-high.txt >> trivy-reports/trivy-report.html
                        else
                            echo "No CRITICAL or HIGH vulnerabilities found." >> trivy-reports/trivy-report.html
                        fi
                        echo "</pre>" >> trivy-reports/trivy-report.html
                        
                        echo "<h2>📋 Security Gate Result</h2>" >> trivy-reports/trivy-report.html
                        echo "<pre>" >> trivy-reports/trivy-report.html
                        if [ -f trivy-reports/security-gate-result.txt ]; then
                            cat trivy-reports/security-gate-result.txt >> trivy-reports/trivy-report.html
                        fi
                        echo "</pre>" >> trivy-reports/trivy-report.html
                        
                        cat >> trivy-reports/trivy-report.html << 'EOF'
    <h2>📄 Full Scan Report</h2>
    <pre id="full-report">
EOF
                        
                        if [ -f trivy-reports/trivy-detailed-report.txt ]; then
                            cat trivy-reports/trivy-detailed-report.txt >> trivy-reports/trivy-report.html
                        fi
                        
                        cat >> trivy-reports/trivy-report.html << 'EOF'
    </pre>
</body>
</html>
EOF
                    '''
                }
            }
        }
        
        stage('Archive Reports & Publish') {
            steps {
                // Archive all reports
                archiveArtifacts artifacts: 'trivy-reports/*', fingerprint: true, allowEmptyArchive: false
                
                // Publish HTML report
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'trivy-reports',
                    reportFiles: 'trivy-report.html',
                    reportName: 'Trivy Security Report',
                    reportTitles: 'Vulnerability Scan Results'
                ])
                
                echo 'Reports published successfully! Check the "Trivy Security Report" link in the build.'
            }
        }
    }
    
    post {
        always {
            // Display summary in console
            script {
                if (fileExists('trivy-reports/trivy-summary.txt')) {
                    echo "\n=== FINAL VULNERABILITY SUMMARY ==="
                    sh 'cat trivy-reports/trivy-summary.txt'
                }
                
                if (fileExists('trivy-reports/security-gate-result.txt')) {
                    echo "\n=== SECURITY GATE RESULT ==="
                    sh 'cat trivy-reports/security-gate-result.txt'
                }
            }
            
            // Clean up Docker images to save space
            sh '''
                echo "Cleaning up Docker images..."
                docker rmi ${DOCKER_IMAGE} 2>/dev/null || echo "Image already removed"
                docker rmi ${APP_NAME}:latest 2>/dev/null || echo "Latest tag already removed"
            '''
        }
        success {
            echo '✅ Pipeline completed successfully - Security reports available'
        }
        failure {
            echo '❌ Pipeline failed - Check security reports for details'
        }
    }
}
