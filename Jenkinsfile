pipeline {
    agent any
    
    environment {
        TRIVY_VERSION = '0.45.0'
        SNYK_IMAGE = 'snyk/snyk:alpine'
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
        
        stage('Snyk Dependency Scan') {
            steps {
                script {
                    echo 'Running Snyk dependency vulnerability scan...'
                    withCredentials([string(credentialsId: 'snyk-api-token', variable: 'SNYK_TOKEN')]) {
                        sh '''
                            # Create reports directory
                            mkdir -p snyk-reports
                            
                            # Run Snyk test for dependencies (will likely find vulnerabilities)
                            echo "Running Snyk dependency scan..."
                            docker run --rm \
                                -e SNYK_TOKEN=${SNYK_TOKEN} \
                                -v ${WORKSPACE}:/workspace \
                                ${SNYK_IMAGE} snyk test /workspace \
                                --file=/workspace/requirements.txt \
                                --package-manager=pip \
                                --severity-threshold=low \
                                --json > snyk-reports/snyk-dependencies.json || echo "Snyk found vulnerabilities (expected)"
                            
                            # Generate readable report
                            docker run --rm \
                                -e SNYK_TOKEN=${SNYK_TOKEN} \
                                -v ${WORKSPACE}:/workspace \
                                ${SNYK_IMAGE} snyk test /workspace \
                                --file=/workspace/requirements.txt \
                                --package-manager=pip \
                                --severity-threshold=low > snyk-reports/snyk-dependencies.txt || echo "Snyk found vulnerabilities (expected)"
                            
                            # Run Snyk monitor to record snapshot (optional)
                            echo "Recording project snapshot in Snyk dashboard..."
                            docker run --rm \
                                -e SNYK_TOKEN=${SNYK_TOKEN} \
                                -v ${WORKSPACE}:/workspace \
                                ${SNYK_IMAGE} snyk monitor /workspace \
                                --file=/workspace/requirements.txt \
                                --package-manager=pip \
                                --project-name="${JOB_NAME}-dependencies-${BUILD_NUMBER}" || echo "Monitor completed"
                        '''
                    }
                }
            }
        }
        
        stage('Snyk Container Scan') {
            steps {
                script {
                    echo 'Running Snyk container vulnerability scan...'
                    withCredentials([string(credentialsId: 'snyk-api-token', variable: 'SNYK_TOKEN')]) {
                        sh '''
                            # Run Snyk container test
                            echo "Running Snyk container scan..."
                            docker run --rm \
                                -e SNYK_TOKEN=${SNYK_TOKEN} \
                                -v /var/run/docker.sock:/var/run/docker.sock \
                                -v ${WORKSPACE}:/workspace \
                                ${SNYK_IMAGE} snyk container test ${DOCKER_IMAGE} \
                                --severity-threshold=low \
                                --json > snyk-reports/snyk-container.json || echo "Snyk found container vulnerabilities (expected)"
                            
                            # Generate readable container report
                            docker run --rm \
                                -e SNYK_TOKEN=${SNYK_TOKEN} \
                                -v /var/run/docker.sock:/var/run/docker.sock \
                                -v ${WORKSPACE}:/workspace \
                                ${SNYK_IMAGE} snyk container test ${DOCKER_IMAGE} \
                                --severity-threshold=low > snyk-reports/snyk-container.txt || echo "Snyk found container vulnerabilities (expected)"
                            
                            # Monitor container in Snyk dashboard
                            echo "Recording container snapshot in Snyk dashboard..."
                            docker run --rm \
                                -e SNYK_TOKEN=${SNYK_TOKEN} \
                                -v /var/run/docker.sock:/var/run/docker.sock \
                                -v ${WORKSPACE}:/workspace \
                                ${SNYK_IMAGE} snyk container monitor ${DOCKER_IMAGE} \
                                --project-name="${JOB_NAME}-container-${BUILD_NUMBER}" || echo "Container monitor completed"
                        '''
                    }
                }
            }
        }
        
        stage('Trivy Security Scan') {
            steps {
                script {
                    echo 'Running comprehensive Trivy security scan...'
                    
                    sh '''
                        # Create reports directory if not exists
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
                        echo "=== TRIVY VULNERABILITY SUMMARY ===" > trivy-reports/trivy-summary.txt
                        echo "Scan Date: $(date)" >> trivy-reports/trivy-summary.txt
                        echo "Image: ${DOCKER_IMAGE}" >> trivy-reports/trivy-summary.txt
                        echo "Git Commit: ${GIT_COMMIT}" >> trivy-reports/trivy-summary.txt
                        echo "Git Branch: ${GIT_BRANCH}" >> trivy-reports/trivy-summary.txt
                        echo "" >> trivy-reports/trivy-summary.txt
                        
                        # Count vulnerabilities by severity
                        if [ -f trivy-reports/trivy-report.json ]; then
                            echo "Parsing Trivy vulnerability counts..." >> trivy-reports/trivy-summary.txt
                            
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
        
        stage('Parse Snyk Results') {
            steps {
                script {
                    echo 'Parsing Snyk scan results...'
                    sh '''
                        # Create Snyk summary report
                        echo "=== SNYK VULNERABILITY SUMMARY ===" > snyk-reports/snyk-summary.txt
                        echo "Scan Date: $(date)" >> snyk-reports/snyk-summary.txt
                        echo "Project: ${JOB_NAME}" >> snyk-reports/snyk-summary.txt
                        echo "Build: ${BUILD_NUMBER}" >> snyk-reports/snyk-summary.txt
                        echo "" >> snyk-reports/snyk-summary.txt
                        
                        # Parse dependency scan results
                        if [ -f snyk-reports/snyk-dependencies.json ]; then
                            echo "=== DEPENDENCY SCAN RESULTS ===" >> snyk-reports/snyk-summary.txt
                            
                            # Simple parsing of JSON results (basic approach)
                            DEP_CRITICAL=$(grep -o '"severity":"critical"' snyk-reports/snyk-dependencies.json | wc -l || echo "0")
                            DEP_HIGH=$(grep -o '"severity":"high"' snyk-reports/snyk-dependencies.json | wc -l || echo "0")
                            DEP_MEDIUM=$(grep -o '"severity":"medium"' snyk-reports/snyk-dependencies.json | wc -l || echo "0")
                            DEP_LOW=$(grep -o '"severity":"low"' snyk-reports/snyk-dependencies.json | wc -l || echo "0")
                            
                            echo "Dependencies - CRITICAL: $DEP_CRITICAL" >> snyk-reports/snyk-summary.txt
                            echo "Dependencies - HIGH: $DEP_HIGH" >> snyk-reports/snyk-summary.txt
                            echo "Dependencies - MEDIUM: $DEP_MEDIUM" >> snyk-reports/snyk-summary.txt
                            echo "Dependencies - LOW: $DEP_LOW" >> snyk-reports/snyk-summary.txt
                            echo "" >> snyk-reports/snyk-summary.txt
                        fi
                        
                        # Parse container scan results
                        if [ -f snyk-reports/snyk-container.json ]; then
                            echo "=== CONTAINER SCAN RESULTS ===" >> snyk-reports/snyk-summary.txt
                            
                            CONT_CRITICAL=$(grep -o '"severity":"critical"' snyk-reports/snyk-container.json | wc -l || echo "0")
                            CONT_HIGH=$(grep -o '"severity":"high"' snyk-reports/snyk-container.json | wc -l || echo "0")
                            CONT_MEDIUM=$(grep -o '"severity":"medium"' snyk-reports/snyk-container.json | wc -l || echo "0")
                            CONT_LOW=$(grep -o '"severity":"low"' snyk-reports/snyk-container.json | wc -l || echo "0")
                            
                            echo "Container - CRITICAL: $CONT_CRITICAL" >> snyk-reports/snyk-summary.txt
                            echo "Container - HIGH: $CONT_HIGH" >> snyk-reports/snyk-summary.txt
                            echo "Container - MEDIUM: $CONT_MEDIUM" >> snyk-reports/snyk-summary.txt
                            echo "Container - LOW: $CONT_LOW" >> snyk-reports/snyk-summary.txt
                        fi
                    '''
                }
            }
        }
        
        stage('Security Gate - Evaluate Thresholds') {
            steps {
                script {
                    echo 'Evaluating security thresholds based on Trivy results...'
                    
                    def criticalCount = 0
                    def highCount = 0
                    def mediumCount = 0
                    
                    // Read Trivy vulnerability counts for security gate
                    if (fileExists('trivy-reports/critical-count.txt')) {
                        criticalCount = readFile('trivy-reports/critical-count.txt').trim() as Integer
                    }
                    if (fileExists('trivy-reports/high-count.txt')) {
                        highCount = readFile('trivy-reports/high-count.txt').trim() as Integer
                    }
                    if (fileExists('trivy-reports/medium-count.txt')) {
                        mediumCount = readFile('trivy-reports/medium-count.txt').trim() as Integer
                    }
                    
                    echo "Trivy found vulnerabilities:"
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
                    writeFile file: 'security-gate-result.txt', text: """
Security Gate Evaluation Result
==============================
Date: ${new Date()}
Image: ${env.DOCKER_IMAGE}
Git Commit: ${env.GIT_COMMIT}
Git Branch: ${env.GIT_BRANCH}
Jenkins Build: #${env.BUILD_NUMBER}

Trivy Vulnerability Counts:
- CRITICAL: ${criticalCount} (Threshold: ${env.MAX_CRITICAL})
- HIGH: ${highCount} (Threshold: ${env.MAX_HIGH})
- MEDIUM: ${mediumCount} (Threshold: ${env.MAX_MEDIUM})

Security Gate: ${securityGatePassed ? 'PASSED' : 'FAILED'}

${failureReasons.size() > 0 ? 'Failure Reasons:\n' + failureReasons.collect{ '- ' + it }.join('\n') : 'All vulnerability counts are within acceptable thresholds.'}

Note: Security gate evaluation is based on Trivy results. 
Snyk results are provided for comparison and analysis purposes.
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
        
        stage('Generate Comparison Report') {
            steps {
                script {
                    // Create comprehensive HTML report comparing both tools
                    sh '''
                        mkdir -p comparison-reports
                        
                        cat > comparison-reports/sca-comparison-report.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>SCA Tools Comparison Report - Trivy vs Snyk</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .critical { color: #dc3545; font-weight: bold; }
        .high { color: #fd7e14; font-weight: bold; }
        .medium { color: #ffc107; font-weight: bold; }
        .low { color: #28a745; }
        .passed { color: #28a745; font-weight: bold; }
        .failed { color: #dc3545; font-weight: bold; }
        pre { background-color: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; font-size: 12px; }
        .info-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .info-table th, .info-table td { padding: 8px 12px; text-align: left; border: 1px solid #dee2e6; }
        .info-table th { background-color: #e9ecef; }
        .comparison-container { display: flex; gap: 20px; margin: 20px 0; }
        .tool-section { flex: 1; border: 1px solid #dee2e6; border-radius: 5px; padding: 15px; }
        .trivy-section { border-color: #007bff; }
        .snyk-section { border-color: #6f42c1; }
        h3.trivy { color: #007bff; }
        h3.snyk { color: #6f42c1; }
        .summary-box { background-color: #e9ecef; padding: 10px; border-radius: 5px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 SCA Tools Comparison Report</h1>
        <h2>Trivy vs Snyk Vulnerability Analysis</h2>
        <table class="info-table">
            <tr><th>Image</th><td>vulnerable-python-app:${BUILD_NUMBER}</td></tr>
            <tr><th>Scan Date</th><td>$(date)</td></tr>
            <tr><th>Jenkins Build</th><td>#${BUILD_NUMBER}</td></tr>
            <tr><th>Git Commit</th><td>${GIT_COMMIT}</td></tr>
            <tr><th>Git Branch</th><td>${GIT_BRANCH}</td></tr>
        </table>
    </div>
    
    <div class="comparison-container">
        <div class="tool-section trivy-section">
            <h3 class="trivy">🛡️ Trivy Results</h3>
            <div class="summary-box">
                <h4>Vulnerability Summary</h4>
EOF
                        
                        if [ -f trivy-reports/trivy-summary.txt ]; then
                            echo "<pre>" >> comparison-reports/sca-comparison-report.html
                            cat trivy-reports/trivy-summary.txt >> comparison-reports/sca-comparison-report.html
                            echo "</pre>" >> comparison-reports/sca-comparison-report.html
                        fi
                        
                        cat >> comparison-reports/sca-comparison-report.html << 'EOF'
            </div>
        </div>
        
        <div class="tool-section snyk-section">
            <h3 class="snyk">🔐 Snyk Results</h3>
            <div class="summary-box">
                <h4>Vulnerability Summary</h4>
EOF
                        
                        if [ -f snyk-reports/snyk-summary.txt ]; then
                            echo "<pre>" >> comparison-reports/sca-comparison-report.html
                            cat snyk-reports/snyk-summary.txt >> comparison-reports/sca-comparison-report.html
                            echo "</pre>" >> comparison-reports/sca-comparison-report.html
                        fi
                        
                        cat >> comparison-reports/sca-comparison-report.html << 'EOF'
            </div>
        </div>
    </div>
    
    <h2>📊 Security Gate Results</h2>
    <div class="summary-box">
EOF
                        
                        if [ -f security-gate-result.txt ]; then
                            echo "<pre>" >> comparison-reports/sca-comparison-report.html
                            cat security-gate-result.txt >> comparison-reports/sca-comparison-report.html
                            echo "</pre>" >> comparison-reports/sca-comparison-report.html
                        fi
                        
                        cat >> comparison-reports/sca-comparison-report.html << 'EOF'
    </div>
    
    <h2>🔍 Detailed Analysis</h2>
    
    <h3 class="trivy">Trivy - Container & OS Package Vulnerabilities</h3>
    <pre>
EOF
                        
                        if [ -f trivy-reports/trivy-critical-high.txt ]; then
                            head -50 trivy-reports/trivy-critical-high.txt >> comparison-reports/sca-comparison-report.html
                            echo "... (truncated for brevity)" >> comparison-reports/sca-comparison-report.html
                        fi
                        
                        cat >> comparison-reports/sca-comparison-report.html << 'EOF'
    </pre>
    
    <h3 class="snyk">Snyk - Dependency Vulnerabilities</h3>
    <pre>
EOF
                        
                        if [ -f snyk-reports/snyk-dependencies.txt ]; then
                            head -50 snyk-reports/snyk-dependencies.txt >> comparison-reports/sca-comparison-report.html
                            echo "... (truncated for brevity)" >> comparison-reports/sca-comparison-report.html
                        fi
                        
                        cat >> comparison-reports/sca-comparison-report.html << 'EOF'
    </pre>
    
    <h2>🔧 Tool Comparison Summary</h2>
    <div class="summary-box">
        <h4>Key Differences:</h4>
        <ul>
            <li><strong>Trivy</strong>: Container-focused, scans OS packages + application dependencies</li>
            <li><strong>Snyk</strong>: Developer-focused, provides detailed fix recommendations</li>
            <li><strong>Coverage</strong>: Different vulnerability databases may show different results</li>
            <li><strong>Remediation</strong>: Snyk typically provides more actionable fix guidance</li>
        </ul>
    </div>
    
    <h2>📋 Raw Reports</h2>
    <p>Download the complete raw reports from Jenkins build artifacts:</p>
    <ul>
        <li>Trivy JSON Report: trivy-reports/trivy-report.json</li>
        <li>Snyk Dependencies JSON: snyk-reports/snyk-dependencies.json</li>
        <li>Snyk Container JSON: snyk-reports/snyk-container.json</li>
    </ul>
</body>
</html>
EOF
                    '''
                }
            }
        }
        
        stage('Archive Reports & Publish') {
            steps {
                // Archive all reports from both tools
                archiveArtifacts artifacts: 'trivy-reports/*,snyk-reports/*,comparison-reports/*,security-gate-result.txt', fingerprint: true, allowEmptyArchive: false
                
                // Publish comparison report
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'comparison-reports',
                    reportFiles: 'sca-comparison-report.html',
                    reportName: 'SCA Comparison Report',
                    reportTitles: 'Trivy vs Snyk Analysis'
                ])
                
                // Publish individual Trivy report for backward compatibility
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'trivy-reports',
                    reportFiles: 'trivy-detailed-report.txt',
                    reportName: 'Trivy Security Report',
                    reportTitles: 'Trivy Vulnerability Scan Results'
                ])
                
                echo 'Reports published successfully!'
                echo 'Check the "SCA Comparison Report" link for side-by-side tool comparison'
            }
        }
    }
    
    post {
        always {
            // Display summary in console
            script {
                echo "\n" + "="*50
                echo "FINAL SCAN SUMMARY"
                echo "="*50
                
                if (fileExists('trivy-reports/trivy-summary.txt')) {
                    echo "\n=== TRIVY RESULTS ==="
                    sh 'cat trivy-reports/trivy-summary.txt'
                }
                
                if (fileExists('snyk-reports/snyk-summary.txt')) {
                    echo "\n=== SNYK RESULTS ==="
                    sh 'cat snyk-reports/snyk-summary.txt'
                }
                
                if (fileExists('security-gate-result.txt')) {
                    echo "\n=== SECURITY GATE RESULT ==="
                    sh 'cat security-gate-result.txt'
                }
                
                echo "\n" + "="*50
                echo "Check the 'SCA Comparison Report' in Jenkins for detailed analysis"
                echo "="*50
            }
            
            // Clean up Docker images to save space
            sh '''
                echo "Cleaning up Docker images..."
                docker rmi ${DOCKER_IMAGE} 2>/dev/null || echo "Image already removed"
                docker rmi ${APP_NAME}:latest 2>/dev/null || echo "Latest tag already removed"
            '''
        }
        success {
            echo '✅ Pipeline completed successfully - Comparison reports available'
        }
        failure {
            echo '❌ Pipeline failed - Check security reports for details'
        }
    }
}
