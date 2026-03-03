// =============================================================================
// Jenkins - Dependency Scanning with OWASP Dependency-Check
// Book Reference: Chapter 3, Section 3.3.3.3
// =============================================================================
//
// PURPOSE:
//   Configures OWASP Dependency-Check in Jenkins pipelines.
//   OWASP Dependency-Check is free, open source, and supports
//   Java, .NET, JavaScript, Python, Ruby, PHP, and more.
//
// SETUP:
//   1. Install the OWASP Dependency-Check plugin in Jenkins:
//      Manage Jenkins > Plugins > Available > "OWASP Dependency-Check"
//   2. Configure the plugin:
//      Manage Jenkins > Configure System > Dependency-Check
//      Set the installation directory
//   3. (Optional) Configure NVD API key for faster database updates:
//      https://nvd.nist.gov/developers/request-an-api-key
//      Add as Jenkins credential: nvd-api-key
//
// THRESHOLDS:
//   Adjust CRITICAL_THRESHOLD and HIGH_THRESHOLD to match your
//   security-thresholds.yml configuration from Example 3.6
// =============================================================================

pipeline {
    agent any

    parameters {
        booleanParam(
            name:         'FORCE_UPDATE_DB',
            defaultValue: false,
            description:  'Force update of the NVD vulnerability database'
        )
        string(
            name:         'CRITICAL_THRESHOLD',
            defaultValue: '0',
            description:  'Max critical vulnerabilities before failing (Table 3.4)'
        )
        string(
            name:         'HIGH_THRESHOLD',
            defaultValue: '5',
            description:  'Max high vulnerabilities before failing (Table 3.4)'
        )
    }

    environment {
        // OWASP Dependency-Check report directory
        DC_REPORT_DIR = 'dependency-check-report'

        // NVD API key for faster database updates (optional)
        // Add this credential in Jenkins: Manage Jenkins > Credentials
        NVD_API_KEY = credentials('nvd-api-key')

        // Notification targets
        SECURITY_EMAIL = 'security-team@yourcompany.com'
    }

    triggers {
        // Run daily to catch newly disclosed CVEs
        cron('H 2 * * *')
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timeout(time: 2, unit: 'HOURS')    // DC can be slow on first run
        timestamps()
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        // =====================================================================
        // OWASP Dependency-Check scan
        // First run downloads the NVD database (~500MB) - subsequent runs
        // use the cached database and only download updates
        // =====================================================================
        stage('OWASP Dependency-Check') {
            steps {
                script {
                    def additionalArgs = ''

                    // Add NVD API key if available (significantly speeds up DB updates)
                    if (env.NVD_API_KEY) {
                        additionalArgs += " --nvdApiKey ${env.NVD_API_KEY}"
                    }

                    // Force DB update if requested
                    if (params.FORCE_UPDATE_DB) {
                        additionalArgs += ' --updateonly'
                    }

                    dependencyCheck(
                        additionalArguments: """
                            --scan .
                            --format ALL
                            --out ${env.DC_REPORT_DIR}
                            --enableRetired
                            --enableExperimental
                            --failOnCVSS 7
                            ${additionalArgs}
                        """,
                        odcInstallation: 'dependency-check'
                    )
                }
            }
        }

        // =====================================================================
        // Publish OWASP Dependency-Check results
        // Makes results visible in Jenkins UI
        // =====================================================================
        stage('Publish Results') {
            steps {
                dependencyCheckPublisher(
                    pattern:              "${env.DC_REPORT_DIR}/dependency-check-report.xml",
                    failedTotalCritical:  params.CRITICAL_THRESHOLD.toInteger(),
                    failedTotalHigh:      params.HIGH_THRESHOLD.toInteger(),
                    unstableTotalMedium:  20,
                    unstableTotalLow:     999
                )
            }
            post {
                always {
                    archiveArtifacts artifacts: "${env.DC_REPORT_DIR}/**",
                                     allowEmptyArchive: true,
                                     fingerprint: true
                }
            }
        }

        // =====================================================================
        // Threshold enforcement
        // Parses the JSON report and enforces thresholds from Table 3.4
        // =====================================================================
        stage('Enforce Thresholds') {
            steps {
                script {
                    def reportFile = "${env.DC_REPORT_DIR}/dependency-check-report.json"

                    if (!fileExists(reportFile)) {
                        echo "No JSON report found - skipping threshold check"
                        return
                    }

                    def report = readJSON file: reportFile

                    def critical = 0
                    def high     = 0
                    def medium   = 0
                    def low      = 0

                    // Parse OWASP DC JSON format
                    report.dependencies?.each { dep ->
                        dep.vulnerabilities?.each { vuln ->
                            def cvss = vuln.cvssv3?.baseScore ?: vuln.cvssv2?.score ?: 0

                            if (cvss >= 9.0) {
                                critical++
                            } else if (cvss >= 7.0) {
                                high++
                            } else if (cvss >= 4.0) {
                                medium++
                            } else {
                                low++
                            }
                        }
                    }

                    env.DC_CRITICAL = critical.toString()
                    env.DC_HIGH     = high.toString()
                    env.DC_MEDIUM   = medium.toString()
                    env.DC_LOW      = low.toString()

                    echo """
                    ============================================
                    OWASP Dependency-Check Results
                    ============================================
                    Critical : ${critical} (threshold: ${params.CRITICAL_THRESHOLD})
                    High     : ${high}     (threshold: ${params.HIGH_THRESHOLD})
                    Medium   : ${medium}   (warn only)
                    Low      : ${low}      (ignored)
                    ============================================
                    """

                    // Print critical findings for developer context
                    if (critical > 0) {
                        echo "=== Critical Findings ==="
                        report.dependencies?.each { dep ->
                            dep.vulnerabilities?.each { vuln ->
                                def cvss = vuln.cvssv3?.baseScore ?: vuln.cvssv2?.score ?: 0
                                if (cvss >= 9.0) {
                                    echo """
                                    Package : ${dep.fileName}
                                    CVE     : ${vuln.name}
                                    CVSS    : ${cvss}
                                    Details : ${vuln.description?.take(200) ?: 'N/A'}
                                    """
                                }
                            }
                        }
                    }

                    // Enforce thresholds
                    def failures = []

                    if (critical > params.CRITICAL_THRESHOLD.toInteger()) {
                        failures << "Critical: ${critical} (threshold: ${params.CRITICAL_THRESHOLD})"
                    }
                    if (high > params.HIGH_THRESHOLD.toInteger()) {
                        failures << "High: ${high} (threshold: ${params.HIGH_THRESHOLD})"
                    }

                    if (medium > 20) {
                        currentBuild.result = 'UNSTABLE'
                        echo "WARNING: Medium threshold exceeded: ${medium} > 20"
                    }

                    if (failures) {
                        error("Dependency threshold FAILED:\n${failures.join('\n')}")
                    }

                    echo "Dependency threshold check PASSED"
                }
            }
        }
    }

    post {

        always {
            script {
                echo """
                ============================================
                Dependency Scan Summary
                ============================================
                Job      : ${env.JOB_NAME} #${env.BUILD_NUMBER}
                Status   : ${currentBuild.currentResult}
                Critical : ${env.DC_CRITICAL ?: 'N/A'}
                High     : ${env.DC_HIGH     ?: 'N/A'}
                Medium   : ${env.DC_MEDIUM   ?: 'N/A'}
                Report   : ${env.BUILD_URL}artifact/${env.DC_REPORT_DIR}/
                ============================================
                """
            }
        }

        failure {
            emailext(
                subject: "Dependency Scan Failed: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: """
                    <h2>Dependency Scan Failed</h2>
                    <table>
                        <tr><td><b>Job</b></td><td>${env.JOB_NAME}</td></tr>
                        <tr><td><b>Build</b></td><td>#${env.BUILD_NUMBER}</td></tr>
                        <tr><td><b>Critical</b></td><td style="color:red">${env.DC_CRITICAL ?: 'N/A'}</td></tr>
                        <tr><td><b>High</b></td><td style="color:orange">${env.DC_HIGH ?: 'N/A'}</td></tr>
                        <tr><td><b>Report</b></td><td><a href="${env.BUILD_URL}artifact/${env.DC_REPORT_DIR}/">View Report</a></td></tr>
                    </table>
                    <p>Fix the vulnerabilities listed in the report and re-run the pipeline.</p>
                """,
                to:       env.SECURITY_EMAIL,
                mimeType: 'text/html'
            )
        }

        fixed {
            emailext(
                subject: "Dependency Scan Recovered: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: "<p>Dependency scan is now passing after previous failures.</p>",
                to:       env.SECURITY_EMAIL,
                mimeType: 'text/html'
            )
        }
    }
}
