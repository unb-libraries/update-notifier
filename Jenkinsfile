// Build, check and deploy update-notifier on every push to main.
//
// The release Jenkins tested is the release that runs: the Build stage assembles it here
// (git archive plus a --no-dev vendor/) and Deploy copies it to the server, so the server
// needs no composer or network access. Each deploy is a new directory under releases/;
// switching the current symlink makes it live in one step.
//
// On the server, DEPLOY_DIR holds:
//   releases/<build number>/  the last KEEP_RELEASES releases
//   shared/                   files that outlive releases (update-notifier.yml), linked
//                             into each release by name, replacing anything there
//   current                   symlink to the live release; cron (thunderflare-etc-files,
//                             cron.d/update-notifier) runs current/bin/update-notifier
//
// Roll back by pointing current at an earlier release, on the server as mrrobot:
//   cd /var/opt/update-notifier && ln -sfn releases/<N> current.new && mv -T current.new current

pipeline {
    agent any

    options {
        disableConcurrentBuilds()
        timeout(time: 15, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '50'))
        ansiColor('xterm')
    }

    triggers {
        githubPush()
    }

    environment {
        DEPLOY_HOST = 'thunderflare.hil.unb.ca'
        DEPLOY_DIR = '/var/opt/update-notifier'
        KEEP_RELEASES = '5'
    }

    stages {
        stage('Install') {
            steps {
                // build/ holds this build's reports and release; a stale junit.xml would be
                // published as this build's results if an earlier stage failed.
                sh 'rm -rf build && mkdir build'
                sh 'composer install --no-interaction --no-progress'
            }
        }

        stage('Lint') {
            steps {
                sh 'composer lint'
            }
        }

        stage('Analyse') {
            steps {
                sh 'composer analyse -- --no-progress'
            }
        }

        stage('Test') {
            steps {
                sh 'composer test -- --log-junit build/junit.xml'
            }
        }

        stage('Build') {
            steps {
                sh '''
                    mkdir build/release
                    git archive HEAD | tar -x -C build/release
                    composer install -d build/release --no-dev --optimize-autoloader \
                        --no-interaction --no-progress
                '''
            }
        }

        stage('Deploy') {
            steps {
                sh '''
                    release="releases/$BUILD_NUMBER"
                    # Files unchanged since the live release are hard-linked to it, not copied.
                    rsync -rlp --checksum --link-dest="$DEPLOY_DIR/current/" \
                        build/release/ "$DEPLOY_HOST:$DEPLOY_DIR/$release/"

                    ssh "$DEPLOY_HOST" bash -s -- "$DEPLOY_DIR" "$release" "$KEEP_RELEASES" <<'EOF'
set -euo pipefail
cd "$1"
release=$2
for shared in shared/* shared/.[!.]*; do
    [ -e "$shared" ] || continue
    name=${shared#shared/}
    rm -rf "${release:?}/$name"
    ln -s "../../$shared" "$release/$name"
done
# Loading the autoloader runs composer's platform check: the PHP version and extensions.
php -r 'require $argv[1];' "$release/vendor/autoload.php"
ln -sfn "$release" current.new
mv -T current.new current
echo "current -> $(readlink current)"
live=$(basename "$(readlink current)")
# awk, not grep -v, since grep fails the script when it outputs nothing.
ls releases | sort -n | head -n "-$3" | awk -v live="$live" '$0 != live { print "releases/" $0 }' \
    | xargs -r rm -rf
EOF
                '''
            }
        }
    }

    post {
        always {
            junit allowEmptyResults: true, testResults: 'build/junit.xml'
        }
        success {
            slackSend color: 'good',
                message: "${env.JOB_NAME} #${env.BUILD_NUMBER} deployed (<${env.BUILD_URL}|Open>)"
        }
        unsuccessful {
            slackSend color: 'danger',
                message: "${env.JOB_NAME} #${env.BUILD_NUMBER} ${currentBuild.currentResult} (<${env.BUILD_URL}|Open>)"
        }
    }
}
